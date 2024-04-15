"""apport.PackageInfo class implementation for python-apt and dpkg.

This is used on Debian and derivatives such as Ubuntu.
"""

# Copyright (C) 2007 - 2011 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

# pylint: disable=too-many-lines
# TODO: Address following pylint complaints
# pylint: disable=invalid-name

# From Python 3.12 on, it doesn't try to evaluate type signatures at runtime
# anymore. This behaviour is helpful to us as apt_sl.Deb822SourceEntry isn't
# always a valid type, so use the __future__ mechanism to have this behaviour
# in older versions as well.
from __future__ import annotations

import contextlib
import datetime
import functools
import glob
import gzip
import hashlib
import http.client
import json
import logging
import os
import pathlib
import pickle
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator

import apt
import apt_pkg
import aptsources.sourceslist as apt_sl
from aptsources.sourceslist import SourceEntry

import apport.logging
from apport.packaging import PackageInfo

WITH_DEB822_SUPPORT = hasattr(apt_sl, "Deb822SourceEntry")


# pylint: disable-next=no-member
def _parse_deb822_sources(source: str) -> list[apt_sl.Deb822SourceEntry]:
    if not WITH_DEB822_SUPPORT:
        return []

    sections = []
    current = []
    with open(source, encoding="utf-8") as f:
        for line in f.read().split("\n"):
            line = line.rstrip()
            if line:
                if not line.lstrip().startswith("#"):
                    current.append(line)
            else:
                if not current:
                    continue
                # pylint: disable-next=no-member
                sections.append(apt_sl.Deb822SourceEntry("\n".join(current), source))
                current = []

        if current:
            # pylint: disable-next=no-member
            sections.append(apt_sl.Deb822SourceEntry("\n".join(current), source))
        return sections


def _order_sources(apt_sources: list[str]) -> Iterator[str]:
    """Order APT sources files heuristically to get the primary sources first."""
    sources = set(apt_sources)
    info = platform.freedesktop_os_release()
    expected_primary = f"{info['ID']}.sources"
    try:
        sources.remove(expected_primary)
        yield expected_primary
    except KeyError:
        pass
    yield from sorted(sources)


# pylint: disable-next=no-member
def _load_all_sources(apt_dir: str) -> list[apt_sl.Deb822SourceEntry | SourceEntry]:
    """Given an APT configuration directory (e.g. /etc/apt/), loads up all
    the source data in one easy-to-consume list.
    """
    sources_d = os.path.join(apt_dir, "sources.list.d")
    if os.path.exists(sources_d):
        to_inspect = [
            os.path.join(sources_d, f) for f in _order_sources(os.listdir(sources_d))
        ]
    else:
        to_inspect = []

    sources_old_file = os.path.join(apt_dir, "sources.list")
    if os.path.exists(sources_old_file):
        to_inspect[0:0] = [sources_old_file]

    sources = []
    for path in to_inspect:
        if path.endswith(".list"):
            with open(path, encoding="utf-8") as f:
                sources.extend([SourceEntry(line, path) for line in f])
        elif path.endswith(".sources") and WITH_DEB822_SUPPORT:
            sources.extend(_parse_deb822_sources(path))

    return sources


def _read_mirror_file(uri: str) -> list[str]:
    """Read an apt-transport-mirror configuration file.

    Note: The metadata will be stripped for simplicity reasons.
    """
    assert uri.startswith("mirror+file:")
    path = pathlib.Path(uri[12:])
    lines = [line.strip() for line in path.read_text("utf-8").split("\n")]
    mirrors = [
        line.split("\t", maxsplit=1)[0] for line in lines if line and line[0] != "#"
    ]
    return mirrors


class __AptDpkgPackageInfo(PackageInfo):
    # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """Concrete apport.packaging.PackageInfo class implementation for
    python-apt and dpkg, as found on Debian and derivatives such as Ubuntu."""

    def __init__(self):
        self._apt_cache = None
        self._current_release_codename = None
        self._sandbox_apt_cache = None
        self._sandbox_apt_cache_arch = None
        self._contents_dir = None
        self._mirror = None
        self._virtual_mapping_obj = None
        self._contents_mapping_obj = None
        self._launchpad_base = "https://api.launchpad.net/devel"
        self._contents_update = False

    def __del__(self):
        try:
            if self._contents_dir:
                shutil.rmtree(self._contents_dir)
        except AttributeError:
            pass

    def _virtual_mapping(self, configdir):
        if self._virtual_mapping_obj is not None:
            return self._virtual_mapping_obj

        mapping_file = os.path.join(configdir, "virtual_mapping.pickle")
        if os.path.exists(mapping_file):
            with open(mapping_file, "rb") as fp:
                self._virtual_mapping_obj = pickle.load(fp)
        else:
            self._virtual_mapping_obj = {}

        return self._virtual_mapping_obj

    def _save_virtual_mapping(self, configdir):
        mapping_file = os.path.join(configdir, "virtual_mapping.pickle")
        if self._virtual_mapping_obj is not None:
            with open(mapping_file, "wb") as fp:
                pickle.dump(self._virtual_mapping_obj, fp)

    def _contents_mapping(self, configdir, release, arch):
        if (
            self._contents_mapping_obj
            and self._contents_mapping_obj["release"] == release
            and self._contents_mapping_obj["arch"] == arch
        ):
            return self._contents_mapping_obj

        mapping_file = os.path.join(
            configdir, f"contents_mapping-{release}-{arch}.pickle"
        )
        if os.path.exists(mapping_file) and os.stat(mapping_file).st_size == 0:
            os.remove(mapping_file)
        if os.path.exists(mapping_file):
            with open(mapping_file, "rb") as fp:
                self._contents_mapping_obj = pickle.load(fp)
        else:
            self._contents_mapping_obj = {"release": release, "arch": arch}

        return self._contents_mapping_obj

    def _save_contents_mapping(self, configdir, release, arch):
        mapping_file = os.path.join(
            configdir, f"contents_mapping-{release}-{arch}.pickle"
        )
        if self._contents_mapping_obj is not None:
            try:
                with open(mapping_file, "wb") as fp:
                    pickle.dump(self._contents_mapping_obj, fp)
            # rather than crashing on systems with little memory just don't
            # write the crash file
            except MemoryError:
                pass

    def _clear_apt_cache(self) -> None:
        # The rootdir option to apt.Cache modifies the global state
        apt_pkg.config.clear("Dir")
        apt_pkg.init_config()
        apt_pkg.init_system()

        self._apt_cache = None
        self._sandbox_apt_cache = None

    def _cache(self):
        """Return apt.Cache() (initialized lazily)."""
        if not self._apt_cache:
            self._clear_apt_cache()
            # avoid spewage on stdout
            progress = apt.progress.base.OpProgress()
            self._apt_cache = apt.Cache(progress=progress)
        return self._apt_cache

    def _sandbox_cache(
        self,
        aptroot,
        apt_dir,
        fetchProgress,
        distro_name,
        release_codename,
        origins,
        arch,
    ):  # pylint: disable=too-many-arguments
        """Build apt sandbox and return apt.Cache(rootdir=) (initialized
        lazily).

        Clear the package selection on subsequent calls.
        """
        if not self._sandbox_apt_cache or arch != self._sandbox_apt_cache_arch:
            self._clear_apt_cache()
            self._build_apt_sandbox(
                aptroot, apt_dir, distro_name, release_codename, origins
            )
            rootdir = os.path.abspath(aptroot)
            self._sandbox_apt_cache = apt.Cache(rootdir=rootdir)
            self._sandbox_apt_cache_arch = arch
            try:
                # We don't need to update this multiple times.
                self._sandbox_apt_cache.update(fetchProgress)
            except apt.cache.FetchFailedException as error:
                raise SystemError(str(error)) from error
            self._sandbox_apt_cache.open()
        else:
            self._sandbox_apt_cache.clear()
        return self._sandbox_apt_cache

    def _apt_pkg(self, package):
        """Return apt.Cache()[package] (initialized lazily).

        Throw a ValueError if the package does not exist.
        """
        try:
            return self._cache()[package]
        except KeyError:
            raise ValueError(f"package {package} does not exist") from None

    def get_version(self, package):
        """Return the installed version of a package."""
        pkg = self._apt_pkg(package)
        inst = pkg.installed
        if not inst:
            raise ValueError(f"package {package} does not exist")
        return inst.version

    def get_available_version(self, package):
        """Return the latest available version of a package."""
        return self._apt_pkg(package).candidate.version

    def get_dependencies(self, package):
        """Return a list of packages a package depends on."""
        cur_ver = self._apt_pkg(package).installed
        if not cur_ver:
            # happens with virtual packages
            return []
        return [
            d[0].name
            for d in cur_ver.get_dependencies("Depends", "PreDepends", "Recommends")
        ]

    def get_source(self, package):
        """Return the source package name for a package."""
        if self._apt_pkg(package).installed:
            return self._apt_pkg(package).installed.source_name
        if self._apt_pkg(package).candidate:
            return self._apt_pkg(package).candidate.source_name
        raise ValueError(f"package {package} does not exist")

    def get_package_origin(self, package):
        """Return package origin.

        Return the repository name from which a package was installed, or None
        if it cannot be determined.

        Throw ValueError if package is not installed.
        """
        pkg = self._apt_pkg(package).installed
        if not pkg:
            raise ValueError("package is not installed")
        for origin in pkg.origins:
            if origin.origin:
                return origin.origin
        return None

    def is_distro_package(self, package):
        """Check if a package is a genuine distro package.

        Return True for a native distro package, False if it comes from a
        third-party source.
        """
        pkg = self._apt_pkg(package)
        # some PPA packages have installed version None, see LP#252734
        if pkg.installed and pkg.installed.version is None:
            return False

        if not pkg.candidate:
            return False

        origins = {o.origin for o in pkg.candidate.origins}

        distro_name = self.get_os_version()[0]
        if distro_name in origins:
            return True

        # on Ubuntu system-image we might not have any /var/lib/apt/lists
        if origins == {""} and os.path.exists("/etc/system-image/channel.ini"):
            return True

        return False

    def is_native_origin_package(self, package):
        """Check if a package originated from a native location.

        Return True for a package which came from an origin which is listed in
        native-origins.d, False if it comes from a third-party source.
        """
        pkg = self._apt_pkg(package)
        # some PPA packages have installed version None, see LP#252734
        if pkg.installed and pkg.installed.version is None:
            return False

        native_origins = []
        for f in glob.glob("/etc/apport/native-origins.d/*"):
            try:
                with open(f, encoding="utf-8") as fd:
                    for line in fd:
                        line = line.strip()
                        if line:
                            native_origins.append(line)
            except OSError:
                pass

        if pkg.candidate and pkg.candidate.origins:  # might be None
            for o in pkg.candidate.origins:
                if o.origin in native_origins:
                    return True
        return False

    @staticmethod
    def get_lp_binary_package(release, package, version, arch):
        """Get Launchpad URL and SHA1 sum for the given binary package version."""
        # allow unauthenticated downloads
        apt.apt_pkg.config.set("APT::Get::AllowUnauthenticated", "True")
        # pylint: disable=import-outside-toplevel
        from launchpadlib.launchpad import Launchpad

        launchpad = Launchpad.login_anonymously(
            "apport-retrace", "production", version="devel"
        )
        ubuntu = launchpad.distributions["ubuntu"]
        series = ubuntu.getSeries(name_or_version=release.split()[-1])
        das = series.getDistroArchSeries(archtag=arch)
        primary = ubuntu.getArchive(name="primary")
        bpph = primary.getPublishedBinaries(
            binary_name=package,
            version=version,
            distro_arch_series=das,
            ordered=False,
            exact_match=True,
        )
        if not bpph:
            return (None, None)
        bf_urls = ""
        for bp in bpph:
            if bp.status == "Deleted":
                continue
            if not bp.architecture_specific:
                # include_meta is required to get the sha1
                bf_urls = bp.binaryFileUrls(include_meta=True)
                break
            if bp.distro_arch_series_link.endswith(arch):
                bf_urls = bp.binaryFileUrls(include_meta=True)
                break
        if not bf_urls:
            return (None, None)
        for bf in bf_urls:
            # return the first binary file url since there being more than one
            # is theoretical
            return (bf["url"], bf["sha1"])

    @staticmethod
    def json_request(url, entries=False):
        """Open, read and parse the JSON of a URL.

        Set entries to True when the json data returned by Launchpad
        has a dictionary with an entries key which contains the data
        desired.
        """
        try:
            with urllib.request.urlopen(url) as response:
                content = response.read()
        except (urllib.error.URLError, urllib.error.HTTPError):
            apport.logging.warning("cannot connect to: %s", urllib.parse.unquote(url))
            return None
        except OSError:
            apport.logging.warning(
                "failure reading data at: %s", urllib.parse.unquote(url)
            )
            return None
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        if entries:
            return json.loads(content)["entries"]
        return json.loads(content)

    @staticmethod
    def get_lp_source_package(package, version):
        """Get files from Launchpad for the given source package version."""
        # pylint: disable=import-outside-toplevel
        from launchpadlib.launchpad import Launchpad

        launchpad = Launchpad.login_anonymously(
            "apport-retrace", "production", version="devel"
        )
        ubuntu = launchpad.distributions["ubuntu"]
        primary = ubuntu.getArchive(name="primary")
        pss = primary.getPublishedSources(
            source_name=package, version=version, exact_match=True
        )
        if not pss:
            return None
        sfus = ""
        for ps in pss:
            if ps.status == "Deleted":
                continue
            sfus = ps.sourceFileUrls()
            # use the first entry as they are sorted chronologically
            break
        if not sfus:
            return None
        source_files = []
        for sfu in sfus:
            source_files.append(sfu)
        return source_files

    def get_architecture(self, package):
        """Return the architecture of a package.

        This might differ on multiarch architectures (e. g. an i386 Firefox
        package on a x86_64 system)
        """
        if self._apt_pkg(package).installed:
            return self._apt_pkg(package).installed.architecture or "unknown"
        if self._apt_pkg(package).candidate:
            return self._apt_pkg(package).candidate.architecture or "unknown"
        raise ValueError(f"package {package} does not exist")

    def get_files(self, package):
        """Return list of files shipped by a package."""
        output = self._call_dpkg(["-L", package])
        if output is None:
            return None
        return [f for f in output.splitlines() if not f.startswith("diverted")]

    def get_modified_files(self, package):
        """Return list of all modified files of a package."""
        # get the maximum mtime of package files that we consider unmodified
        listfile = f"/var/lib/dpkg/info/{package}:{self.get_system_architecture()}.list"
        if not os.path.exists(listfile):
            listfile = f"/var/lib/dpkg/info/{package}.list"
        try:
            s = os.stat(listfile)
            if not stat.S_ISREG(s.st_mode):
                raise OSError
            max_time = max(s.st_mtime, s.st_ctime)
        except OSError:
            return []

        # create a list of files with a newer timestamp for md5sum'ing
        sums = b""
        sumfile = (
            f"/var/lib/dpkg/info/{package}:{self.get_system_architecture()}.md5sums"
        )
        if not os.path.exists(sumfile):
            sumfile = f"/var/lib/dpkg/info/{package}.md5sums"
            if not os.path.exists(sumfile):
                # some packages do not ship md5sums
                return []

        with open(sumfile, "rb") as fd:
            for line in fd:
                try:
                    # ignore lines with NUL bytes (happens, LP#96050)
                    if b"\0" in line:
                        apport.logging.warning(
                            "%s contains NUL character, ignoring line", sumfile
                        )
                        continue
                    words = line.split()
                    if not words:
                        apport.logging.warning(
                            "%s contains empty line, ignoring line", sumfile
                        )
                        continue
                    s = os.stat(f"/{words[-1].decode('UTF-8')}".encode("UTF-8"))
                    if max(s.st_mtime, s.st_ctime) <= max_time:
                        continue
                except OSError:
                    pass

                sums += line

        if sums:
            return self._check_files_md5(sums)
        return []

    def get_modified_conffiles(self, package):
        """Return modified configuration files of a package.

        Return a file name -> file contents map of all configuration files of
        package. Please note that apport.hookutils.attach_conffiles() is the
        official user-facing API for this, which will ask for confirmation and
        allows filtering.
        """
        dpkg = subprocess.run(
            ["dpkg-query", "-W", "--showformat=${Conffiles}", "--", package],
            check=False,
            stdout=subprocess.PIPE,
        )

        if dpkg.returncode != 0:
            return {}

        modified = {}
        for line in dpkg.stdout.decode().splitlines():
            if not line:
                continue
            # just take the first two fields, to not stumble over obsolete
            # conffiles
            path, default_md5sum = line.strip().split()[:2]

            if os.path.exists(path):
                try:
                    with open(path, "rb") as fd:
                        contents = fd.read()
                    m = hashlib.md5()
                    m.update(contents)
                    calculated_md5sum = m.hexdigest()

                    if calculated_md5sum != default_md5sum:
                        modified[path] = contents
                except OSError as error:
                    modified[path] = f"[inaccessible: {str(error)}]"
            else:
                modified[path] = "[deleted]"

        return modified

    @staticmethod
    def __fgrep_files(pattern, file_list):
        """Call fgrep for a pattern on given file list and return the first
        matching file, or None if no file matches."""
        match = None
        slice_size = 100
        i = 0

        while not match and i < len(file_list):
            fgrep = subprocess.run(
                ["fgrep", "-lxm", "1", "--", pattern] + file_list[i : (i + slice_size)],
                check=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if fgrep.returncode == 0:
                match = fgrep.stdout.decode("UTF-8")
            i += slice_size

        return match

    def get_file_package(
        self, file, uninstalled=False, map_cachedir=None, release=None, arch=None
    ):
        """Return the package a file belongs to.

        Return None if the file is not shipped by any package.

        If uninstalled is True, this will also find files of uninstalled
        packages; this is very expensive, though, and needs network access and
        lots of CPU and I/O resources. In this case, map_cachedir can be set to
        an existing directory which will be used to permanently store the
        downloaded maps. If it is not set, a temporary directory will be used.
        Also, release and arch can be set to a foreign release/architecture
        instead of the one from the current system.
        """
        if uninstalled:
            return self._search_contents(file, map_cachedir, release, arch)

        # check if the file is a diversion
        dpkg = subprocess.run(
            ["dpkg-divert", "--list", file],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out = dpkg.stdout.decode("UTF-8")
        if dpkg.returncode == 0 and out:
            pkg = out.split()[-1]
            if pkg != "hardening-wrapper":
                return pkg

        fname = os.path.splitext(os.path.basename(file))[0].lower()

        all_lists = []
        likely_lists = []
        for f in glob.glob("/var/lib/dpkg/info/*.list"):
            p = os.path.splitext(os.path.basename(f))[0].lower().split(":")[0]
            if p in fname or fname in p:
                likely_lists.append(f)
            else:
                all_lists.append(f)

        # first check the likely packages
        match = self.__fgrep_files(file, likely_lists)
        if not match:
            match = self.__fgrep_files(file, all_lists)
        # with usrmerge some binaries appear in usr but their .list file
        # doesn't reflect that so strip the /usr from the path
        if not match and file.startswith("/usr"):
            file = file[4:]
            match = self.__fgrep_files(f"{file}", likely_lists)
            if not match:
                match = self.__fgrep_files(f"{file}", all_lists)

        if match:
            return os.path.splitext(os.path.basename(match))[0].split(":")[0]

        return None

    @staticmethod
    @functools.cache
    def get_system_architecture():
        """Return the architecture of the system, in the notation used by the
        particular distribution."""
        dpkg = subprocess.run(
            ["dpkg", "--print-architecture"], check=True, stdout=subprocess.PIPE
        )
        arch = dpkg.stdout.decode().strip()
        assert arch
        return arch

    def get_library_paths(self):
        """Return a list of default library search paths.

        The entries should be separated with a colon ':', like for
        $LD_LIBRARY_PATH. This needs to take any multiarch directories into
        account.
        """
        dpkg = subprocess.run(
            ["dpkg-architecture", "-qDEB_HOST_MULTIARCH"],
            check=True,
            stdout=subprocess.PIPE,
        )
        multiarch_triple = dpkg.stdout.decode().strip()

        return f"/lib/{multiarch_triple}:/lib"

    def set_mirror(self, url):
        """Explicitly set a distribution mirror URL for operations that need to
        fetch distribution files/packages from the network.

        By default, the mirror will be read from the system configuration
        files.
        """
        self._mirror = url

        # purge our contents dir cache
        try:
            if self._contents_dir:
                shutil.rmtree(self._contents_dir)
                self._contents_dir = None
        except AttributeError:
            pass

    def get_source_tree(self, srcpackage, output_dir, version=None, sandbox=None):
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-locals
        """Download source package and unpack it into output_dir.

        This also has to care about applying patches etc., so that output_dir
        will eventually contain the actually compiled source. output_dir needs
        to exist and should be empty.

        If version is given, this particular version will be retrieved.
        Otherwise this will fetch the latest available version.

        If sandbox is given, it calls apt-get source in that sandbox, otherwise
        it uses the system apt configuration.

        If apt_update is True, it will call apt-get update before apt-get
        source. This is mostly necessary for freshly created sandboxes.

        Return the directory that contains the actual source root directory
        (which might be a subdirectory of output_dir). Return None if the
        source is not available.
        """
        # configure apt for sandbox
        env = os.environ.copy()
        if sandbox:
            # hard to change, pylint: disable=consider-using-with
            f = tempfile.NamedTemporaryFile("w+")
            f.write(
                f'Dir "{sandbox}";\n'
                f'Dir::State::Status "/var/lib/dpkg/status";\n'
                f'Debug::NoLocking "true";\n'
            )
            f.flush()
            env["APT_CONFIG"] = f.name

        if sandbox and not glob.glob(f"{sandbox}/var/lib/apt/lists/*Sources"):
            subprocess.call(["apt-get", "-qq", "update"], env=env)

        # fetch source tree
        argv = ["apt-get", "-qq", "--assume-yes", "source", srcpackage]
        if version:
            argv[-1] += f"={version}"
        try:
            if subprocess.call(argv, cwd=output_dir, env=env) != 0:
                if not version:
                    return None
                sf_urls = self.get_lp_source_package(srcpackage, version)
                if sf_urls:
                    proxy = ""
                    if apt.apt_pkg.config.find("Acquire::http::Proxy") != "":
                        proxy = apt.apt_pkg.config.find("Acquire::http::Proxy")
                        apt.apt_pkg.config.set("Acquire::http::Proxy", "")
                    fetchProgress = apt.progress.base.AcquireProgress()
                    fetcher = apt.apt_pkg.Acquire(fetchProgress)
                    af_queue = []
                    for sf in sf_urls:
                        af_queue.append(
                            apt.apt_pkg.AcquireFile(fetcher, sf, destdir=output_dir)
                        )
                    result = fetcher.run()
                    if result != fetcher.RESULT_CONTINUE:
                        return None
                    if proxy:
                        apt.apt_pkg.config.set("Acquire::http::Proxy", proxy)
                    for dsc in glob.glob(os.path.join(output_dir, "*.dsc")):
                        subprocess.call(
                            ["dpkg-source", "-sn", "-x", dsc],
                            stdout=subprocess.PIPE,
                            cwd=output_dir,
                        )
                else:
                    return None
        except OSError:
            return None

        # find top level directory
        root = None
        for d in glob.glob(os.path.join(output_dir, f"{srcpackage}-*")):
            if os.path.isdir(d):
                root = d
        assert root, "could not determine source tree root directory"

        # apply patches on a best-effort basis
        try:
            subprocess.call(
                "(debian/rules patch || debian/rules apply-patches "
                "|| debian/rules apply-dpatches || "
                "debian/rules unpack || debian/rules patch-stamp || "
                "debian/rules setup) >/dev/null 2>&1",
                shell=True,
                cwd=root,
            )
        except OSError:
            pass

        return root

    def get_kernel_package(self):
        """Return the actual Linux kernel package name.

        This is used when the user reports a bug against the "linux" package.
        """
        # TODO: Ubuntu specific
        return f"linux-image-{os.uname()[2]}"

    def install_packages(
        self,
        rootdir,
        configdir,
        release,
        packages,
        verbose=False,
        cache_dir=None,
        permanent_rootdir=False,
        architecture=None,
        origins=None,
        install_dbg=True,
        install_deps=False,
    ):  # pylint: disable=too-many-arguments
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-locals
        # pylint: disable=too-many-nested-blocks,too-many-statements
        """Install packages into a sandbox (for apport-retrace).

        In order to work without any special permissions and without touching
        the running system, this should only download and unpack packages into
        the given root directory, not install them into the system.

        configdir points to a directory with by-release configuration files for
        the packaging system; this is completely dependent on the backend
        implementation, the only assumption is that this looks into
        configdir/release/, so that you can use retracing for multiple
        DistroReleases. As a special case, if configdir is None, it uses the
        current system configuration, and "release" is ignored.

        release is the value of the report's 'DistroRelease' field.

        packages is a list of ('packagename', 'version') tuples. If the version
        is None, it should install the most current available version.

        If cache_dir is given, then the downloaded packages will be stored
        there, to speed up subsequent retraces.

        If permanent_rootdir is True, then the sandbox created from the
        downloaded packages will be reused, to speed up subsequent retraces.

        If architecture is given, the sandbox will be created with packages of
        the given architecture (as specified in a report's "Architecture"
        field). If not given it defaults to the host system's architecture.

        If origins is given, the sandbox will be created with apt data sources
        for foreign origins.

        If install_deps is True, then the dependencies of packages will also
        be installed.

        Return a string with outdated packages, or an empty string if all
        packages were installed.

        If something is wrong with the environment (invalid configuration,
        package servers down, etc.), this should raise a SystemError with a
        meaningful error message.
        """
        if not architecture:
            architecture = self.get_system_architecture()
        if not configdir:
            apt_dir = "/etc/apt"
            self._current_release_codename = self.get_distro_codename()
        else:
            # support architecture specific config, fall back to global config
            apt_dir = os.path.join(configdir, release)
            if architecture != self.get_system_architecture():
                arch_apt_dir = os.path.join(configdir, release, architecture)
                arch_old_sources = os.path.join(arch_apt_dir, "sources.list")
                arch_sources_dir = os.path.join(arch_apt_dir, "sources.list.d")
                if os.path.exists(arch_old_sources) or (
                    os.path.exists(arch_sources_dir) and os.listdir(arch_sources_dir)
                ):
                    apt_dir = arch_apt_dir

            # set mirror for get_file_package()
            try:
                self.set_mirror(self._get_primary_mirror_from_apt_sources(apt_dir))
            except SystemError as error:
                apport.logging.warning("cannot determine mirror: %s", str(error))

            # set current release code name for _distro_release_to_codename
            with open(
                os.path.join(configdir, release, "codename"), encoding="utf-8"
            ) as f:
                self._current_release_codename = f.read().strip()

        # create apt sandbox
        if cache_dir:
            tmp_aptroot = False
            if architecture != self.get_system_architecture():
                aptroot_arch = architecture
            else:
                aptroot_arch = ""
            if configdir:
                aptroot = os.path.join(cache_dir, release, aptroot_arch, "apt")
            else:
                aptroot = os.path.join(cache_dir, "system", aptroot_arch, "apt")
            if not os.path.isdir(aptroot):
                os.makedirs(aptroot)
        else:
            tmp_aptroot = True
            aptroot = tempfile.mkdtemp()

        apt.apt_pkg.config.set("APT::Architecture", architecture)
        apt.apt_pkg.config.set("Acquire::Languages", "none")
        # directly connect to Launchpad when downloading deb files
        apt.apt_pkg.config.set("Acquire::http::Proxy::api.launchpad.net", "DIRECT")
        apt.apt_pkg.config.set("Acquire::http::Proxy::launchpad.net", "DIRECT")

        if verbose:
            fetchProgress = apt.progress.text.AcquireProgress()
        else:
            fetchProgress = apt.progress.base.AcquireProgress()
        if not tmp_aptroot:
            apt_cache = self._sandbox_cache(
                aptroot,
                apt_dir,
                fetchProgress,
                self.get_distro_name(),
                self._current_release_codename,
                origins,
                architecture,
            )
        else:
            self._build_apt_sandbox(
                aptroot,
                apt_dir,
                self.get_distro_name(),
                self._current_release_codename,
                origins,
            )
            apt_cache = apt.Cache(rootdir=os.path.abspath(aptroot))
            try:
                apt_cache.update(fetchProgress)
            except apt.cache.FetchFailedException as error:
                raise SystemError(str(error)) from error
            apt_cache.open()

        archivedir = apt.apt_pkg.config.find_dir("Dir::Cache::archives")

        obsolete = ""

        src_records = apt.apt_pkg.SourceRecords()

        # read original package list
        pkg_list = os.path.join(rootdir, "packages.txt")
        pkg_versions = {}
        if os.path.exists(pkg_list):
            with open(pkg_list, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    (p, v) = line.split()
                    pkg_versions[p] = v

        # mark packages for installation
        real_pkgs = set()
        lp_cache = {}
        fetcher = apt.apt_pkg.Acquire(fetchProgress)
        # need to keep AcquireFile references
        acquire_queue = []
        # add any dependencies to the packages list
        if install_deps:
            deps = []
            for pkg, ver in packages:
                try:
                    cache_pkg = apt_cache[pkg]
                except KeyError:
                    m = f"package {pkg.replace('%', '%%')} does not exist, ignoring"
                    obsolete += f"{m}\n"
                    apport.logging.warning("%s", m)
                    continue
                for dep in cache_pkg.candidate.dependencies:
                    # the dependency may be satisfied by a different package
                    if dep[0].name not in apt_cache:
                        dep[0] = apt_cache.get_providing_packages(dep[0].name)[0]
                    # the version in dep is the one from pkg's dependencies,
                    # so use the version from the cache
                    dep_pkg_vers = apt_cache[dep[0].name].candidate.version
                    # if the dependency is in the list of packages we don't
                    # need to look up its dependencies again
                    if dep[0].name in [pkg[0] for pkg in packages]:
                        continue
                    # if the package is already extracted in the sandbox
                    # because the report needs that package we don't want to
                    # install a newer version which may cause a CRC mismatch
                    # with the installed dbg symbols
                    if dep[0].name in pkg_versions:
                        inst_version = pkg_versions[dep[0].name]
                        if self.compare_versions(inst_version, dep_pkg_vers) > -1:
                            deps.append((dep[0].name, inst_version))
                        else:
                            deps.append((dep[0].name, dep_pkg_vers))
                    else:
                        deps.append((dep[0].name, dep_pkg_vers))
                    if dep[0].name not in [pkg[0] for pkg in packages]:
                        packages.append((dep[0].name, None))
            packages.extend(deps)

        for pkg, ver in packages:
            try:
                cache_pkg = apt_cache[pkg]
            except KeyError:
                m = f"package {pkg.replace('%', '%%')} does not exist, ignoring"
                obsolete += f"{m}\n"
                apport.logging.warning("%s", m)
                continue

            # try to select matching version
            try:
                if ver:
                    cache_pkg.candidate = cache_pkg.versions[ver]
            except KeyError:
                (lp_url, sha1sum) = self.get_lp_binary_package(
                    release, pkg, ver, architecture
                )
                if lp_url:
                    acquire_queue.append(
                        apt.apt_pkg.AcquireFile(
                            fetcher, lp_url, hash=f"sha1:{sha1sum}", destdir=archivedir
                        )
                    )
                    lp_cache[pkg] = ver
                else:
                    obsolete += (
                        f"{pkg} version {ver} required,"
                        f" but {cache_pkg.candidate.version} is available\n"
                    )
                    ver = cache_pkg.candidate.version

            candidate = cache_pkg.candidate
            real_pkgs.add(pkg)

            if permanent_rootdir:
                virtual_mapping = self._virtual_mapping(aptroot)
                # Remember all the virtual packages that this package provides,
                # so that if we encounter that virtual package as a
                # Conflicts/Replaces later, we know to remove this package from
                # the cache.
                for p in candidate.provides:
                    virtual_mapping.setdefault(p, set()).add(pkg)
                conflicts = []
                if "Conflicts" in candidate.record:
                    conflicts += apt.apt_pkg.parse_depends(
                        candidate.record["Conflicts"]
                    )
                if "Replaces" in candidate.record:
                    conflicts += apt.apt_pkg.parse_depends(candidate.record["Replaces"])
                for conflict in conflicts:
                    # if the package conflicts with itself its wonky e.g.
                    # gdb in artful
                    if conflict[0][0] == candidate.package.name:
                        continue
                    # apt_pkg.parse_depends needs to handle the or operator,
                    # but as policy states it is invalid to use that in
                    # Replaces/Depends, we can safely choose the first value
                    # here.
                    conflict = conflict[0]
                    if apt_cache.is_virtual_package(conflict[0]):
                        try:
                            providers = virtual_mapping[conflict[0]]
                        except KeyError:
                            # We may not have seen the virtual package that
                            # this conflicts with, so we can assume it's not
                            # unpacked into the sandbox.
                            continue
                        for p in providers:
                            # if the candidate package being installed
                            # conflicts with but also provides a virtual
                            # package don't act on the candidate e.g.
                            # libpam-modules and libpam-mkhomedir in artful
                            if p == candidate.package.name:
                                continue
                            debs = os.path.join(archivedir, f"{p}_*.deb")
                            for path in glob.glob(debs):
                                ver = self._deb_version(path)
                                if apt.apt_pkg.check_dep(ver, conflict[2], conflict[1]):
                                    os.unlink(path)
                            try:
                                del pkg_versions[p]
                            except KeyError:
                                pass
                        del providers
                    else:
                        debs = os.path.join(archivedir, f"{conflict[0]}_*.deb")
                        for path in glob.glob(debs):
                            ver = self._deb_version(path)
                            if apt.apt_pkg.check_dep(ver, conflict[2], conflict[1]):
                                os.unlink(path)
                                try:
                                    del pkg_versions[conflict[0]]
                                except KeyError:
                                    pass

            if candidate.architecture != "all" and install_dbg:
                try:
                    dbg_pkg = f"{pkg}-dbg"
                    dbg = apt_cache[dbg_pkg]
                    pkg_found = False
                    # try to get the same version as pkg
                    if ver:
                        try:
                            dbg.candidate = dbg.versions[ver]
                            pkg_found = True
                        except KeyError:
                            (lp_url, sha1sum) = self.get_lp_binary_package(
                                release, dbg_pkg, ver, architecture
                            )
                            if lp_url:
                                acquire_queue.append(
                                    apt.apt_pkg.AcquireFile(
                                        fetcher,
                                        lp_url,
                                        hash=f"sha1:{sha1sum}",
                                        destdir=archivedir,
                                    )
                                )
                                lp_cache[dbg_pkg] = ver
                                pkg_found = True
                            # if it can't be found in Launchpad failover to a
                            # code path that'll use -dbgsym packages
                            else:
                                raise
                    if not pkg_found:
                        try:
                            dbg.candidate = dbg.versions[candidate.version]
                        except KeyError:
                            obsolete += (
                                f"outdated -dbg package for {pkg}:"
                                f" package version {ver}"
                                f" -dbg version {dbg.candidate.version}\n"
                            )
                    real_pkgs.add(dbg_pkg)
                except KeyError:
                    # install all -dbg from the source package; lookup() just
                    # works from the current list pointer, we always need to
                    # start from the beginning
                    src_records.restart()
                    if src_records.lookup(candidate.source_name):
                        # ignore transitional packages
                        # False positive, see
                        # https://github.com/PyCQA/pylint/issues/7122
                        # pylint: disable=not-an-iterable
                        dbgs = [
                            p
                            for p in src_records.binaries
                            if p.endswith("-dbg")
                            and p in apt_cache
                            and "transitional" not in apt_cache[p].candidate.description
                        ]
                        # if a specific version of a package was requested
                        # only install dbg pkgs whose version matches
                        if ver:
                            for dbg in dbgs:
                                if apt_cache[dbg].candidate.version != ver:
                                    dbgs.remove(dbg)
                    else:
                        dbgs = []
                    if dbgs:
                        for p in dbgs:
                            # if the package has already been added to
                            # real_pkgs don't search for it again
                            if p in real_pkgs:
                                continue
                            pkg_found = False
                            # prefer the version requested
                            if ver:
                                try:
                                    apt_cache[p].candidate = apt_cache[p].versions[ver]
                                    pkg_found = True
                                except KeyError:
                                    (lp_url, sha1sum) = self.get_lp_binary_package(
                                        release, p, ver, architecture
                                    )
                                    if lp_url:
                                        acquire_queue.append(
                                            apt.apt_pkg.AcquireFile(
                                                fetcher,
                                                lp_url,
                                                hash=f"sha1:{sha1sum}",
                                                destdir=archivedir,
                                            )
                                        )
                                        lp_cache[p] = ver
                                        pkg_found = True
                            if not pkg_found:
                                try:
                                    apt_cache[p].candidate = apt_cache[p].versions[
                                        candidate.version
                                    ]
                                except KeyError:
                                    # we don't really expect that, but it's
                                    # possible that other binaries have a
                                    # different version
                                    pass
                            real_pkgs.add(p)
                    else:
                        pkg_found = False
                        dbgsym_pkg = f"{pkg}-dbgsym"
                        try:
                            dbgsym = apt_cache[dbgsym_pkg]
                            real_pkgs.add(dbgsym_pkg)
                            # prefer the version requested
                            if ver:
                                try:
                                    dbgsym.candidate = dbgsym.versions[ver]
                                    pkg_found = True
                                except KeyError:
                                    (lp_url, sha1sum) = self.get_lp_binary_package(
                                        release, dbgsym_pkg, ver, architecture
                                    )
                                    if lp_url:
                                        acquire_queue.append(
                                            apt.apt_pkg.AcquireFile(
                                                fetcher,
                                                lp_url,
                                                hash=f"sha1:{sha1sum}",
                                                destdir=archivedir,
                                            )
                                        )
                                        lp_cache[dbgsym_pkg] = ver
                                        pkg_found = True
                            if not pkg_found:
                                try:
                                    dbgsym.candidate = dbgsym.versions[
                                        candidate.version
                                    ]
                                except KeyError:
                                    obsolete += (
                                        f"outdated debug symbol package"
                                        f" for {pkg}: package version"
                                        f" {candidate.version}"
                                        f" dbgsym version"
                                        f" {dbgsym.candidate.version}\n"
                                    )

                        except KeyError:
                            if ver:
                                (lp_url, sha1sum) = self.get_lp_binary_package(
                                    release, dbgsym_pkg, ver, architecture
                                )
                                if lp_url:
                                    acquire_queue.append(
                                        apt.apt_pkg.AcquireFile(
                                            fetcher,
                                            lp_url,
                                            hash=f"sha1:{sha1sum}",
                                            destdir=archivedir,
                                        )
                                    )
                                    lp_cache[dbgsym_pkg] = ver
                                    pkg_found = True
                            if not pkg_found:
                                obsolete += f"no debug symbol package found for {pkg}\n"

        # unpack packages, weed out the ones that are already installed (for
        # permanent sandboxes)
        logger = logging.getLogger(__name__)
        requested_pkgs = dict(packages)
        for p in real_pkgs.copy():
            if p in requested_pkgs:
                if requested_pkgs[p] is None:
                    # We already have the latest version of this package
                    if pkg_versions.get(p) == apt_cache[p].candidate.version:
                        logger.debug(
                            "Removing %s which is already the right version", p
                        )
                        real_pkgs.remove(p)
                    else:
                        logger.debug(
                            "Installing %s version %s",
                            p,
                            apt_cache[p].candidate.version,
                        )
                        apt_cache[p].mark_install(False, False)
                elif pkg_versions.get(p) != requested_pkgs[p]:
                    logger.debug(
                        "Installing %s version %s", p, apt_cache[p].candidate.version
                    )
                    apt_cache[p].mark_install(False, False)
                elif pkg_versions.get(p) != apt_cache[p].candidate.version:
                    logger.debug(
                        "Installing %s version %s", p, apt_cache[p].candidate.version
                    )
                    apt_cache[p].mark_install(False, False)
                else:
                    logger.debug("Removing %s which is already the right version", p)
                    real_pkgs.remove(p)
            elif pkg_versions.get(p) != apt_cache[p].candidate.version:
                logger.debug("Installing %s", p)
                apt_cache[p].mark_install(False, False)
            else:
                logger.debug("Removing %s which is already the right version", p)
                real_pkgs.remove(p)

        last_written = time.time()
        # fetch packages
        try:
            apt_cache.fetch_archives(fetcher=fetcher)
        except apt.cache.FetchFailedException as error:
            apport.logging.error(
                "Package download error, try again later: %s", str(error)
            )
            sys.exit(1)  # transient error

        if verbose:
            print("Extracting downloaded debs...")
        # False positive, see https://github.com/PyCQA/pylint/issues/7122
        for i in fetcher.items:  # pylint: disable=not-an-iterable
            if not i.destfile.endswith("deb"):
                continue
            out = subprocess.check_output(["dpkg-deb", "--show", i.destfile]).decode()
            (p, v) = out.strip().split()
            if (
                not permanent_rootdir
                or p not in pkg_versions
                or os.path.getctime(i.destfile) > last_written
            ):
                # don't extract the same version of the package if it is
                # already extracted
                if pkg_versions.get(p) == v:
                    pass
                # don't extract the package if it is a different version than
                # the one we want to extract from Launchpad
                elif p in lp_cache and lp_cache[p] != v:
                    pass
                else:
                    subprocess.check_call(["dpkg", "-x", i.destfile, rootdir])
                    pkg_versions[p] = v
            pkg_name = os.path.basename(i.destfile).split("_", 1)[0]
            # because a package may exist multiple times in the fetcher it may
            # have already been removed
            if pkg_name in real_pkgs:
                real_pkgs.remove(pkg_name)

        # update package list
        pkgs = list(pkg_versions.keys())
        pkgs.sort()
        with open(pkg_list, "w", encoding="utf-8") as f:
            for p in pkgs:
                f.write(p)
                f.write(" ")
                f.write(pkg_versions[p])
                f.write("\n")

        if tmp_aptroot:
            shutil.rmtree(aptroot)

        # check bookkeeping that apt fetcher really got everything
        assert (
            not real_pkgs
        ), f"apt fetcher did not fetch these packages: {' '.join(real_pkgs)}"

        if permanent_rootdir:
            self._save_virtual_mapping(aptroot)

        return obsolete

    def package_name_glob(self, nameglob):
        """Return known package names which match given glob."""
        return glob.fnmatch.filter(self._cache().keys(), nameglob)

    #
    # Internal helper methods
    #

    @staticmethod
    def _call_dpkg(args):
        """Call dpkg with given arguments and return output, or return None on
        error."""
        dpkg = subprocess.run(
            ["dpkg"] + args, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if dpkg.returncode == 0:
            return dpkg.stdout.decode("UTF-8")
        raise ValueError("package does not exist")

    @staticmethod
    def _check_files_md5(sumfile):
        """Call md5sum.

        This is separate from get_modified_files so that it is automatically
        testable.
        """
        if os.path.exists(sumfile):
            args = [sumfile]
            stdin = None
        else:
            assert isinstance(sumfile, bytes), "md5sum list value must be a byte array"
            args = []
            stdin = sumfile
        md5sum = subprocess.run(
            ["/usr/bin/md5sum", "-c"] + args,
            check=False,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env={},
        )

        # if md5sum succeeded, don't bother parsing the output
        if md5sum.returncode == 0:
            return []
        out = md5sum.stdout.decode("UTF-8", errors="replace")

        mismatches = []
        for line in out.splitlines():
            if line.endswith("FAILED"):
                mismatches.append(line.rsplit(":", 1)[0])

        return mismatches

    @staticmethod
    def _get_primary_mirror_from_apt_sources(apt_dir: str) -> str:
        """Heuristically determine primary mirror from an apt sources.list."""
        uri = None
        sources = _load_all_sources(apt_dir)
        for source in sources:
            if source.disabled or source.invalid:
                continue
            # TODO: remove the typeched branch once python-apt commit
            # bdcb2550cb6f623f4556bf6581a040642f29dd28 is available
            # in a proper release
            if isinstance(source, SourceEntry):
                if source.type == "deb":
                    uri = source.uri or ""
            elif "deb" in source.types:
                uri = source.uris[0]

            if uri is not None:
                if uri.startswith("mirror+file:"):
                    mirrors = _read_mirror_file(uri)
                    assert mirrors
                    return mirrors[0]
                return uri

        raise SystemError(
            "cannot determine default mirror:"
            f" couldn't find configured source contains the `deb` type in {apt_dir}"
        )

    def _get_mirror(self):
        """Return the distribution mirror URL.

        If it has not been set yet, it will be read from the system
        configuration.
        """
        if not self._mirror:
            self._mirror = self._get_primary_mirror_from_apt_sources("/etc/apt")
        return self._mirror

    def _ppa_archive_url(self, user: str, distro: str, ppa_name: str) -> str:
        return f"{self._launchpad_base}/~{user}/+archive/{distro}/{ppa_name}"

    def _distro_release_to_codename(self, release):
        """Map a DistroRelease: field value to a release code name."""
        # if we called install_packages() with a configdir, we can read the
        # codename from there
        if self._current_release_codename is not None:
            return self._current_release_codename

        raise NotImplementedError(
            f"Cannot map DistroRelease '{release}' to a code name"
            " without install_packages()"
        )

    def _search_contents(self, file, map_cachedir, release, arch):
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-locals,too-many-statements
        """Search file in Contents.gz."""
        if not map_cachedir:
            if not self._contents_dir:
                self._contents_dir = tempfile.mkdtemp()
            map_cachedir = self._contents_dir

        if arch is None:
            arch = self.get_system_architecture()
        if release is None:
            release = self.get_distro_codename()
        else:
            release = self._distro_release_to_codename(release)
        # this is ordered by likelihood of installation with the most common
        # last
        # XXX - maybe we shouldn't check -security and -updates if it is the
        # devel release as they will be old and empty
        for pocket in ("-proposed", "", "-security", "-updates"):
            contents_filename = os.path.join(
                map_cachedir, f"{release}{pocket}-Contents-{arch}.gz"
            )
            # check if map exists and is younger than a day; if not, we need
            # to refresh it
            update = False
            try:
                st = os.stat(contents_filename)
                age = int(time.time() - st.st_mtime)
            except OSError:
                age = None

            if age is None or age >= 86400:
                url = (
                    f"{self._get_mirror()}/dists"
                    f"/{release}{pocket}/Contents-{arch}.gz"
                )
                if age:
                    # HTTPConnection requires server name e.g.
                    # archive.ubuntu.com
                    server = urllib.parse.urlparse(url)[1]
                    conn = http.client.HTTPConnection(server)
                    conn.request("HEAD", urllib.parse.urlparse(url)[2])
                    res = conn.getresponse()
                    modified_str = res.getheader("last-modified", None)
                    if modified_str:
                        modified = datetime.datetime.strptime(
                            modified_str, "%a, %d %b %Y %H:%M:%S %Z"
                        )
                        update = modified > datetime.datetime.fromtimestamp(st.st_mtime)
                    else:
                        update = True
                    # don't update the file if it is empty
                    if res.getheader("content-length", None) == "40":
                        update = False
                else:
                    update = True
                if update:
                    self._contents_update = True
                    try:
                        # hard to change, pylint: disable=consider-using-with
                        src = urllib.request.urlopen(url)
                    except OSError:
                        # we ignore non-existing pockets, but we do crash
                        # if the release pocket doesn't exist
                        if pocket == "":
                            raise
                        continue

                    with open(contents_filename, "wb") as f:
                        while True:
                            data = src.read(1000000)
                            if not data:
                                break
                            f.write(data)
                    src.close()
                    assert os.path.exists(contents_filename)

            contents_mapping = self._contents_mapping(map_cachedir, release, arch)
            # if the mapping is empty build it
            if not contents_mapping or len(contents_mapping) == 2:
                self._contents_update = True
            # if any of the Contents files were updated we need to update the
            # map because the ordering in which is created is important
            if self._contents_update:
                with gzip.open(f"{contents_filename}", "rb") as contents:
                    line_num = 0
                    for line in contents:
                        line_num += 1
                        # the first 32 lines are descriptive only for these
                        # releases
                        if (
                            pocket == ""
                            and release in {"trusty", "xenial"}
                            and line_num < 33
                        ):
                            continue
                        path = line.split()[0]
                        if path.split(b"/")[0] == b"usr":
                            if path.split(b"/")[1] not in (
                                b"lib",
                                b"libexec",
                                b"libx32",
                                b"bin",
                                b"sbin",
                                b"share",
                                b"games",
                                b"Brother",
                            ):
                                continue
                            if path.split(b"/")[1] == b"share" and path.split(b"/")[
                                2
                            ] in {
                                b"doc",
                                b"icons",
                                b"man",
                                b"texlive",
                                b"gocode",
                                b"locale",
                                b"help",
                            }:
                                continue
                            package = line.split()[-1].split(b",")[0].split(b"/")[-1]
                        elif path.split(b"/")[0] in {b"lib", b"bin", b"sbin", b"etc"}:
                            package = line.split()[-1].split(b",")[0].split(b"/")[-1]
                        else:
                            continue
                        if path in contents_mapping:
                            if package == contents_mapping[path]:
                                continue
                            # if the package was updated use the update
                            # b/c everyone should have packages from
                            # -updates and -security installed
                        contents_mapping[path] = package
        # the file only needs to be saved after an update
        if self._contents_update:
            self._save_contents_mapping(map_cachedir, release, arch)
            # the update of the mapping only needs to be done once
            self._contents_update = False
        if isinstance(file, bytes):
            file = file.decode()
        if file[0] == "/":
            file = file[1:]
        files = [file.encode()]
        if file.startswith("usr/"):
            files.append(file[4:].encode())
        for filename in files:
            try:
                pkg = contents_mapping[filename].decode()
                return pkg
            except KeyError:
                pass
        return None

    def _analyze_ppa_origin_string(
        self, origin: str, distro: str
    ) -> tuple[str, str] | None:
        if not origin.startswith("LP-PPA-"):
            return None

        components = origin.split("-")[2:]
        # If the PPA is unnamed, it will not appear in origin information
        # but is named ppa in Launchpad.
        try_ppa = True
        if len(components) == 1:
            components.append("ppa")
            try_ppa = False

        index = 1
        while index < len(components):
            # For an origin we can't tell where the user name ends and the
            # PPA name starts, so split on each "-" until we find a PPA
            # that exists.
            user = str.join("-", components[:index])
            ppa_name = str.join("-", components[index:])
            try:
                with contextlib.closing(
                    urllib.request.urlopen(
                        self._ppa_archive_url(
                            user=user, distro=distro, ppa_name=ppa_name
                        )
                    )
                ) as response:
                    response.read()
                    return user, ppa_name
            except (urllib.error.URLError, urllib.error.HTTPError):
                index += 1
                if index == len(components):
                    if try_ppa:
                        components.append("ppa")
                        try_ppa = False
                        index = 2
        return None

    # pylint: disable-next=no-member
    def create_ppa_source_from_origin(
        self, origin: str, distro: str, release_codename: str
    ) -> list[apt_sl.Deb822SourceEntry | SourceEntry] | None:
        """For an origin from a Launchpad PPA create sources.list content.

        distro is the distribution for which content is being created e.g.
        ubuntu.

        release_codename is the codename of the release for which content is
        being created e.g. trusty.

        Returns None if the origin is not a Launchpad PPA, a list of source
        entry objects otherwise."""
        ppa_data = self._analyze_ppa_origin_string(origin, distro)
        if not ppa_data:
            return None
        user, ppa_name = ppa_data
        debug_url = (
            f"http://ppa.launchpad.net/{user}/{ppa_name}/{distro}"
            f"/dists/{release_codename}/main/debug"
        )

        if WITH_DEB822_SUPPORT:
            main_entry = apt_sl.Deb822SourceEntry(None, "")
            main_entry.uris = [f"http://ppa.launchpad.net/{user}/{ppa_name}/{distro}"]
            main_entry.types = ["deb", "deb-src"]
            main_entry.comps = ["main"]
            main_entry.suites = [release_codename]

            try:
                with contextlib.closing(urllib.request.urlopen(debug_url)) as response:
                    response.read()
                debug_entry = apt_sl.Deb822SourceEntry(None, "")
                debug_entry.uris = [
                    f"http://ppa.launchpad.net/{user}/{ppa_name}/{distro}"
                ]
                debug_entry.types = ["deb"]
                debug_entry.comps = ["main/debug"]
                debug_entry.suites = [release_codename]
                return [main_entry, debug_entry]
            except (urllib.error.URLError, urllib.error.HTTPError):
                return [main_entry]
        else:
            ppa_line = (
                f"deb http://ppa.launchpad.net/{user}/{ppa_name}/{distro}"
                f" {release_codename} main"
            )
            try:
                with contextlib.closing(urllib.request.urlopen(debug_url)) as response:
                    response.read()
                add_debug = " main/debug"
            except (urllib.error.URLError, urllib.error.HTTPError):
                add_debug = ""
            return [
                SourceEntry(ppa_line + add_debug),
                SourceEntry(f"deb-src {ppa_line[4:]}"),
            ]

    @staticmethod
    def _find_source_file_from_origin(origin: str, src_list_d: str) -> str | None:
        """Find a possible source file matching the Origin field of a
        given package (i.e. a PPA)"""
        if os.path.isdir(src_list_d):
            # check to see if there is a sources.list file for the
            # origin, if there isn't try using a sources.list file
            # w/o LP-PPA-
            candidates = [os.path.join(src_list_d, f"{origin}.list")]
            if WITH_DEB822_SUPPORT:
                candidates[0:0] = [os.path.join(src_list_d, f"{origin}.source")]
            if "LP-PPA" in origin:
                stripped = origin.strip("LP-PPA-")
                if WITH_DEB822_SUPPORT:
                    candidates.append(os.path.join(f"{stripped}.source"))
                candidates.append(os.path.join(f"{stripped}.list"))

            for path in candidates:
                if os.path.exists(path):
                    return path
        return None

    def _build_apt_sandbox(
        self, apt_root, apt_dir, distro_name, release_codename, origins
    ):
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-locals,too-many-statements

        # pre-create directories, to avoid apt.Cache() printing "creating..."
        # messages on stdout
        if not os.path.exists(os.path.join(apt_root, "var", "lib", "apt")):
            os.makedirs(os.path.join(apt_root, "var", "lib", "apt", "lists", "partial"))
            os.makedirs(
                os.path.join(apt_root, "var", "cache", "apt", "archives", "partial")
            )
            os.makedirs(os.path.join(apt_root, "var", "lib", "dpkg"))
            os.makedirs(os.path.join(apt_root, "etc", "apt", "apt.conf.d"))
            os.makedirs(os.path.join(apt_root, "etc", "apt", "preferences.d"))

        # install apt sources
        src_list_d = os.path.join(apt_dir, "sources.list.d")
        dst_list_d = os.path.join(apt_root, "etc", "apt", "sources.list.d")
        if os.path.exists(dst_list_d):
            shutil.rmtree(dst_list_d)
        if os.path.isdir(src_list_d):
            shutil.copytree(src_list_d, dst_list_d)
        else:
            os.makedirs(dst_list_d)
        old_sources = os.path.join(apt_dir, "sources.list")
        if os.path.exists(old_sources):
            with open(old_sources, encoding="utf-8") as src:
                with open(
                    os.path.join(apt_root, "etc", "apt", "sources.list"),
                    "w",
                    encoding="utf-8",
                ) as dest:
                    dest.write(src.read())

        # install apt keyrings; prefer the ones from the config dir, fall back
        # to system
        trusted_gpg = os.path.join(apt_dir, "trusted.gpg")
        if os.path.exists(trusted_gpg):
            shutil.copy(trusted_gpg, os.path.join(apt_root, "etc", "apt"))
        elif os.path.exists("/etc/apt/trusted.gpg"):
            shutil.copy("/etc/apt/trusted.gpg", os.path.join(apt_root, "etc", "apt"))

        trusted_d = os.path.join(apt_root, "etc", "apt", "trusted.gpg.d")
        if os.path.exists(trusted_d):
            shutil.rmtree(trusted_d)

        if os.path.exists(f"{trusted_gpg}.d"):
            shutil.copytree(f"{trusted_gpg}.d", trusted_d)
        elif os.path.exists("/etc/apt/trusted.gpg.d"):
            shutil.copytree("/etc/apt/trusted.gpg.d", trusted_d)
        else:
            os.makedirs(trusted_d)

        if origins:
            # map an origin to a Launchpad username and PPA name
            origin_data = {}
            for origin in origins:
                # apport's report format uses unknown for packages w/o
                # an origin
                if origin == "unknown":
                    continue
                origin_path = self._find_source_file_from_origin(origin, src_list_d)
                extension = ".sources"
                if origin_path:
                    if origin_path.endswith(".list"):
                        extension = ".list"
                        with open(origin_path, encoding="utf-8") as src:
                            source_list_content = [SourceEntry(line) for line in src]
                    else:
                        source_list_content = _parse_deb822_sources(origin_path)
                else:
                    source_list_content = self.create_ppa_source_from_origin(
                        origin, distro_name, release_codename
                    )
                    if not WITH_DEB822_SUPPORT:
                        extension = ".list"
                if source_list_content:
                    with open(
                        os.path.join(
                            apt_root, "etc", "apt", "sources.list.d", origin + extension
                        ),
                        "a",
                        encoding="utf-8",
                    ) as dest:
                        dest.write(
                            "\n".join([f"{entry}\n" for entry in source_list_content])
                        )
                    for entry in source_list_content:
                        if not entry.uri or "ppa.launchpad.net" not in entry.uri:
                            continue
                        user = entry.uri.split("/")[3]
                        ppa = entry.uri.split("/")[4]
                        origin_data[origin] = (user, ppa)
                else:
                    apport.logging.warning(
                        "Could not find or create source config for %s", origin
                    )

            # install apt keyrings for PPAs
            for origin, (ppa_user, ppa_name) in origin_data.items():
                ppa_archive_url = self._ppa_archive_url(
                    user=urllib.parse.quote(ppa_user),
                    distro=distro_name,
                    ppa_name=urllib.parse.quote(ppa_name),
                )
                ppa_info = self.json_request(ppa_archive_url)
                if not ppa_info:
                    continue
                try:
                    signing_key_fingerprint = ppa_info["signing_key_fingerprint"]
                except IndexError:
                    apport.logging.warning(
                        "Error: can't find signing_key_fingerprint at %s",
                        ppa_archive_url,
                    )
                    continue
                argv = [
                    "apt-key",
                    "--keyring",
                    os.path.join(trusted_d, f"{origin}.gpg"),
                    "adv",
                    "--quiet",
                    "--keyserver",
                    "keyserver.ubuntu.com",
                    "--recv-key",
                    signing_key_fingerprint,
                ]

                if subprocess.call(argv) != 0:
                    apport.logging.warning(
                        "Unable to import key for %s", ppa_archive_url
                    )

    @staticmethod
    def _deb_version(pkg):
        """Return the version of a .deb file."""
        dpkg = subprocess.run(
            ["dpkg-deb", "-f", pkg, "Version"], check=True, stdout=subprocess.PIPE
        )
        out = dpkg.stdout.decode("UTF-8").strip()
        assert out
        return out

    def compare_versions(self, ver1, ver2):
        """Compare two package versions.

        Return -1 for ver < ver2, 0 for ver1 == ver2, and 1 for ver1 > ver2.
        """
        return apt.apt_pkg.version_compare(ver1, ver2)

    _distro_codename = None

    def get_distro_codename(self):
        """Get "lsb_release -sc", cache the result."""
        if self._distro_codename is None:
            try:
                info = platform.freedesktop_os_release()
                self._distro_codename = info["VERSION_CODENAME"]
            except (KeyError, OSError):
                # Fall back to query lsb_release
                lsb_release = subprocess.run(
                    ["lsb_release", "-sc"],
                    check=True,
                    stdout=subprocess.PIPE,
                    text=True,
                )
                self._distro_codename = lsb_release.stdout.strip()

        return self._distro_codename

    _distro_name = None

    def get_distro_name(self):
        """Get osname from /etc/os-release, or if that doesn't exist,
        'lsb_release -sir' output and cache the result."""
        if self._distro_name is None:
            self._distro_name = self.get_os_version()[0].lower()
            if " " in self._distro_name:
                # concatenate distro name e.g. ubuntu-rtm
                self._distro_name = self._distro_name.replace(" ", "-")

        return self._distro_name


impl = __AptDpkgPackageInfo()
