"""System tests for the apport.packaging_impl.apt_dpkg module."""

# pylint: disable=missing-function-docstring,too-many-lines
# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import glob
import gzip
import os
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import typing
from collections.abc import Iterator

import pytest
from apt import apt_pkg

from apport.packaging_impl.apt_dpkg import _parse_deb822_sources, impl
from tests.helper import has_internet, skip_if_command_is_missing
from tests.paths import get_test_data_directory

if shutil.which("dpkg") is None:
    pytest.skip("dpkg not installed", allow_module_level=True)

AptStyle: typing.TypeAlias = typing.Literal["deb822", "one-line"]

pytestmark = pytest.mark.parametrize("apt_style", ["one-line", "deb822"])


@pytest.fixture(name="workdir")
def fixture_workdir() -> Iterator[str]:
    workdir = tempfile.mkdtemp()
    yield workdir
    shutil.rmtree(workdir)


@pytest.fixture(name="cachedir")
def fixture_cachedir(workdir: str) -> str:
    ret = os.path.join(workdir, "cache")
    os.makedirs(ret)
    return ret


@pytest.fixture(name="rootdir")
def fixture_rootdir(workdir: str) -> str:
    ret = os.path.join(workdir, "root")
    os.makedirs(ret)
    return ret


@pytest.fixture(name="configdir")
def fixture_configdir(workdir: str) -> str:
    ret = os.path.join(workdir, "config")
    os.makedirs(ret)
    return ret


@pytest.fixture(autouse=True)
def environment(workdir: str) -> Iterator[None]:
    orig_environ = os.environ.copy()
    os.environ["HOME"] = workdir
    yield
    os.environ.clear()
    os.environ.update(orig_environ)


@pytest.fixture(autouse=True)
def reset_impl() -> Iterator[None]:
    # pylint: disable=protected-access
    orig_conf = impl.configuration
    impl._apt_cache = None
    impl._sandbox_apt_cache = None
    yield
    impl.configuration = orig_conf


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_install_packages_versioned(
    configdir: str, cachedir: str, rootdir: str, apt_style: AptStyle
) -> None:
    # TODO: Split into smaller functions/methods
    # pylint: disable=too-many-locals,too-many-statements
    """install_packages() with versions and with cache"""
    release = _setup_foonux_config(configdir, apt_style, updates=True)
    wanted = {
        "coreutils": "8.32-4.1ubuntu1",
        "libc6": "2.35-0ubuntu3",
        "libcurl4": "7.81.0-1",  # should not come from -updates
        "tzdata": None,  # should come from -updates, > 2022a
    }
    obsolete = impl.install_packages(
        rootdir, configdir, release, list(wanted.items()), False, cachedir
    )

    def sandbox_ver(pkg: str) -> str:
        with gzip.open(
            os.path.join(rootdir, "usr/share/doc", pkg, "changelog.Debian.gz")
        ) as f:
            return f.readline().decode().split()[1][1:-1]

    assert obsolete == ""

    # packages get installed
    assert os.path.exists(os.path.join(rootdir, "usr/bin/stat"))
    assert_elf_arch(
        os.path.join(rootdir, "usr/bin/stat"), impl.get_system_architecture()
    )
    assert os.path.exists(os.path.join(rootdir, "usr/lib/debug/.build-id"))
    assert os.path.exists(os.path.join(rootdir, "usr/share/zoneinfo/zone.tab"))
    for library in ("libc6", "libcurl4"):
        copyright_filename = f"usr/share/doc/{library}/copyright"
        assert os.path.exists(os.path.join(rootdir, copyright_filename))

    # their versions are as expected
    assert sandbox_ver("coreutils") == wanted["coreutils"]
    assert sandbox_ver("libc6") == wanted["libc6"]
    assert sandbox_ver("libc6-dbg") == wanted["libc6"]
    assert sandbox_ver("libcurl4") == wanted["libcurl4"]
    assert sandbox_ver("tzdata") > "2022a"

    with open(os.path.join(rootdir, "packages.txt"), encoding="utf-8") as f:
        pkglist = f.read().splitlines()
    assert f"coreutils {wanted['coreutils']}" in pkglist
    assert f"coreutils-dbgsym {wanted['coreutils']}" in pkglist
    assert f"libc6 {wanted['libc6']}" in pkglist
    assert f"libc6-dbg {wanted['libc6']}" in pkglist
    assert f"libcurl4 {wanted['libcurl4']}" in pkglist
    assert f"libcurl4-dbgsym {wanted['libcurl4']}" in pkglist
    assert f"tzdata {sandbox_ver('tzdata')}" in pkglist
    assert len(pkglist) == 7

    # does not clobber config dir
    assert os.listdir(configdir) == [release]

    expected_content = {"sources.list.d", "trusted.gpg.d"}
    # old-style apt sources have the old file present
    if apt_style == "one-line":
        expected_content.add("sources.list")

    assert set(os.listdir(os.path.join(configdir, release))) == (
        expected_content | {"armhf", "codename"}
    )
    assert (
        set(os.listdir(os.path.join(configdir, release, "armhf"))) == expected_content
    )

    # caches packages, and their versions are as expected
    cache = os.listdir(
        os.path.join(cachedir, release, "apt", "var", "cache", "apt", "archives")
    )
    cache_versions = {}
    for p in cache:
        try:
            (name, ver) = p.split("_")[:2]
            cache_versions[name] = ver
        except ValueError:
            pass  # not a .deb, ignore
    assert cache_versions["coreutils"] == wanted["coreutils"]
    assert cache_versions["coreutils-dbgsym"] == wanted["coreutils"]
    assert cache_versions["libc6"] == wanted["libc6"]
    assert cache_versions["libc6-dbg"] == wanted["libc6"]
    assert cache_versions["libcurl4"] == wanted["libcurl4"]
    assert "tzdata" in cache_versions

    # installs cached packages
    os.unlink(os.path.join(rootdir, "usr/bin/stat"))
    os.unlink(os.path.join(rootdir, "packages.txt"))
    obsolete = impl.install_packages(
        rootdir,
        configdir,
        release,
        [("coreutils", wanted["coreutils"])],
        False,
        cachedir,
    )
    assert obsolete == ""
    assert os.path.exists(os.path.join(rootdir, "usr/bin/stat"))

    # complains about obsolete packages
    result = impl.install_packages(rootdir, configdir, release, [("aspell-doc", "1.1")])
    assert "aspell-doc version 1.1 required, but 0.60.8-4build1" in result
    # ... but installs the current version anyway
    assert os.path.exists(os.path.join(rootdir, "usr/share/info/aspell.info.gz"))
    assert sandbox_ver("aspell-doc") >= "0.60.8"

    # does not crash on nonexisting packages
    result = impl.install_packages(
        rootdir, configdir, release, [("buggerbogger", None)]
    )
    assert len(result.splitlines()) == 1
    assert "buggerbogger" in result
    assert "not exist" in result

    # can interleave with other operations
    dpkg = subprocess.run(
        ["dpkg-query", "-Wf${Version}", "dash"], check=True, stdout=subprocess.PIPE
    )
    dash_version = dpkg.stdout.decode()

    assert impl.get_version("dash") == dash_version
    with pytest.raises(ValueError):
        impl.get_available_version("buggerbogger")

    # still installs packages after above operations
    os.unlink(os.path.join(rootdir, "usr/bin/stat"))
    os.unlink(os.path.join(rootdir, "packages.txt"))
    impl.install_packages(
        rootdir,
        configdir,
        release,
        [("coreutils", wanted["coreutils"]), ("dpkg", None)],
        False,
        cachedir,
    )
    assert os.path.exists(os.path.join(rootdir, "usr/bin/stat"))
    assert os.path.exists(os.path.join(rootdir, "usr/bin/dpkg"))


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_install_packages_unversioned(
    configdir: str, cachedir: str, rootdir: str, apt_style: AptStyle
) -> None:
    """install_packages() without versions and no cache"""
    release = _setup_foonux_config(configdir, apt_style)
    obsolete = impl.install_packages(
        rootdir,
        configdir,
        release,
        [("coreutils", None), ("tzdata", None)],
        False,
        None,
    )

    assert obsolete == ""
    assert os.path.exists(os.path.join(rootdir, "usr/bin/stat"))
    assert_elf_arch(
        os.path.join(rootdir, "usr/bin/stat"), impl.get_system_architecture()
    )
    assert os.path.exists(os.path.join(rootdir, "usr/lib/debug/.build-id"))
    assert os.path.exists(os.path.join(rootdir, "usr/share/zoneinfo/zone.tab"))

    # does not clobber config dir
    assert os.listdir(configdir) == [release]

    expected_content = {"sources.list.d", "trusted.gpg.d"}
    # old-style apt sources have the old file present
    if apt_style == "one-line":
        expected_content.add("sources.list")

    assert set(os.listdir(os.path.join(configdir, release))) == (
        expected_content | {"armhf", "codename"}
    )
    assert (
        set(os.listdir(os.path.join(configdir, release, "armhf"))) == expected_content
    )

    # no cache
    assert os.listdir(cachedir) == []

    # keeps track of package versions
    with open(os.path.join(rootdir, "packages.txt"), encoding="utf-8") as f:
        pkglist = f.read().splitlines()
    assert "coreutils 8.32-4.1ubuntu1" in pkglist
    assert "coreutils-dbgsym 8.32-4.1ubuntu1" in pkglist
    assert "tzdata 2022a-0ubuntu1" in pkglist
    assert len(pkglist), str(pkglist) == 3


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_install_packages_dependencies(
    configdir: str, rootdir: str, apt_style: AptStyle
) -> None:
    """Test install packages's dependencies."""
    release = _setup_foonux_config(configdir, apt_style)
    # coreutils should always depend on libc6
    result = impl.install_packages(
        rootdir,
        configdir,
        release,
        [("coreutils", None)],
        False,
        None,
        install_deps=True,
    )

    # check packages.txt for a dependency
    with open(os.path.join(rootdir, "packages.txt"), encoding="utf-8") as f:
        pkglist = f.read().splitlines()
    assert "coreutils 8.32-4.1ubuntu1" in pkglist
    assert "libc6 2.35-0ubuntu3" in pkglist

    # ensure obsolete packages doesn't include libc6
    assert "libc6" not in result


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_install_packages_system(
    cachedir: str, workdir: str, rootdir: str, apt_style: AptStyle
) -> None:
    # pylint: disable=unused-argument
    """install_packages() with system configuration"""
    # trigger an unrelated package query here to get the cache set up,
    # reproducing an install failure when the internal caches are not
    # reset properly
    impl.get_version("dash")

    release = " ".join(impl.get_os_version())
    cachedir = os.path.join(workdir, "cache")
    rootdir = os.path.join(workdir, "root")

    result = impl.install_packages(
        rootdir,
        None,
        release,
        [("coreutils", impl.get_version("coreutils")), ("tzdata", "1.1")],
        False,
        cachedir,
    )

    assert os.path.exists(os.path.join(rootdir, "usr/bin/stat"))
    assert os.path.exists(os.path.join(rootdir, "usr/share/zoneinfo/zone.tab"))

    # complains about obsolete packages
    assert len(result.splitlines()) == 1
    assert "tzdata" in result
    assert "1.1" in result

    # caches packages
    cache = os.listdir(
        os.path.join(cachedir, "system", "apt", "var", "cache", "apt", "archives")
    )
    cache_names = [p.split("_")[0] for p in cache]
    assert "coreutils" in cache_names
    assert "coreutils-dbgsym" in cache_names
    assert "tzdata" in cache_names

    # works with relative paths and existing cache
    os.unlink(os.path.join(rootdir, "usr/bin/stat"))
    os.unlink(os.path.join(rootdir, "packages.txt"))
    orig_cwd = os.getcwd()
    try:
        os.chdir(workdir)
        impl.install_packages(
            "root", None, release, [("coreutils", None)], False, "cache"
        )
    finally:
        os.chdir(orig_cwd)
        assert os.path.exists(os.path.join(rootdir, "usr/bin/stat"))


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_install_packages_error(
    configdir: str, cachedir: str, rootdir: str, apt_style: AptStyle
) -> None:
    """install_packages() with errors"""
    # sources.list with invalid format
    release = _setup_foonux_config(configdir, apt_style)
    with open(
        os.path.join(configdir, release, "sources.list"), "w", encoding="utf-8"
    ) as f:
        f.write("bogus format")

    with pytest.raises(SystemError) as exc_info:
        impl.install_packages(
            rootdir, configdir, release, [("tzdata", None)], False, cachedir
        )
    exc_info.match("E:Type 'bogus' is not known .* sources could not be read.$")

    # sources.list with wrong server
    with open(
        os.path.join(configdir, release, "sources.list"), "w", encoding="utf-8"
    ) as f:
        f.write("deb http://archive.ubuntu.com/nosuchdistro/ jammy main\n")

    with pytest.raises(SystemError) as exc_info:
        impl.install_packages(
            rootdir, configdir, release, [("tzdata", None)], False, cachedir
        )
    exc_info.match(
        "E:The repository 'http://archive.ubuntu.com/nosuchdistro"
        " jammy.*' does not have a Release file.$"
    )


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_install_packages_permanent_sandbox(
    configdir: str, cachedir: str, rootdir: str, apt_style: AptStyle
) -> None:
    """install_packages() with a permanent sandbox"""
    release = _setup_foonux_config(configdir, apt_style)
    zonetab = os.path.join(rootdir, "usr/share/zoneinfo/zone.tab")

    impl.install_packages(
        rootdir,
        configdir,
        release,
        [("tzdata", None)],
        False,
        cachedir,
        permanent_rootdir=True,
    )

    # This will now be using a Cache with our rootdir.
    archives = apt_pkg.config.find_dir("Dir::Cache::archives")
    tzdata = glob.glob(os.path.join(archives, "tzdata*.deb"))
    assert tzdata
    tzdata_written = os.path.getctime(tzdata[0])
    zonetab_written = os.path.getctime(zonetab)

    impl.install_packages(
        rootdir,
        configdir,
        release,
        [("coreutils", None), ("tzdata", None)],
        False,
        cachedir,
        permanent_rootdir=True,
    )

    # Check if the deb was downloaded
    assert glob.glob(os.path.join(archives, "coreutils*.deb"))
    assert os.path.getctime(tzdata[0]) == tzdata_written
    assert zonetab_written == os.path.getctime(zonetab)
    assert os.path.exists(os.path.join(rootdir, "usr/bin/stat"))

    # Prevent packages from downloading.
    orig_apt_proxy = apt_pkg.config.get("Acquire::http::Proxy", "")
    apt_pkg.config.set("Acquire::http::Proxy", "http://nonexistent")
    orig_http_proxy = os.environ.get("http_proxy")
    os.environ["http_proxy"] = "http://nonexistent"
    try:
        orig_no_proxy = os.environ["no_proxy"]
        del os.environ["no_proxy"]
    except KeyError:
        orig_no_proxy = None

    with pytest.raises(SystemExit):
        impl.install_packages(
            rootdir,
            configdir,
            release,
            [("libc6", None)],
            False,
            cachedir,
            permanent_rootdir=True,
        )

    # These packages exist, so attempting to install them should not fail.
    impl.install_packages(
        rootdir,
        configdir,
        release,
        [("coreutils", None), ("tzdata", None)],
        False,
        cachedir,
        permanent_rootdir=True,
    )
    # even without cached debs, trying to install the same versions should
    # be a no-op and succeed
    for f in glob.glob(f"{cachedir}/{release}/apt/var/cache/apt/archives/coreutils*"):
        os.unlink(f)
    impl.install_packages(
        rootdir,
        configdir,
        release,
        [("coreutils", None)],
        False,
        cachedir,
        permanent_rootdir=True,
    )

    # trying to install another package should fail, though
    with pytest.raises(SystemExit):
        impl.install_packages(
            rootdir,
            configdir,
            release,
            [("aspell-doc", None)],
            False,
            cachedir,
            permanent_rootdir=True,
        )

    # restore original proxy settings
    if orig_http_proxy:
        os.environ["http_proxy"] = orig_http_proxy
    else:
        del os.environ["http_proxy"]
    if orig_no_proxy:
        os.environ["no_proxy"] = orig_no_proxy
    apt_pkg.config.set("Acquire::http::Proxy", orig_apt_proxy)


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_install_packages_permanent_sandbox_repack(
    configdir: str, cachedir: str, rootdir: str, apt_style: AptStyle
) -> None:
    # Both packages needs to conflict with each other, because they
    # ship the same file.
    release = _setup_foonux_config(configdir, apt_style)
    impl.install_packages(
        rootdir,
        configdir,
        release,
        [("libcurl4-gnutls-dev", None)],
        False,
        cachedir,
        permanent_rootdir=True,
    )
    curl_library = _get_library_path("libcurl.so", rootdir)
    assert os.readlink(curl_library) == "libcurl-gnutls.so"

    impl.install_packages(
        rootdir,
        configdir,
        release,
        [("libcurl4-nss-dev", None)],
        False,
        cachedir,
        permanent_rootdir=True,
    )
    assert os.readlink(curl_library) == "libcurl-nss.so"

    impl.install_packages(
        rootdir,
        configdir,
        release,
        [("libcurl4-gnutls-dev", None)],
        False,
        cachedir,
        permanent_rootdir=True,
    )
    assert os.readlink(curl_library) == "libcurl-gnutls.so"


@pytest.mark.skipif(not has_internet(), reason="online test")
@pytest.mark.skipif(
    impl.get_system_architecture() == "armhf", reason="native armhf architecture"
)
def test_install_packages_armhf(
    configdir: str, cachedir: str, rootdir: str, apt_style: AptStyle
) -> None:
    """install_packages() for foreign architecture armhf"""
    release = _setup_foonux_config(configdir, apt_style)
    wanted_version = "2.35-0ubuntu0"
    got_version = "2.35-0ubuntu3"
    obsolete = impl.install_packages(
        rootdir,
        configdir,
        release,
        [("coreutils", None), ("libc6", wanted_version)],
        False,
        cachedir,
        architecture="armhf",
    )

    assert (
        obsolete == f"libc6 version {wanted_version} required,"
        f" but {got_version} is available\n"
    )
    assert os.path.exists(os.path.join(rootdir, "usr/bin/stat"))
    assert_elf_arch(os.path.join(rootdir, "usr/bin/stat"), "armhf")
    assert os.path.exists(os.path.join(rootdir, "usr/share/doc/libc6/copyright"))
    # caches packages
    cache = os.listdir(
        os.path.join(
            cachedir, release, "armhf", "apt", "var", "cache", "apt", "archives"
        )
    )
    assert "coreutils_8.32-4.1ubuntu1_armhf.deb" in cache
    assert f"libc6_{got_version}_armhf.deb" in cache


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_install_packages_from_launchpad(
    configdir: str, cachedir: str, rootdir: str, apt_style: AptStyle
) -> None:
    """install_packages() using packages only available on Launchpad"""
    release = _setup_foonux_config(configdir, apt_style, release="focal")
    # Wanted are superseded versions from -updates or -security.
    wanted = {
        "distro-info-data": "0.43ubuntu1.9",  # arch all
        "libc6": "2.31-0ubuntu9.4",  # -dbg, arch specific
        "qemu-utils": "1:4.2-3ubuntu6.1",  # -dbgsym, arch specific
    }
    obsolete = impl.install_packages(
        rootdir, configdir, release, list(wanted.items()), False, cachedir
    )

    def sandbox_ver(pkg: str, debian: bool = True) -> str:
        if debian:
            changelog = "changelog.Debian.gz"
        else:
            changelog = "changelog.gz"
        with gzip.open(os.path.join(rootdir, "usr/share/doc", pkg, changelog)) as f:
            return f.readline().decode().split()[1][1:-1]

    assert obsolete == ""

    # packages get installed
    assert os.path.exists(os.path.join(rootdir, "usr/share/distro-info/ubuntu.csv"))
    assert os.path.exists(os.path.join(rootdir, "usr/lib/debug/.build-id"))
    assert os.path.exists(os.path.join(rootdir, "usr/bin/qemu-img"))

    # their versions are as expected
    assert sandbox_ver("distro-info-data", debian=False) == wanted["distro-info-data"]
    assert sandbox_ver("libc6") == wanted["libc6"]
    assert sandbox_ver("libc6-dbg") == wanted["libc6"]

    # keeps track of package versions
    with open(os.path.join(rootdir, "packages.txt"), encoding="utf-8") as f:
        pkglist = f.read().splitlines()
    assert f"distro-info-data {wanted['distro-info-data']}" in pkglist
    assert f"libc6 {wanted['libc6']}" in pkglist
    assert f"libc6-dbg {wanted['libc6']}" in pkglist
    assert f"qemu-utils {wanted['qemu-utils']}" in pkglist
    assert f"qemu-utils-dbgsym {wanted['qemu-utils']}" in pkglist

    # caches packages, and their versions are as expected
    cache = os.listdir(
        os.path.join(cachedir, release, "apt", "var", "cache", "apt", "archives")
    )

    # archive and launchpad versions of packages exist in the cache,
    # so use a list
    cache_versions = []
    for p in cache:
        try:
            (name, ver) = p.split("_")[:2]
            cache_versions.append((name, ver))
        except ValueError:
            pass  # not a .deb, ignore
    assert ("distro-info-data", wanted["distro-info-data"]) in cache_versions
    assert ("libc6-dbg", wanted["libc6"]) in cache_versions
    assert ("qemu-utils-dbgsym", _strip_epoch(wanted["qemu-utils"])) in cache_versions


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_install_old_packages(
    configdir: str, cachedir: str, rootdir: str, apt_style: AptStyle
) -> None:
    """Sandbox will install older package versions from launchpad."""
    release = _setup_foonux_config(configdir, apt_style)
    wanted_package = "libcurl4"
    wanted_version = "7.81.0-1"  # pre-release version
    obsolete = impl.install_packages(
        rootdir, configdir, release, [(wanted_package, wanted_version)], False, cachedir
    )

    assert obsolete == ""

    def sandbox_ver(pkg: str) -> str:
        with gzip.open(
            os.path.join(rootdir, "usr/share/doc", pkg, "changelog.Debian.gz")
        ) as f:
            return f.readline().decode().split()[1][1:-1]

    # the version is as expected
    assert sandbox_ver(wanted_package) == wanted_version

    # keeps track of package version
    with open(os.path.join(rootdir, "packages.txt"), encoding="utf-8") as f:
        pkglist = f.read().splitlines()
    assert f"{wanted_package} {wanted_version}" in pkglist

    wanted_version = "7.74.0-1.3ubuntu3"
    obsolete = impl.install_packages(
        rootdir, configdir, release, [(wanted_package, wanted_version)], False, cachedir
    )

    assert obsolete == ""

    # the old version is installed
    assert sandbox_ver(wanted_package) == wanted_version

    # the old versions is tracked
    with open(os.path.join(rootdir, "packages.txt"), encoding="utf-8") as f:
        pkglist = f.read().splitlines()
    assert f"{wanted_package} {wanted_version}" in pkglist


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_get_source_tree_sandbox(
    configdir: str, workdir: str, rootdir: str, apt_style: AptStyle
) -> None:
    release = _setup_foonux_config(configdir, apt_style)
    out_dir = os.path.join(workdir, "out")
    os.mkdir(out_dir)
    # pylint: disable=protected-access
    impl._build_apt_sandbox(
        rootdir, os.path.join(configdir, release), "ubuntu", "jammy", origins=None
    )
    res = impl.get_source_tree("base-files", out_dir, sandbox=rootdir)
    assert os.path.isdir(os.path.join(res, "debian"))
    # this needs to be updated when the release in _setup_foonux_config
    # changes
    assert res.endswith("/base-files-12ubuntu4")


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_get_source_tree_lp_sandbox(
    configdir: str, workdir: str, rootdir: str, apt_style: AptStyle
) -> None:
    release = _setup_foonux_config(configdir, apt_style)
    wanted_package = "curl"
    wanted_version = "7.81.0-1ubuntu1.2"  # superseded -security version
    out_dir = os.path.join(workdir, "out")
    os.mkdir(out_dir)
    # pylint: disable=protected-access
    impl._build_apt_sandbox(
        rootdir, os.path.join(configdir, release), "ubuntu", "jammy", origins=None
    )
    res = impl.get_source_tree(
        wanted_package, out_dir, version=wanted_version, sandbox=rootdir
    )
    assert os.path.isdir(os.path.join(res, "debian"))
    # this needs to be updated when the release in _setup_foonux_config
    # changes
    upstream_version = wanted_version.split("-", maxsplit=1)[0]
    assert res.endswith(f"/{wanted_package}-{upstream_version}")


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_create_sources_for_a_named_ppa(
    configdir: str, rootdir: str, apt_style: AptStyle
) -> None:
    """Add sources.list entries for a named PPA."""
    ppa = "LP-PPA-daisy-pluckers-daisy-seeds"
    release = _setup_foonux_config(configdir, apt_style)
    # pylint: disable=protected-access
    impl._build_apt_sandbox(
        rootdir, os.path.join(configdir, release), "ubuntu", "jammy", origins=[ppa]
    )
    ppasource = os.path.join(rootdir, "etc", "apt", "sources.list.d", f"{ppa}.sources")
    entries = _parse_deb822_sources(ppasource)
    assert [
        e
        for e in entries
        if {"deb", "deb-src"} == set(e.types)
        and "jammy" in e.suites
        and "main" in e.comps
        and "http://ppa.launchpad.net/" "daisy-pluckers/daisy-seeds/ubuntu" in e.uris
    ]
    assert [
        e
        for e in entries
        if "deb" in e.types
        and "jammy" in e.suites
        and "main/debug" in e.comps
        and "http://ppa.launchpad.net/" "daisy-pluckers/daisy-seeds/ubuntu" in e.uris
    ]

    trusted_gpg_d = pathlib.Path(rootdir) / "etc" / "apt" / "trusted.gpg.d"
    actual_file = trusted_gpg_d / "LP-PPA-daisy-pluckers-daisy-seeds.asc"
    actual_key = actual_file.read_text(encoding="utf-8")
    expected_file = get_test_data_directory() / "LP-PPA-daisy-pluckers-daisy-seeds.asc"
    expected_key = expected_file.read_text(encoding="utf-8")

    assert expected_key == actual_key


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_create_sources_for_an_unnamed_ppa(
    configdir: str, rootdir: str, apt_style: AptStyle
) -> None:
    """Add sources.list entries for an unnamed PPA."""
    ppa = "LP-PPA-apport-hackers-apport-autopkgtests"
    release = _setup_foonux_config(configdir, apt_style, ppa=True)
    # pylint: disable=protected-access
    impl._build_apt_sandbox(
        rootdir, os.path.join(configdir, release), "ubuntu", "jammy", origins=[ppa]
    )
    ppasource = os.path.join(rootdir, "etc", "apt", "sources.list.d", f"{ppa}.sources")
    entries = _parse_deb822_sources(ppasource)
    assert [
        e
        for e in entries
        if {"deb", "deb-src"} == set(e.types)
        and "jammy" in e.suites
        and "main" in e.comps
        and "http://ppa.launchpad.net/"
        "apport-hackers/apport-autopkgtests/ubuntu" in e.uris
    ]
    assert [
        e
        for e in entries
        if "deb" in e.types
        and "jammy" in e.suites
        and "main/debug" in e.comps
        and "http://ppa.launchpad.net/"
        "apport-hackers/apport-autopkgtests/ubuntu" in e.uris
    ]

    trusted_gpg_d = pathlib.Path(rootdir) / "etc" / "apt" / "trusted.gpg.d"
    actual_file = trusted_gpg_d / "LP-PPA-apport-hackers-apport-autopkgtests.asc"
    actual_key = actual_file.read_text(encoding="utf-8")
    expected_file = (
        get_test_data_directory() / "LP-PPA-apport-hackers-apport-autopkgtests.asc"
    )
    expected_key = expected_file.read_text(encoding="utf-8")

    assert expected_key == actual_key


def test_use_sources_for_a_ppa(
    configdir: str, rootdir: str, apt_style: AptStyle
) -> None:
    """Use a sources.list.d file for a PPA."""
    ppa = "fooser-bar-ppa"
    release = _setup_foonux_config(configdir, apt_style, ppa=True)
    # pylint: disable=protected-access
    impl._build_apt_sandbox(
        rootdir,
        os.path.join(configdir, release),
        "ubuntu",
        "jammy",
        origins=[f"LP-PPA-{ppa}"],
    )
    if apt_style == "one-line":
        with open(
            os.path.join(rootdir, "etc", "apt", "sources.list.d", f"{ppa}.list"),
            encoding="utf-8",
        ) as f:
            sources = f.read().splitlines()
        assert (
            "deb http://ppa.launchpad.net/fooser/bar-ppa/ubuntu"
            " jammy main main/debug" in sources
        )
        assert (
            "deb-src http://ppa.launchpad.net/fooser/bar-ppa/ubuntu"
            " jammy main" in sources
        )
    else:
        ppasource = os.path.join(
            rootdir, "etc", "apt", "sources.list.d", f"{ppa}.sources"
        )
        entries = _parse_deb822_sources(ppasource)

        assert [
            e
            for e in entries
            if "deb-src" in e.types and "jammy" in e.suites and "main" in e.comps
        ]


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_install_package_from_a_ppa(
    configdir: str, cachedir: str, rootdir: str, apt_style: AptStyle
) -> None:
    """Install a package from a PPA."""
    # Needs apport package in https://launchpad.net
    # /~apport-hackers/+archive/ubuntu/apport-autopkgtests
    ppa = "LP-PPA-apport-hackers-apport-autopkgtests"
    release = _setup_foonux_config(configdir, apt_style)
    wanted_package = "apport"
    wanted_version = "2.20.11-0ubuntu82.1~ppa2"
    obsolete = impl.install_packages(
        rootdir,
        configdir,
        release,
        [(wanted_package, wanted_version)],
        False,
        cachedir,
        origins=[ppa],
    )

    assert obsolete == ""

    def sandbox_ver(pkg: str) -> str:
        with gzip.open(
            os.path.join(rootdir, "usr/share/doc", pkg, "changelog.Debian.gz")
        ) as f:
            return f.readline().decode().split()[1][1:-1]

    assert sandbox_ver(wanted_package) == wanted_version


def _get_library_path(library_name: str, root_dir: str = "/") -> str:
    """Find library path regardless of the architecture."""
    libraries = glob.glob(os.path.join(root_dir, "usr/lib/*", library_name))
    assert len(libraries) == 1
    return libraries[0]


def _ubuntu_archive_uri(arch: str | None = None) -> str:
    """Return archive URI for the given architecture."""
    if arch is None:
        arch = impl.get_system_architecture()
    if arch in {"amd64", "i386"}:
        return "http://archive.ubuntu.com/ubuntu"
    return "http://ports.ubuntu.com/ubuntu-ports"


def _write_deb822_file(
    sources_filename: str, uri: str, release: str, updates: bool, ppa: bool = False
) -> None:
    with open(sources_filename, "w", encoding="utf-8") as sources_file:
        updates_suite = f"{release}-updates" if updates else ""
        sources_file.write(
            textwrap.dedent(
                f"""\
                    Types: deb deb-src
                    URIs: {uri}
                    Suites:
                     {release} {updates_suite}
                    Components: main
                    """
            )
        )

        sources_file.write("\n")

        if ppa:
            sources_file.write(
                textwrap.dedent(
                    f"""\
                        Types: deb
                        URIs: {uri}
                        Suites: {release}
                        Components: main/debug"""
                )
            )
        else:
            sources_file.write(
                textwrap.dedent(
                    f"""\
                        Types: deb
                        URIs: http://ddebs.ubuntu.com/
                        Suites:
                         {release} {updates_suite}
                        Components: main
                        """
                )
            )


def _setup_foonux_config(
    configdir: str,
    apt_style: AptStyle,
    updates: bool = False,
    release: str = "jammy",
    ppa: bool = False,
) -> str:
    """Set up directories and configuration for install_packages()

    If ppa is True, then a sources.list file for a PPA will be created
    in sources.list.d used to test copying of a sources.list file to a
    sandbox.

    Return name and version of the operating system (DistroRelease
    field in crash report).
    """
    versions = {"focal": "20.04", "jammy": "22.04"}
    distro_release = f"Foonux {versions[release]}"
    config_release_dir = os.path.join(configdir, distro_release)
    sources_dir = os.path.join(config_release_dir, "sources.list.d")
    armhf_dir = os.path.join(config_release_dir, "armhf")
    armhf_sources = os.path.join(armhf_dir, "sources.list.d")
    os.makedirs(sources_dir)
    os.makedirs(armhf_sources)
    if apt_style == "deb822":
        _write_deb822_file(
            os.path.join(sources_dir, "foonux.sources"),
            _ubuntu_archive_uri(),
            release,
            updates,
        )
        if ppa:
            _write_deb822_file(
                os.path.join(sources_dir, "fooser-bar-ppa.sources"),
                "http://ppa.launchpad.net/fooser/bar-ppa/ubuntu",
                release,
                False,
                ppa=True,
            )
        _write_deb822_file(
            os.path.join(armhf_sources, "armhf.sources"),
            _ubuntu_archive_uri("armhf"),
            release,
            updates,
        )
    else:
        _write_source_file(
            os.path.join(config_release_dir, "sources.list"),
            _ubuntu_archive_uri(),
            release,
            updates,
        )
        if ppa:
            _write_source_file(
                os.path.join(sources_dir, "fooser-bar-ppa.list"),
                "http://ppa.launchpad.net/fooser/bar-ppa/ubuntu",
                release,
                False,
                ppa=True,
            )
        _write_source_file(
            os.path.join(armhf_dir, "sources.list"),
            _ubuntu_archive_uri("armhf"),
            release,
            updates,
        )
    with open(os.path.join(config_release_dir, "codename"), "w", encoding="utf-8") as f:
        f.write(f"{release}")

    # install GPG key for ddebs
    # TODO: figure out a way to do it in the new deb822 world
    keyring_dir = os.path.join(config_release_dir, "trusted.gpg.d")
    _copy_ubuntu_keyrings(keyring_dir)
    # Create an architecture specific symlink, otherwise it cannot be
    # found for armhf in __AptDpkgPackageInfo._build_apt_sandbox() as
    # that looks for trusted.gpg.d relative to sources.list.
    keyring_arch_dir = os.path.join(armhf_dir, "trusted.gpg.d")
    os.symlink("../trusted.gpg.d", keyring_arch_dir)
    return distro_release


def _strip_epoch(version: str) -> str:
    """Strip epoch from Debian package version."""
    return version.split(":", maxsplit=1)[-1]


def _copy_ubuntu_keyrings(keyring_dir: str) -> None:
    """Copy the archive and debug symbol archive keyring."""
    os.makedirs(keyring_dir, exist_ok=True)
    try:
        shutil.copy("/usr/share/keyrings/ubuntu-archive-keyring.gpg", keyring_dir)
    except FileNotFoundError as error:  # pragma: no cover
        pytest.skip(f"{error.filename} missing. Please install ubuntu-keyring!")

    dbgsym_keyring = "/usr/share/keyrings/ubuntu-dbgsym-keyring.gpg"
    if not os.path.isfile(dbgsym_keyring):
        pytest.skip(  # pragma: no cover
            f"{dbgsym_keyring} missing. Please install ubuntu-dbgsym-keyring!"
        )
    # Convert from GPG keybox database format to OpenPGP Public Key format
    output_dbgsym_keyring = os.path.join(keyring_dir, os.path.basename(dbgsym_keyring))
    try:
        with open(output_dbgsym_keyring, "wb") as gpg_key:
            gpg_cmd = [
                "gpg",
                "--no-default-keyring",
                "--keyring",
                dbgsym_keyring,
                "--export",
            ]
            subprocess.check_call(gpg_cmd, stdout=gpg_key)
    except FileNotFoundError as error:  # pragma: no cover
        pytest.skip(f"{error.filename} not available")


def _write_source_file(
    sources_filename: str, uri: str, release: str, updates: bool, ppa: bool = False
) -> None:
    """Write sources.list file."""
    with open(sources_filename, "w", encoding="utf-8") as sources_file:
        sources_file.write(
            f"deb {uri} {release} main {'main/debug' if ppa else ''}\n"
            f"deb-src {uri} {release} main\n"
        )
        if not ppa:
            sources_file.write(f"deb http://ddebs.ubuntu.com/ {release} main\n")
        if updates:
            sources_file.write(
                f"deb {uri} {release}-updates main\n"
                f"deb-src {uri} {release}-updates main\n"
                f"deb http://ddebs.ubuntu.com/ {release}-updates main\n"
            )


def assert_elf_arch(path: str, expected: str) -> None:
    """Assert that an ELF file is for an expected machine type.

    Expected is a Debian-style architecture (i386, amd64, armhf)
    """
    archmap = {
        "amd64": "X86-64",
        "arm64": "AArch64",
        "armhf": "ARM",
        "i386": "80386",
        "ppc64el": "PowerPC64",
        "s390x": "IBM S/390",
    }

    # get ELF machine type
    env: dict[str, str] = {}
    readelf = subprocess.run(
        ["readelf", "-e", path], check=True, env=env, stdout=subprocess.PIPE, text=True
    )
    for line in readelf.stdout.splitlines():
        if line.startswith("  Machine:"):
            machine = line.split(None, 1)[1]
            break
    else:
        pytest.fail("could not find Machine: in readelf output")

    assert archmap[expected] in machine
