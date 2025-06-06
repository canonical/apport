"""Abstraction of packaging operations."""

# Copyright (C) 2007 - 2011 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import platform
import re
from collections.abc import Iterable


class PackageInfo:
    """Abstraction of packaging operations."""

    # default global configuration file
    configuration = "/etc/default/apport"

    def get_version(self, package: str) -> str:
        """Return the installed version of a package.

        Throw ValueError if package does not exist.
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def get_available_version(self, package: str) -> str:
        """Return the latest available version of a package.

        Throw ValueError if package does not exist.
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def get_dependencies(self, package: str) -> list[str]:
        """Return a list of packages a package depends on."""
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def get_source(self, package: str) -> str:
        """Return the source package name for a package.

        Throw ValueError if package does not exist.
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def get_package_origin(self, package: str) -> str | None:
        """Return package origin.

        Return the repository name from which a package was installed, or None
        if it cannot be determined.

        Throw ValueError if package is not installed.
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def is_distro_package(self, package: str) -> bool:
        """Check package origin.

        Return True if the package is a genuine distro package, or False if it
        comes from a third-party source.

        Throw ValueError if package does not exist.
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def get_architecture(self, package: str) -> str:
        """Return the architecture of a package.

        This might differ on multiarch architectures (e. g. an i386 Firefox
        package on a x86_64 system)
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def get_files(self, package: str) -> list[str]:
        """Return list of files shipped by a package.

        Throw ValueError if package does not exist.
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def get_modified_files(self, package: str) -> list[str]:
        """Return list of all modified files of a package."""
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def get_modified_conffiles(self, package: str) -> dict[str, bytes | str]:
        """Return modified configuration files of a package.

        Return a file name -> file contents map of all configuration files of
        package. Please note that apport.hookutils.attach_conffiles() is the
        official user-facing API for this, which will ask for confirmation and
        allows filtering.
        """
        # Default implementation does nothing, i.e. no config files modified
        # pylint: disable=no-self-use,unused-argument
        return {}

    def get_file_package(
        self,
        file: str,
        uninstalled: bool = False,
        map_cachedir: str | None = None,
        release: str | None = None,
        arch: str | None = None,
    ) -> str | None:
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
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    @staticmethod
    def get_system_architecture() -> str:
        """Return the architecture of the system.

        This should use the notation of the particular distribution.
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    @staticmethod
    def get_native_multiarch_triplet() -> str:
        """Return the GNU multiarch triplet for of the system architecture, if
        applicable, raises NotImplementedError otherwise.
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass if applicable"
        )

    def get_library_paths(self) -> str:
        """Return a list of default library search paths.

        The entries should be separated with a colon ':', like for
        $LD_LIBRARY_PATH. This needs to take any multiarch directories into
        account.
        """
        # simple default implementation, pylint: disable=no-self-use
        return "/lib:/usr/lib"

    def set_mirror(self, url: str) -> None:
        """Explicitly set a distribution mirror URL.

        This might be called for operations that need to fetch distribution
        files/packages from the network.

        By default, the mirror will be read from the system configuration
        files.
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def get_source_tree(
        self,
        srcpackage: str,
        output_dir: str,
        version: str | None = None,
        sandbox: str | None = None,
    ) -> str | None:
        """Download source package and unpack it into output_dir.

        This also has to care about applying patches etc., so that output_dir
        will eventually contain the actually compiled source. output_dir needs
        to exist and should be empty.

        If version is given, this particular version will be retrieved.
        Otherwise this will fetch the latest available version.

        If sandbox is given, that sandbox is used to download the source
        package, otherwise it uses the system configuration.

        Return the directory that contains the actual source root directory
        (which might be a subdirectory of output_dir). Return None if the
        source is not available.
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def compare_versions(self, ver1: str, ver2: str) -> int:
        """Compare two package versions.

        Return -1 for ver < ver2, 0 for ver1 == ver2, and 1 for ver1 > ver2.
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def enabled(self) -> bool:
        """Return whether Apport should generate crash reports.

        Signal crashes are controlled by /proc/sys/kernel/core_pattern, but
        some init script needs to set that value based on a configuration file.
        This also determines whether Apport generates reports for Python,
        package, or kernel crashes.

        Implementations should parse the configuration file which controls
        Apport (such as /etc/default/apport in Debian/Ubuntu).
        """
        try:
            with open(self.configuration, encoding="utf-8") as config_file:
                conf = config_file.read()
        except OSError:
            # if the file does not exist, assume it's enabled
            return True

        return re.search(r"^\s*enabled\s*=\s*0\s*$", conf, re.M) is None

    def get_kernel_package(self) -> str:
        """Return the actual Linux kernel package name.

        This is used when the user reports a bug against the "linux" package.
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def install_packages(
        self,
        rootdir: str,
        configdir: str | None,
        release: str,
        packages: list[tuple[str, str | None]],
        verbose: bool = False,
        cache_dir: str | None = None,
        permanent_rootdir: bool = False,
        architecture: str | None = None,
        origins: Iterable[str] | None = None,
        install_dbg: bool = True,
        install_deps: bool = False,
    ) -> str:
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

        Return a string with outdated packages, or None if all packages were
        installed.

        If something is wrong with the environment (invalid configuration,
        package servers down, etc.), this should raise a SystemError with a
        meaningful error message.
        """
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def package_name_glob(self, nameglob: str) -> list[str]:
        """Return known package names which match given glob."""
        raise NotImplementedError(
            "this method must be implemented by a concrete subclass"
        )

    def is_native_origin_package(self, package: str) -> bool:
        """Check if a package is one which has been allow listed.

        Return True for a package which came from an origin which is listed in
        native-origins.d, False if it comes from a third-party source.
        """
        # Default implementation does nothing, i. e. native origins are not
        # supported.
        # pylint: disable=no-self-use,unused-argument
        return False

    def get_uninstalled_package(self) -> str:
        """Return a valid package name which is not installed.

        Raises a ValueError in case no uninstalled package was found.

        This is only used in the test suite. The default implementation should
        work, but might be slow for your backend, so you might want to
        reimplement this.
        """
        for package in self.package_name_glob("*"):
            if not self.is_distro_package(package):
                continue
            try:
                self.get_version(package)
                continue
            except ValueError:
                return package
        raise ValueError

    _os_version = None

    @staticmethod
    def _sanitize_operating_system_name(name: str) -> str:
        # Strip GNU/Linux from e.g. "Debian GNU/Linux"
        if name.endswith(" GNU/Linux"):
            name = name.rsplit(maxsplit=1)[0]
        return name

    def get_os_version(self) -> tuple[str, str]:
        """Return (osname, osversion) tuple.

        This is read from /etc/os-release.
        """
        if self._os_version:
            return self._os_version

        info = platform.freedesktop_os_release()
        name = self._sanitize_operating_system_name(info["NAME"])
        version = info.get("VERSION_ID", "n/a")
        self._os_version = (name, version)
        return self._os_version
