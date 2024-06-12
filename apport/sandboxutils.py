"""Functions to manage sandboxes."""

# Copyright (C) 2006 - 2013 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#         Kyle Nitzsche <kyle.nitzsche@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import atexit
import os
import re
import shutil
import tempfile

import apport.fileutils
import apport.logging
from apport.packaging_impl import impl as packaging


def needed_packages(report):
    """Determine necessary packages for given report.

    Return list of (pkgname, version) pairs. version might be None for unknown
    package versions.
    """
    pkgs = {}

    # first, grab the versions that we captured at crash time
    for line in (
        f"{report.get('Package', '')}\n{report.get('Dependencies', '')}"
    ).splitlines():
        if not line.strip():
            continue
        try:
            (pkg, version) = line.split()[:2]
        except ValueError:
            apport.logging.warning("invalid Package/Dependencies line: %s", line)
            # invalid line, ignore
            continue
        pkgs[pkg] = version

    return list(pkgs.items())


def report_package_versions(report):
    """Return package -> version dictionary from report."""
    pkg_vers = {}
    for line in (
        f"{report.get('Package', '')}\n{report.get('Dependencies', '')}"
    ).splitlines():
        if not line.strip():
            continue
        try:
            (pkg, version) = line.split()[:2]
        except ValueError:
            apport.logging.warning("invalid Package/Dependencies line: %s", line)
            # invalid line, ignore
            continue
        pkg_vers[pkg] = version

    return pkg_vers


def needed_runtime_packages(report, pkgmap_cache_dir, pkg_versions, verbose=False):
    """Determine necessary runtime packages for given report.

    This determines libraries dynamically loaded at runtime in two cases:
    1. The executable has already run: /proc/pid/maps is used, from the report
    2. The executable has not already run: shared_libraries() is used

    The libraries are resolved to the packages that installed them.

    Return list of (pkgname, None) pairs.

    When pkgmap_cache_dir is specified, it is used as a cache for
    get_file_package().
    """
    # check list of libraries that the crashed process referenced at
    # runtime and warn about those which are not available
    pkgs = set()
    libs = set()
    if "ProcMaps" in report:
        for line in report["ProcMaps"].splitlines():
            if not line.strip():
                continue
            cols = line.split()
            if len(cols) in {6, 7} and "x" in cols[1] and ".so" in cols[5]:
                lib = os.path.realpath(cols[5])
                libs.add(lib)
    else:
        # 'ProcMaps' key is absent in apport-valgrind use case
        libs = apport.fileutils.shared_libraries(report["ExecutablePath"]).values()
    if not os.path.exists(pkgmap_cache_dir):
        os.makedirs(pkgmap_cache_dir)

    # grab as much as we can
    for line in libs:
        pkg = packaging.get_file_package(
            line,
            True,
            pkgmap_cache_dir,
            release=report["DistroRelease"],
            arch=report.get("Architecture"),
        )
        if pkg:
            if verbose:
                apport.logging.log(
                    f"dynamically loaded {line} needs package {pkg}, queueing"
                )
            pkgs.add(pkg)
        else:
            apport.logging.warning(
                "%s is needed, but cannot be mapped to a package", line
            )

    return [(p, pkg_versions.get(p)) for p in pkgs]


def _move_base_files_first(pkgs: list[tuple[str, None | str]]) -> None:
    """Move base-files to the front or add it if missing."""
    for i, (pkg, version) in enumerate(pkgs):
        if pkg == "base-files":
            pkgs.pop(i)
            pkgs[:0] = [("base-files", version)]
            return


# pylint: disable-next=too-many-arguments
def make_sandbox(
    report: apport.Report,
    config_dir: str | None,
    cache_dir: str | None = None,
    sandbox_dir: str | None = None,
    extra_packages: list[str] | None = None,
    verbose: bool = False,
    log_timestamps: bool = False,
    dynamic_origins: bool = False,
) -> tuple[str, str, str]:
    # TODO: Split into smaller functions/methods
    # pylint: disable=too-many-branches,too-many-locals,too-many-statements
    """Build a sandbox with the packages that belong to a particular report.

    This downloads and unpacks all packages from the report's Package and
    Dependencies fields, plus all packages that ship the files from ProcMaps
    (often, runtime plugins do not appear in Dependencies), plus optionally
    some extra ones, for the distro release and architecture of the report.

    For unpackaged executables, there are no Dependencies. Packages for shared
    libraries are unpacked.

    report is an apport.Report object to build a sandbox for. Presence of the
    Package field determines whether to determine dependencies through
    packaging (via the optional report['Dependencies'] field), or through ldd
    via needed_runtime_packages() -> shared_libraries().  Usually
    report['Architecture'] and report['Uname'] are present.

    config_dir points to a directory with by-release configuration files for
    the packaging system, or "system"; this is passed to
    apport.packaging.install_packages(), see that method for details.

    cache_dir points to a directory where the downloaded packages and debug
    symbols are kept, which is useful if you create sandboxes very often. If
    not given, the downloaded packages get deleted at program exit.

    sandbox_dir points to a directory with a permanently unpacked sandbox with
    the already unpacked packages. This speeds up operations even further if
    you need to create sandboxes for different reports very often; but the
    sandboxes can become very big over time, and you must ensure that an
    already existing sandbox matches the DistroRelease: and Architecture: of
    report. If not given, a temporary directory will be created which gets
    deleted at program exit.

    extra_packages can specify a list of additional packages to install which
    are not derived from the report and will be installed along with their
    dependencies.

    If verbose is True (False by default), this will write some additional
    logging to stdout.

    If log_timestamps is True, these log messages will be prefixed with the
    current time.

    If dynamic_origins is True (False by default), the sandbox will be built
    with packages from foreign origins that appear in the report's
    Packages:/Dependencies:.

    Return a tuple (sandbox_dir, cache_dir, outdated_msg).
    """
    # sandbox
    if sandbox_dir:
        sandbox_dir = os.path.abspath(sandbox_dir)
        if not os.path.isdir(sandbox_dir):
            os.makedirs(sandbox_dir)
        permanent_rootdir = True
    else:
        sandbox_dir = tempfile.mkdtemp(prefix="apport_sandbox_")
        atexit.register(shutil.rmtree, sandbox_dir)
        permanent_rootdir = False

    # cache
    if cache_dir:
        cache_dir = os.path.abspath(cache_dir)
    else:
        cache_dir = tempfile.mkdtemp(prefix="apport_cache_")
        atexit.register(shutil.rmtree, cache_dir)

    pkgmap_cache_dir = os.path.join(cache_dir, report["DistroRelease"])

    pkgs = []

    # when ProcMaps is available and we don't have any third-party packages, it
    # is enough to get the libraries in it and map their files to packages;
    # otherwise, get Package/Dependencies
    if "ProcMaps" not in report or "[origin" in (
        report.get("Package", "") + report.get("Dependencies", "")
    ):
        pkgs = needed_packages(report)

    if config_dir == "system":
        config_dir = None

    origins = None
    if dynamic_origins:
        pkg_list = f"{report.get('Package', '')}\n{report.get('Dependencies', '')}"
        match = re.compile(r"\[origin: ([a-zA-Z0-9][a-zA-Z0-9\+\.\-]+)\]")
        origins = set(match.findall(pkg_list))
        if origins:
            apport.logging.log(f"Origins: {origins}")

    # Install base-files first to get correct usrmerge
    _move_base_files_first(pkgs)

    # unpack packages, if any, using cache and sandbox
    try:
        outdated_msg = packaging.install_packages(
            sandbox_dir,
            config_dir,
            report["DistroRelease"],
            pkgs,
            verbose,
            cache_dir,
            permanent_rootdir,
            architecture=report.get("Architecture"),
            origins=origins,
        )
    except SystemError as error:
        apport.logging.fatal("%s", str(error))

    # install the extra packages and their deps
    if extra_packages:
        try:
            outdated_msg += packaging.install_packages(
                sandbox_dir,
                config_dir,
                report["DistroRelease"],
                [(p, None) for p in extra_packages],
                verbose,
                cache_dir,
                permanent_rootdir,
                architecture=report.get("Architecture"),
                origins=origins,
                install_dbg=False,
                install_deps=True,
            )
        except SystemError as error:
            apport.logging.fatal("%s", str(error))

    pkg_versions = report_package_versions(report)
    pkgs = needed_runtime_packages(report, pkgmap_cache_dir, pkg_versions, verbose)

    # package hooks might reassign Package:, check that we have the originally
    # crashing binary
    for path in ("InterpreterPath", "ExecutablePath"):
        if path in report:
            pkg = packaging.get_file_package(
                report[path],
                True,
                pkgmap_cache_dir,
                release=report["DistroRelease"],
                arch=report.get("Architecture"),
            )
            # Because of UsrMerge the two systemctl's may share the same
            # location, however since systemd and systemctl conflict we can
            # assume that if the SourcePackage was set to systemd it is
            # correct. For an example see LP: #1872211.
            if pkg == "systemctl":
                if report["SourcePackage"] == "systemd":
                    report["ExecutablePath"] = "/bin/systemctl"
                    pkg = "systemd"
            if pkg:
                apport.logging.log(
                    f"Installing extra package {pkg} to get {path}", log_timestamps
                )
                pkgs.append((pkg, pkg_versions.get(pkg)))
            else:
                apport.logging.fatal(
                    "Cannot find package which ships %s %s", path, report[path]
                )

    # unpack packages for executable using cache and sandbox
    if pkgs:
        try:
            outdated_msg += packaging.install_packages(
                sandbox_dir,
                config_dir,
                report["DistroRelease"],
                pkgs,
                verbose,
                cache_dir,
                permanent_rootdir,
                architecture=report.get("Architecture"),
                origins=origins,
            )
        except SystemError as error:
            apport.logging.fatal("%s", str(error))

    # consistency check: for a packaged binary we require having the executable
    # in the sandbox; TODO: for an unpackage binary we don't currently copy its
    # potential local library dependencies (like those in build trees) into the
    # sandbox, and we call gdb/valgrind on the binary outside the sandbox.
    if "Package" in report:
        for path in ("InterpreterPath", "ExecutablePath"):
            if path in report and not os.path.exists(sandbox_dir + report[path]):
                if report[path].startswith("/usr"):
                    if os.path.exists(sandbox_dir + report[path][4:]):
                        report[path] = report[path][4:]
                    else:
                        apport.logging.fatal(
                            "%s %s does not exist (report specified package %s)",
                            path,
                            sandbox_dir + report[path],
                            report["Package"],
                        )
                else:
                    apport.logging.fatal(
                        "%s %s does not exist (report specified package %s)",
                        path,
                        sandbox_dir + report[path],
                        report["Package"],
                    )

    if outdated_msg:
        report["RetraceOutdatedPackages"] = outdated_msg

    apport.logging.memdbg("built sandbox")

    return sandbox_dir, cache_dir, outdated_msg
