'''Functions to manage sandboxes'''

# Copyright (C) 2006 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#         Kyle Nitzsche <kyle.nitzsche@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import atexit, os, os.path, shutil, sys, tempfile
import apport


def needed_packages(report):
    '''Determine necessary packages for given report.

    Return list of (pkgname, version) pairs. version might be None for unknown
    package versions.
    '''
    pkgs = {}

    # first, grab the versions that we captured at crash time
    for l in (report['Package'] + '\n' + report.get('Dependencies', '')).splitlines():
        if not l.strip():
            continue
        try:
            (pkg, version) = l.split()[:2]
        except ValueError:
            apport.warning('invalid Package/Dependencies line: %s', l)
            # invalid line, ignore
            continue
        pkgs[pkg] = version

    return [(p, v) for (p, v) in pkgs.items()]


def needed_runtime_packages(report, sandbox, cache_dir, verbose=False):
    '''Determine necessary runtime packages for given report.

    This determines libraries dynamically loaded at runtime and
    supports four use cases:

    1. The executable is packaged and already ran (apport-retrace only)
    2. The executable is packaged and has not yet run (apport-valgrind only)
    3. The executable is unpackaged and already ran (theoretical only, no
    use case)
    4. The executable is unpackaged and has not yet run (apport-valgrind)

    Two report keys are used to select the code path appropriate for the
    particular use case:

    1. report['Procmaps']: this only exists when the executable has already
    run and therefore is applicable to apport-retrace only. When this key is
    present, its value contains data from /proc/pid/maps, which shows the
    shared libraries.

    2. report['Packaged']: this only exists when the executable is installed
    by a package. This case applies to both apport-retrace and apport
    valgrind. However, when the key does not exist, it (probably) only applies
    to apport-valgrind. The idea is to support running apport-valgrind on
    unpackaged executables. In this case, shared libraries are determined from
    shared_libraries(), which uses ldd on the executable.

    The package for each shared lib is obtained from get_file_package().

    Return list of (pkgname, None) pairs.

    When cache_dir is specified, it is used as a cache for get_file_package().
    '''
    # check list of libraries that the crashed process referenced at
    # runtime and warn about those which are not available
    pkgs = set()
    libs = set()
    if 'ProcMaps' in report:
        for l in report['ProcMaps'].splitlines():
            if not l.strip():
                continue
            cols = l.split()
            if len(cols) == 6 and 'x' in cols[1] and '.so' in cols[5]:
                lib = os.path.realpath(cols[5])
                libs.add(lib)
    try:
        report['Packaged']
    except KeyError:
        # 'Packaged' key is absent on unpackaged executables
        libs = apport.fileutils.shared_libraries(report['ExecutablePath'])
        for l in libs:
            libs.add(l.encode('utf8'))

    if sandbox:
        cache_dir = os.path.join(cache_dir, report['DistroRelease'])

    # grab as much as we can
    for l in libs:
        if os.path.exists(sandbox + l):
            continue

        pkg = apport.packaging.get_file_package(l, True, cache_dir,
                                                exact_match=False,
                                                arch=report.get('Architecture'))
        if pkg:
            if verbose:
                apport.log('dynamically loaded %s needs package %s, queueing' % (l, pkg))
            pkgs.add(pkg)
        else:
                apport.warning('%s is needed, but cannot be mapped to a package', l)

    return [(p, None) for p in pkgs]


def make_sandbox(report, config_dir, cache_dir=None, sandbox_dir=None,
                 extra_packages=[], verbose=False, log_timestamps=False):
    '''Build a sandbox with the packages that belong to a particular report
    and for the executable.

    This downloads and unpacks all packages from the report's Package and
    Dependencies fields, plus all packages that ship the files from ProcMaps
    (often, runtime plugins do not appear in Dependencies), plus optionally
    some extra ones, for the distro release and architecture of the report.

    For unpackaged executables, there are no Dependencies. Packages for shared
    libaries are unpacked.

    report is an apport.Report object to build a sandbox for. Presence of the
    Package field determines whether to determine dependencies through
    packaging (vai the optional report['Dependencies'] field), or through ldd
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
    are not derived from the report.

    If verbose is True (False by default), this will write some additional
    logging to stdout. If log_timestamps is True, these log messages will be
    prefixed with the current time.

    Return a tuple (sandbox_dir, cache_dir, outdated_msg).
    '''
    # sandbox
    if sandbox_dir:
        sandbox_dir = os.path.abspath(sandbox_dir)
        if not os.path.isdir(sandbox_dir):
            os.makedirs(sandbox_dir)
        permanent_rootdir = True
    else:
        sandbox_dir = tempfile.mkdtemp(prefix='apport_sandbox_')
        atexit.register(shutil.rmtree, sandbox_dir)
        permanent_rootdir = False

    # cache
    if cache_dir:
        cache_dir = os.path.abspath(cache_dir)
    else:
        cache_dir = tempfile.mkdtemp(prefix='apport_cache_')
        atexit.register(shutil.rmtree, cache_dir)

    # get dependencies of packaged executable, if any
    try:
        report['Package']
        pkgs = needed_packages(report)
    except KeyError:
        # Package key does not exist in case of unpackaged exectutable, so
        # simply create the pkgs var
        pkgs = []

    for p in extra_packages:
        pkgs.append((p, None))
    if config_dir == 'system':
        config_dir = None

    # unpack dependencies of packaged executable using cache and sandbox
    try:
        outdated_msg = apport.packaging.install_packages(
            sandbox_dir, config_dir, report['DistroRelease'], pkgs,
            verbose, cache_dir, permanent_rootdir,
            architecture=report.get('Architecture'))
    except SystemError as e:
        sys.stderr.write(str(e) + '\n')
        sys.exit(1)

    # get packages for executable (packaged or not)
    pkgs = needed_runtime_packages(report, sandbox_dir, cache_dir, verbose)

    # package hooks might reassign Package:, check that we have the originally
    # crashing binary
    for path in ('InterpreterPath', 'ExecutablePath'):
        if path in report and not os.path.exists(sandbox_dir + report[path]):
            pkg = apport.packaging.get_file_package(report[path], True, cache_dir,
                                                    arch=report.get('Architecture'))
            if pkg:
                apport.log('Installing extra package %s to get %s' % (pkg, path), log_timestamps)
                pkgs.append((pkg, None))
            else:
                apport.warning('Cannot find package which ships %s', path)

    # unpack packages for executable using cache and sandbox
    if pkgs:
        try:
            outdated_msg += apport.packaging.install_packages(
                sandbox_dir, config_dir, report['DistroRelease'], pkgs,
                cache_dir=cache_dir, architecture=report.get('Architecture'))
        except SystemError as e:
            sys.stderr.write(str(e) + '\n')
            sys.exit(1)
    try:
        # This test for the executable being in the sandbox is not valid for
        # unpackaged executables, so do not run on KeyError
        for path in ('InterpreterPath', 'ExecutablePath'):
            if path in report and not os.path.exists(sandbox_dir + report[path]):
                apport.error('%s %s does not exist (report specified package %s)',
                             path, sandbox_dir + report[path], report['Package'])
                sys.exit(0)
    except KeyError:
        pass

    if outdated_msg:
        report['RetraceOutdatedPackages'] = outdated_msg

    apport.memdbg('built sandbox')

    return sandbox_dir, cache_dir, outdated_msg
