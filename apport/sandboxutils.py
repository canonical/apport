'''Functions to manage sandboxes'''

# Copyright (C) 2006 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import atexit, os, os.path, shutil, sys, tempfile
import apport, apport.fileutils
from apport.packaging_impl import impl as packaging

try:
    from configparser import ConfigParser, NoOptionError, NoSectionError
    (ConfigParser, NoOptionError, NoSectionError)  # pyflakes
except ImportError:
    # Python 2
    from ConfigParser import ConfigParser, NoOptionError, NoSectionError

def log(message, log_timestamps=None):
    '''Log the given string to stdout. Prepend timestamp if requested'''

    if log_timestamps:
        sys.stdout.write('%s: ' % time.strftime('%x %X'))
    print(message)


def needed_packages(report):
    '''Determine necessary packages for given report.

    Return list of (pkgname, version) pairs. version might be None for unknown
    package versions.
    '''
    pkgs = {}

    # first, grab the versions that we captured at crash time
    for l in (report['Package'] + '\n' + report.get('Dependencies',
'')).splitlines():
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

    This determines libraries which were dynamically loaded at runtime, i. e.
    appear in /proc/pid/maps, but not in Dependencies: (such as plugins).

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

    if sandbox:
        cache_dir = os.path.join(cache_dir, report['DistroRelease'])

    # grab as much as we can
    for l in libs:
        if os.path.exists(sandbox + l):
            continue

        pkg = apport.packaging.get_file_package(l, True, cache_dir)
        if pkg:
            if verbose:
                log('dynamically loaded %s needs package %s, queueing' % (l,
pkg))
            pkgs.add(pkg)
        else:
                apport.warning('%s is needed, but cannot be mapped to a package', l)

    return [(p, None) for p in pkgs]


def make_sandbox(sandbox, sandbox_dir, cache, verbose, report, extra_package=[], log_timestamps=None):

    if sandbox:
        if sandbox_dir:
            sbox = os.path.abspath(sandbox_dir)
            if not os.path.isdir(sbox):
                os.makedirs(sbox)
            permanent_rootdir = True
        else:
            sbox = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, sbox)
            permanent_rootdir = False

        pkgs = needed_packages(report)
        for p in extra_package:
            pkgs.append((p, None))
        if sandbox == 'system':
            sandbox_arg = None
        else:
            sandbox_arg = sandbox

        # we call install_packages() multiple times, plus get_file_package(); use
        # a
        # shared cache dir for these
        if cache:
            cache = os.path.abspath(cache)
        else:
            cache = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, cache)

        try:
            outdated_msg = apport.packaging.install_packages(
                sbox, sandbox_arg, report['DistroRelease'], pkgs,
                verbose, cache, permanent_rootdir)
        except SystemError as e:
            sys.stderr.write(str(e) + '\n')
            sys.exit(1)

        pkgs = needed_runtime_packages(report, sbox, cache, verbose)

        # package hooks might reassign Package:, check that we have the originally
        # crashing binary
        for path in ('InterpreterPath', 'ExecutablePath'):
            if path in report and not os.path.exists(sbox + report[path]):
                pkg = apport.packaging.get_file_package(report[path], True, cache)
                if pkg:
                    log('Installing extra package %s to get %s' % (pkg, path))
                    pkgs.append((pkg, None))
                else:
                    apport.warning('Cannot find package which ships %s', path)

        if pkgs:
            try:
                outdated_msg += apport.packaging.install_packages(
                    sbox, sandbox_arg, report['DistroRelease'], pkgs,
                    cache)
            except SystemError as e:
                sys.stderr.write(str(e) + '\n')
                sys.exit(1)

        for path in ('InterpreterPath', 'ExecutablePath'):
            if path in report and not os.path.exists(sbox + report[path]):
                apport.error('%s %s does not exist (report specified package %s)',
                             path, sbox + report[path], report['Package'])
                sys.exit(0)

        if outdated_msg:
            report['RetraceOutdatedPackages'] = outdated_msg

        apport.memdbg('built sandbox')

    return sbox, outdated_msg

