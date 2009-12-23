'''Attach generally useful information, not specific to any package.'''

# Copyright (C) 2009 Canonical Ltd.
# Authors: Matt Zimmerman <mdz@canonical.com>
#          Martin Pitt <martin.pitt@ubuntu.com>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import os, re
import apport.hookutils

def add_info(report):
    nm = apport.hookutils.nonfree_kernel_modules()
    if nm:
        report['NonfreeKernelModules'] = ' '.join(nm)

    # check for low space
    mounts = { '/': 'system' }
    home = os.getenv('HOME')
    if home:
        mounts[home] = 'home'
    treshold = 10

    for mount in mounts:
        st = os.statvfs(mount)
        free_mb = st.f_bavail * st.f_frsize / 1000000

        if free_mb < treshold:
            report['UnreportableReason'] = 'Your %s partition has less than \
%s MB of free space available, which leads to a lot of problems. Please \
free some space.' % (mounts[mount], free_mb)

    # important glib errors/assertions (which should not have private data)
    if 'ExecutablePath' in report:
        path = report['ExecutablePath']
        if (apport.hookutils.links_with_shared_library(path, 'libgtk') or
            apport.hookutils.links_with_shared_library(path, 'libX11')):

            pattern = re.compile('^(\(.*:\d+\): \w+-(WARNING|CRITICAL|ERROR))|(Error: .*No Symbols named)')
            xsession_errors = apport.hookutils.xsession_errors(pattern)
            if xsession_errors:
                report['XsessionErrors'] = xsession_errors

    # using ecryptfs?
    if os.path.exists(os.path.expanduser('~/.ecryptfs/wrapped-passphrase')):
        report['EcryptfsInUse'] = 'Yes'

if __name__ == '__main__':
    r = {}
    add_info(r)
    for k in r:
        print k, ':', r[k]
