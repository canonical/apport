'''Attach generally useful information, not specific to any package.

Copyright (C) 2009 Canonical Ltd.
Author: Matt Zimmerman <mdz@canonical.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

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
    xsession_errors_path = os.path.join(home, '.xsession-errors')
    if os.path.exists(xsession_errors_path) and 'ExecutablePath' in report:
        libs = apport.hookutils.command_output(['ldd', report['ExecutablePath']])
        if 'libgtk' in libs and 'libX11' in libs:
            xsession_errors = ''
            filter = re.compile('^(\(.*:\d+\): \w+-(WARNING|CRITICAL|ERROR))|(Error: .*No Symbols named)')
            for line in open(xsession_errors_path):
                if filter.match(line):
                    xsession_errors += line
            if xsession_errors:
                report['XsessionErrors'] = xsession_errors

if __name__ == '__main__':
    r = {}
    add_info(r)
    for k in r:
        print k, ':', r[k]
