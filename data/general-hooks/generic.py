'''Attach generally useful information, not specific to any package.

Copyright (C) 2009 Canonical Ltd.
Author: Matt Zimmerman <mdz@canonical.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import apport.hookutils
import os

def add_info(report):
    nm = apport.hookutils.nonfree_kernel_modules()
    if nm:
        report['NonfreeKernelModules'] = ' '.join(nm)

    # check for low space
    mounts = { '/': 'system', '/home': '/home' }
    treshold = 10

    for mount in mounts:
        st = os.statvfs(mount)
        free_mb = st.f_bavail * st.f_frsize / 1000000

        if free_mb < treshold:
            report['UnreportableReason'] = 'Your %s partition has less than \
%s MB of free space available, which leads to a lot of problems. Please \
free some space.' % (mounts[mount], free_mb)
