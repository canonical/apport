'''Various utility functions to handle apport problem reports.

Copyright (C) 2006 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import subprocess, os, os.path, glob

def find_package_desktopfile(package):
    '''If given package is installed and has a single .desktop file, return the
    path to it, otherwise return None.'''

    dpkg = subprocess.Popen(['dpkg', '-L', package], stdout=subprocess.PIPE,
	stderr=subprocess.PIPE)
    out = dpkg.communicate(input)[0]
    if dpkg.returncode != 0:
	return None

    desktopfile = None

    for line in out.splitlines():
	if line.endswith('.desktop'):
	    if desktopfile:
		return None # more than one
	    else:
		desktopfile = line

    return desktopfile

def get_new_reports():
    '''Return a list with all report files which have not yet been processed
    and are accessible to the calling user.'''

    return [r for r in glob.glob('/var/crash/*.crash') 
	    if os.path.getsize(r) > 0 and os.access(r, os.R_OK)]

def delete_report(report):
    '''Delete the given report file.

    This will not actually unlink the file, since /var/crash is not writable to
    normal users; instead, the file will be truncated to 0 bytes.'''

    open(report, 'w').truncate(0)

