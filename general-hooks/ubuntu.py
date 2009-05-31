'''Attach generally useful information, not specific to any package.

Copyright (C) 2009 Canonical Ltd.
Author: Matt Zimmerman <mdz@canonical.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import apport.packaging
from apport.hookutils import *

def add_info(report):
    # crash reports from live system installer often expose target mount
    for f in ('ExecutablePath', 'InterpreterPath'):
        if f in report and report[f].startswith('/target/'):
            report[f] = report[f][7:]

    # if we are running from a live system, add the build timestamp
    attach_file_if_exists(report, '/cdrom/.disk/info', 'LiveMediaBuild')

	# This includes the Ubuntu packaged kernel version
    attach_file_if_exists(report, '/proc/version_signature', 'ProcVersionSignature')

    package = report.get('Package', '').split()[0]
    if package:
        attach_conffiles(report, package)
