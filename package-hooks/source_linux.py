'''Apport package hook for the Linux kernel.

(c) 2008 Canonical Ltd.
Contributors:
Matt Zimmerman <mdz@canonical.com>
Martin Pitt <martin.pitt@canonical.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import os
import subprocess
from apport.hookutils import *

def add_info(report):
	attach_hardware(report)

	attach_file_if_exists(report, "/etc/initramfs-tools/conf.d/resume",
                          key="HibernationDevice")

	version_signature = report.get('ProcVersionSignature', '')
	if not version_signature.startswith('Ubuntu '):
		report['UnreportableReason'] = _('The running kernel is not an Ubuntu kernel')

if __name__ == '__main__':
	report = {}
	add_info(report)
	for key in report:
		print '%s: %s' % (key, report[key].split('\n', 1)[0])
