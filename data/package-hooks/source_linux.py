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

SUBMIT_SCRIPT = "/usr/bin/kerneloops-submit"

def add_info(report, ui):
	attach_hardware(report)
	attach_alsa(report)
	attach_wifi(report)

	attach_file_if_exists(report, "/etc/initramfs-tools/conf.d/resume",
                          key="HibernationDevice")

	version_signature = report.get('ProcVersionSignature', '')
	if not version_signature.startswith('Ubuntu '):
		report['UnreportableReason'] = _('The running kernel is not an Ubuntu kernel')
		return

	uname_release = os.uname()[2]
	lrm_package_name = 'linux-restricted-modules-%s' % uname_release
	lbm_package_name = 'linux-backports-modules-%s' % uname_release

	attach_related_packages(report, [lrm_package_name, lbm_package_name, 'linux-firmware'])

	if ('Failure' in report and report['Failure'] == 'oops'
			and 'OopsText' in report and os.path.exists(SUBMIT_SCRIPT)):
		#it's from kerneloops, ask the user whether to submit there as well
		if ui is not None:
			if ui.yesno("This report may also be submitted to "
				"http://kerneloops.org/ in order to help collect aggregate "
				"information about kernel problems. This aids in identifying "
				"widespread issues and problematic areas. Would you like to "
				"submit information about this crash there?"):
				text = report['OopsText']
				proc = subprocess.Popen(SUBMIT_SCRIPT,
					stdin=subprocess.PIPE)
				proc.communicate(text)

if __name__ == '__main__':
	report = {}
	add_info(report, None)
	for key in report:
		print '%s: %s' % (key, report[key].split('\n', 1)[0])
