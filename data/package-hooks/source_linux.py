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

    tags = []

    ui.information("As part of the bug reporting process, you'll be asked a series of questions to help provide a more descriptive bug report.  Please answer the following questions to the best of your ability.  Afterwards, a browser will be opened to finish filing this as a bug in the Launchpad bug tracking system.")

    response = ui.yesno("Has this issue been confirmed to exist with the upstream kernel?")
    if response == None: #user cancelled
        raise StopIteration

    if response == False:
        report['TestedUpstream'] = "No"
        tags.append("needs-upstream-testing")
        testupstream = ui.yesno("Testing the upstream kernel can help isolate issues in Ubuntu kernel patches, discover a bug is fixed upstream, or confirm the issue exists upstream.  Would you like to test the upstream kernel first before reporting this bug?")
        if testupstream == True:
            ui.information("For information on testing the upstream kernel, refer to https://wiki.ubuntu.com/KernelTeam/MainlineBuilds")
            raise StopIteration

    elif response == True:
        report['TestedUpstream'] = "Yes"
        ui.information("It can also be beneficial to report this bug upstream at http://bugzilla.kernel.org/ so that the upstream kernel developers are also aware of the issue.")

    response = ui.yesno("A bug is considered a regression if the issue did not exist on a previous kernel.  Is this a regression?")
    if response == None: #user cancelled
        raise StopIteration

    report['Regression'] = "No"
    if response == True:
        report['Regression'] = "Yes"
        regression_tags = ["regression-release", "regression-potential",
            "regression-update", "regression-proposed",
            "regression-potential"]

        # add code to check if running dev release; if so, tag regression-potential and move on.
        regression = ui.choice("How would you describe the regression?",
            ["regression-release - A regression in a new stable release.",
            "regression-potential - A bug discovered in the development release that was not present in the stable release.",
            "regression-update - A regression introduced by an updated package in the stable release.",
            "regression-proposed - A regression introduced by a package in -proposed .",
            "I don't know."], False)

        #Don't Know response defaults to regression-potential
        tags.append(regression_tags[regression[0]])
        ui.information("If possible, when filling out your bug report later on, please note the most recent kernel version where this was not an issue.")

    response = ui.yesno("Can you recreate this bug with a specific series of steps?")

    if response == None: #user cancelled
        raise StopIteration

    if response == True:
        report['Reproducible'] = "Yes"
        ui.information("After apport finishes collection debug information, please document your steps to reproduce the issue when filling out the bug report.")
    elif response == False:
        report['Reproducible'] = "No"
        frequency_options = ["Once a day.",
                    "Once every few days.",
                    "Once a week.",
                    "Once every few weeks.",
                    "Once a month.",
                    "Once every few months.",
                    "This has only happened once."]

        frequency = ui.choice("How often does this issue appear?",
                    frequency_options)
        report['Frequency'] = frequency_options[frequency[0]]

    report.setdefault('Tags', '')
    report['Tags'] += ' ' + ' '.join(tags)

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

