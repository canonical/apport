'''KDE 4 Apport User Interface tests'''

# Copyright (C) 2012 Canonical Ltd.
# Author: Evan Dandrea <evan.dandrea@canonical.com>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.
import imp
import unittest
import tempfile
import sys
import os

from PyQt4.QtCore import QTimer, QCoreApplication
from PyKDE4.kdecore import ki18n, KCmdLineArgs, KAboutData, KLocalizedString
from PyKDE4.kdeui import KApplication

import apport
from apport import unicode_gettext as _

if os.environ.get('APPORT_TEST_LOCAL'):
    path = 'kde/apport-kde'
else:
    path = os.path.join(os.environ.get('APPORT_DATA_DIR','/usr/share/apport'), 'apport-kde')
MainUserInterface = imp.load_source('', path).MainUserInterface

# Work around MainUserInterface using basename to find the KDE UI file.
sys.argv[0] = 'kde/foo'

class T(unittest.TestCase):
    def setUp(self):
        self.report = apport.Report()
        self.app = MainUserInterface()
        self.app.report = self.report
        self.app.report_file = '/var/crash/fake.crash'

    def test_close_button(self):
        '''Clicking the close button on the window does not report the crash.'''

        def c(*args):
            self.app.dialog.reject()
        QTimer.singleShot(0, c)
        result = self.app.ui_present_report_details(True)
        self.assertFalse(result['report'])

    def test_kernel_crash_layout(self):
        '''
        +-----------------------------------------------------------------+
        | [ ubuntu ] Ubuntu has restarted after experiencing an internal  |
        |            error.                                               |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |                                                                 |
        | [ Show Details ]                                   [ Continue ] |
        +-----------------------------------------------------------------+
        '''
        self.report['ProblemType'] = 'KernelCrash'
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.heading.text(),
             _('Ubuntu has restarted after experiencing an internal error.'))
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _('Continue'))
        self.assertFalse(self.app.dialog.closed_button.isVisible())
        self.assertFalse(self.app.dialog.text.isVisible())

    def test_package_crash_layout(self):
        '''
        +-----------------------------------------------------------------+
        | [ error  ] Sorry, a problem occurred while installing software. |
        |            Package: apport 1.2.3~0ubuntu1                       |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |                                                                 |
        | [ Show Details ]                                   [ Continue ] |
        +-----------------------------------------------------------------+
        '''
        self.report['ProblemType'] = 'Package'
        self.report['Package'] = 'apport 1.2.3~0ubuntu1'
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.heading.text(),
             _('Sorry, a problem occurred while installing software.'))
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _('Continue'))
        self.assertFalse(self.app.dialog.closed_button.isVisible())
        self.assertEqual(self.app.dialog.text.text(),
            _('Package: apport 1.2.3~0ubuntu1'))

    def test_regular_crash_layout(self):
        '''
        +-----------------------------------------------------------------+
        | [ apport ] The application Apport has closed unexpectedly.      |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |                                                                 |
        | [ Show Details ]                 [ Leave Closed ]  [ Relaunch ] |
        +-----------------------------------------------------------------+
        '''
        self.report['ProblemType'] = 'Crash'
        self.report['Package'] = 'apport 1.2.3~0ubuntu1'
        with tempfile.NamedTemporaryFile() as fp:
            fp.write('''[Desktop Entry]
Version=1.0
Name=Apport
Type=Application''')
            fp.flush()
            self.report['DesktopFile'] = fp.name
            QTimer.singleShot(0, QCoreApplication.quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.heading.text(),
             _('The application Apport has closed unexpectedly.'))
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _('Relaunch'))
        self.assertTrue(self.app.dialog.closed_button.isVisible())
        self.assertFalse(self.app.dialog.text.isVisible())

    def test_system_crash_layout(self):
        '''
        +-----------------------------------------------------------------+
        | [ ubuntu ] Sorry, Ubuntu has experienced an internal error.     |
        |            If you notice further problems, try restarting the   |
        |            computer                                             |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |                                                                 |
        | [ Show Details ]                                   [ Continue ] |
        +-----------------------------------------------------------------+
        '''
        self.report['ProblemType'] = 'Crash'
        self.report['Package'] = 'apport 1.2.3~0ubuntu1'
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.heading.text(),
             _('Sorry, Ubuntu has experienced an internal error.'))
        self.assertEqual(self.app.dialog.text.text(),
             _('If you notice further problems, try restarting the computer.'))
        self.assertTrue(self.app.dialog.text.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _('Continue'))
        self.assertFalse(self.app.dialog.closed_button.isVisible())

    def test_apport_bug_package(self):
        '''
        +-------------------------------------------------------------------+
        | [ error  ] Send problem report to the developers?                 |
        |                                                                   |
        |            +----------------------------------------------------+ |
        |            | |> ApportVersion                                   | |
        |            | ...                                                | |
        |            +----------------------------------------------------+ |
        |                                                                   |
        | [ Cancel ]                                               [ Send ] |
        +-------------------------------------------------------------------+
        '''
        self.app.report_file = None
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.heading.text(),
             _('Send problem report to the developers?'))
        self.assertFalse(self.app.dialog.text.isVisible())
        self.assertFalse(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertFalse(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _('Send'))
        self.assertFalse(self.app.dialog.closed_button.isVisible())
        self.assertTrue(self.app.dialog.cancel_button.isVisible())
        self.assertTrue(self.app.dialog.treeview.isVisible())

    def test_administrator_disabled_reporting(self):
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(False)
        self.assertFalse(self.app.dialog.send_error_report.isVisible())
        self.assertFalse(self.app.dialog.send_error_report.isChecked())

appName = 'apport-kde'
catalog = 'apport'
programName = ki18n('Apport KDE')
version = '1.0'
description = ki18n('KDE 4 frontend tests for the apport')
license = KAboutData.License_GPL
copyright = ki18n('2012 Canonical Ltd.')
text = KLocalizedString()
homePage = 'https://wiki.ubuntu.com/AutomatedProblemReports'
bugEmail = 'kubuntu-devel@lists.ubuntu.com'

aboutData = KAboutData(appName, catalog, programName, version, description,
                       license, copyright, text, homePage, bugEmail)

KCmdLineArgs.init([''], aboutData)
app = KApplication()
unittest.main()
