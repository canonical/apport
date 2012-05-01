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
import shutil

from mock import patch
from PyQt4.QtCore import QTimer, QCoreApplication
from PyQt4.QtGui import QTreeWidget
from PyKDE4.kdecore import ki18n, KCmdLineArgs, KAboutData, KLocalizedString
from PyKDE4.kdeui import KApplication

import apport
from apport import unicode_gettext as _
import apport.crashdb_impl.memory

if os.environ.get('APPORT_TEST_LOCAL'):
    apport_kde_path = 'kde/apport-kde'
else:
    apport_kde_path = os.path.join(os.environ.get('APPORT_DATA_DIR', '/usr/share/apport'), 'apport-kde')
MainUserInterface = imp.load_source('', apport_kde_path).MainUserInterface

# Work around MainUserInterface using basename to find the KDE UI file.
sys.argv[0] = apport_kde_path


class T(unittest.TestCase):
    @classmethod
    def setUpClass(klass):
        r = apport.Report()
        r.add_os_info()
        klass.distro = r['DistroRelease']

    def setUp(self):
        self.report_dir = tempfile.mkdtemp()
        apport.fileutils.report_dir = self.report_dir

        self.app = MainUserInterface()

        # use in-memory crashdb
        self.app.crashdb = apport.crashdb_impl.memory.CrashDatabase(None, {})

        # test report
        self.app.report_file = os.path.join(self.report_dir, 'bash.crash')

        self.app.report = apport.Report()
        self.app.report['ExecutablePath'] = '/bin/bash'
        self.app.report['Signal'] = '11'
        self.app.report['CoreDump'] = ''
        with open(self.app.report_file, 'wb') as f:
            self.app.report.write(f)

    def tearDown(self):
        if self.app.dialog:
            QCoreApplication.processEvents()
            self.app.dialog.done(0)
            QCoreApplication.processEvents()

        shutil.rmtree(self.report_dir)

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
        | [ logo ] YourDistro has experienced an internal error.          |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |                                                                 |
        | [ Show Details ]                                   [ Continue ] |
        +-----------------------------------------------------------------+
        '''
        self.app.report['ProblemType'] = 'KernelCrash'
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(),
            self.distro.split()[0])
        self.assertEqual(self.app.dialog.heading.text(),
              _('Sorry, %s has experienced an internal error.') % self.distro)
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
        self.app.report['ProblemType'] = 'Package'
        self.app.report['Package'] = 'apport 1.2.3~0ubuntu1'
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(),
            self.distro.split()[0])
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
        |            [ ] Ignore future problems of this program version.  |
        |                                                                 |
        | [ Show Details ]                                   [ Continue ] |
        +-----------------------------------------------------------------+
        '''
        self.app.report['ProblemType'] = 'Crash'
        self.app.report['CrashCounter'] = '1'
        self.app.report['Package'] = 'apport 1.2.3~0ubuntu1'
        with tempfile.NamedTemporaryFile() as fp:
            fp.write('''[Desktop Entry]
Version=1.0
Name=Apport
Type=Application''')
            fp.flush()
            self.app.report['DesktopFile'] = fp.name
            QTimer.singleShot(0, QCoreApplication.quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(),
            self.distro.split()[0])
        self.assertEqual(self.app.dialog.heading.text(),
             _('The application Apport has closed unexpectedly.'))
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        # no ProcCmdline, cannot restart
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _('Continue'))
        self.assertFalse(self.app.dialog.closed_button.isVisible())
        self.assertFalse(self.app.dialog.text.isVisible())
        self.assertFalse(self.app.dialog.text.isVisible())
        self.assertTrue(self.app.dialog.ignore_future_problems.isVisible())
        self.assertTrue(str(self.app.dialog.ignore_future_problems.text()).endswith(
            'of this program version'))

    def test_regular_crash_layout_restart(self):
        '''
        +-----------------------------------------------------------------+
        | [ apport ] The application Apport has closed unexpectedly.      |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |            [ ] Ignore future problems of this program version.  |
        |                                                                 |
        | [ Show Details ]                 [ Leave Closed ]  [ Relaunch ] |
        +-----------------------------------------------------------------+
        '''
        self.app.report['ProblemType'] = 'Crash'
        self.app.report['CrashCounter'] = '1'
        self.app.report['ProcCmdline'] = 'apport-bug apport'
        self.app.report['Package'] = 'apport 1.2.3~0ubuntu1'
        with tempfile.NamedTemporaryFile() as fp:
            fp.write('''[Desktop Entry]
Version=1.0
Name=Apport
Type=Application''')
            fp.flush()
            self.app.report['DesktopFile'] = fp.name
            QTimer.singleShot(0, QCoreApplication.quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(),
            self.distro.split()[0])
        self.assertEqual(self.app.dialog.heading.text(),
             _('The application Apport has closed unexpectedly.'))
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _('Relaunch'))
        self.assertTrue(self.app.dialog.closed_button.isVisible())
        self.assertFalse(self.app.dialog.text.isVisible())
        self.assertFalse(self.app.dialog.text.isVisible())
        self.assertTrue(self.app.dialog.ignore_future_problems.isVisible())
        self.assertTrue(str(self.app.dialog.ignore_future_problems.text()).endswith(
            'of this program version'))

    def test_system_crash_layout(self):
        '''
        +-----------------------------------------------------------------+
        | [ logo ] Sorry, YourDistro has experienced an internal error.   |
        |            If you notice further problems, try restarting the   |
        |            computer                                             |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |            [ ] Ignore future problems of this type.             |
        |                                                                 |
        | [ Show Details ]                                   [ Continue ] |
        +-----------------------------------------------------------------+
        '''
        self.app.report['ProblemType'] = 'Crash'
        self.app.report['CrashCounter'] = '1'
        self.app.report['Package'] = 'apport 1.2.3~0ubuntu1'
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(),
            self.distro.split()[0])
        self.assertEqual(self.app.dialog.heading.text(),
             _('Sorry, %s has experienced an internal error.') % self.distro)
        self.assertEqual(self.app.dialog.text.text(),
             _('If you notice further problems, try restarting the computer.'))
        self.assertTrue(self.app.dialog.text.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _('Continue'))
        self.assertFalse(self.app.dialog.closed_button.isVisible())
        self.assertTrue(self.app.dialog.ignore_future_problems.isVisible())
        self.assertTrue(str(self.app.dialog.ignore_future_problems.text()).endswith(
            'of this type'))

    def test_apport_bug_package_layout(self):
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
        self.assertEqual(self.app.dialog.windowTitle(),
            self.distro.split()[0])
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

    @patch.object(MainUserInterface, 'open_url')
    def test_1_crash_nodetails(self, *args):
        '''Crash report without showing details'''

        def cont(*args):
            if self.app.dialog and self.app.dialog.continue_button.isVisible():
                self.app.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(1000, cont)

        QTimer.singleShot(1000, cont)
        self.app.run_crash(self.app.report_file)

        # we should have reported one crash
        self.assertEqual(self.app.crashdb.latest_id(), 0)
        r = self.app.crashdb.download(0)
        self.assertEqual(r['ProblemType'], 'Crash')
        self.assertEqual(r['ExecutablePath'], '/bin/bash')

        # data was collected
        self.assertTrue(r['Package'].startswith('bash '))
        self.assertTrue('libc' in r['Dependencies'])
        self.assertTrue('Stacktrace' in r)

        # URL was opened
        self.assertEqual(self.app.open_url.call_count, 1)

    @patch.object(MainUserInterface, 'open_url')
    def test_1_crash_details(self, *args):
        '''Crash report with showing details'''

        def show_details(*args):
            if self.app.dialog and self.app.dialog.show_details.isVisible():
                self.app.dialog.show_details.click()
                QTimer.singleShot(1000, cont)
                return

            # try again
            QTimer.singleShot(200, show_details)

        def cont(*args):
            # wait until data collection is done and tree filled
            details = self.app.dialog.findChild(QTreeWidget, 'details')
            if details.topLevelItemCount() == 0:
                QTimer.singleShot(200, cont)
                return

            if self.app.dialog and self.app.dialog.continue_button.isVisible():
                self.app.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(200, cont)

        QTimer.singleShot(200, show_details)
        self.app.run_crash(self.app.report_file)

        # we should have reported one crash
        self.assertEqual(self.app.crashdb.latest_id(), 0)
        r = self.app.crashdb.download(0)
        self.assertEqual(r['ProblemType'], 'Crash')
        self.assertEqual(r['ExecutablePath'], '/bin/bash')

        # data was collected
        self.assertTrue(r['Package'].startswith('bash '))
        self.assertTrue('libc' in r['Dependencies'])
        self.assertTrue('Stacktrace' in r)

        # URL was opened
        self.assertEqual(self.app.open_url.call_count, 1)

    def test_bug_report_installed_package(self):
        '''Bug report for installed package'''

        self.app.report_file = None
        self.app.options.package = 'bash'

        def c(*args):
            if self.app.dialog and self.app.dialog.cancel_button.isVisible():
                self.app.dialog.cancel_button.click()
                return
            # try again
            QTimer.singleShot(1000, c)

        QTimer.singleShot(1000, c)
        self.app.run_report_bug()

        self.assertEqual(self.app.report['ProblemType'], 'Bug')
        self.assertEqual(self.app.report['SourcePackage'], 'bash')
        self.assertTrue(self.app.report['Package'].startswith('bash '))
        self.assertNotEqual(self.app.report['Dependencies'], '')

    def test_bug_report_uninstalled_package(self):
        '''Bug report for uninstalled package'''

        pkg = apport.packaging.get_uninstalled_package()

        self.app.report_file = None
        self.app.options.package = pkg

        def c(*args):
            if self.app.dialog and self.app.dialog.cancel_button.isVisible():
                self.app.dialog.cancel_button.click()
                return
            # try again
            QTimer.singleShot(1000, c)

        QTimer.singleShot(1000, c)
        self.app.run_report_bug()

        self.assertEqual(self.app.report['ProblemType'], 'Bug')
        self.assertEqual(self.app.report['SourcePackage'],
                apport.packaging.get_source(pkg))
        self.assertEqual(self.app.report['Package'], '%s (not installed)' % pkg)

    @patch.object(MainUserInterface, 'open_url')
    def test_1_update_report(self, *args):
        '''Updating an existing report'''

        self.app.report_file = None

        def cont(*args):
            if self.app.dialog and self.app.dialog.continue_button.isVisible():
                self.app.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(200, cont)

        # upload empty report
        id = self.app.crashdb.upload({})
        self.assertEqual(id, 0)
        self.app.options.update_report = 0
        self.app.options.package = 'bash'

        QTimer.singleShot(200, cont)
        self.app.run_update_report()

        # no new bug reported
        self.assertEqual(self.app.crashdb.latest_id(), 0)

        # bug was updated
        r = self.app.crashdb.download(0)
        self.assertTrue(r['Package'].startswith('bash '))
        self.assertTrue('libc' in r['Dependencies'])
        self.assertTrue('DistroRelease' in r)

        # No URL in this mode
        self.assertEqual(self.app.open_url.call_count, 0)

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
