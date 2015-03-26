'''Qt 5 Apport User Interface tests'''

# Copyright (C) 2015 Harald Sitter <sitter@kde.org>
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
try:
    from PyQt5.QtCore import QTimer, QCoreApplication
    from PyQt5.QtGui import QApplication, QTreeWidget, QIcon
except ImportError as e:
    sys.stderr.write('SKIP: PyQt/PyKDE not available: %s\n' % str(e))
    sys.exit(0)

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
        os.environ['APPORT_REPORT_DIR'] = self.report_dir
        # do not cause eternal hangs because of error dialog boxes
        os.environ['APPORT_DISABLE_DISTRO_CHECK'] = '1'

        self.app = MainUserInterface()

        # use in-memory crashdb
        self.app.crashdb = apport.crashdb_impl.memory.CrashDatabase(None, {})

        # disable package hooks, as they might ask for sudo password and other
        # interactive bits; allow tests to install their own hooks
        self.hook_dir = tempfile.mkdtemp()
        apport.report._hook_dir = self.hook_dir
        apport.report._common_hook_dir = self.hook_dir

        # test report
        self.app.report_file = os.path.join(self.report_dir, 'bash.crash')

        self.app.report = apport.Report()
        self.app.report['ExecutablePath'] = '/bin/bash'
        self.app.report['Signal'] = '11'
        self.app.report['CoreDump'] = b'\x01\x02'
        with open(self.app.report_file, 'wb') as f:
            self.app.report.write(f)

    def tearDown(self):
        if self.app.dialog:
            QCoreApplication.processEvents()
            self.app.dialog.done(0)
            QCoreApplication.processEvents()

        shutil.rmtree(self.report_dir)
        shutil.rmtree(self.hook_dir)

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
        self.assertEqual(self.app.dialog.windowTitle(), self.distro.split()[0])
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
        self.assertEqual(self.app.dialog.windowTitle(), self.distro.split()[0])
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

    def test_regular_crash_thread_layout(self):
        '''A thread of execution has failed, but the application persists.'''
        self.app.report['ProblemType'] = 'Crash'
        self.app.report['ProcStatus'] = 'Name:\tupstart\nPid:\t1'
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(True)
        self.assertFalse(self.app.dialog.closed_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _('Continue'))

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
            fp.write(b'''[Desktop Entry]
Version=1.0
Name=Apport
Type=Application''')
            fp.flush()
            self.app.report['DesktopFile'] = fp.name
            QTimer.singleShot(0, QCoreApplication.quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(), self.distro.split()[0])
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
            fp.write(b'''[Desktop Entry]
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
        self.assertEqual(self.app.dialog.windowTitle(), self.distro.split()[0])
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
        self.assertEqual(self.app.dialog.windowTitle(), self.distro.split()[0])
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

    def test_recoverable_crash_layout(self):
        '''
        +-----------------------------------------------------------------+
        | [ logo ] The application Foo has experienced an internal error. |
        |          Developer-specified error text.                        |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |                                                                 |
        | [ Show Details ]                                   [ Continue ] |
        +-----------------------------------------------------------------+
        '''
        self.app.report['ProblemType'] = 'RecoverableProblem'
        self.app.report['Package'] = 'apport 1.2.3~0ubuntu1'
        self.app.report['DialogBody'] = 'Some developer-specified error text.'

        with tempfile.NamedTemporaryFile() as fp:
            fp.write(b'''[Desktop Entry]
Version=1.0
Name=Apport
Type=Application''')
            fp.flush()
            self.app.report['DesktopFile'] = fp.name
            QTimer.singleShot(0, QCoreApplication.quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(),
                         self.distro.split()[0])
        msg = 'The application Apport has experienced an internal error.'
        self.assertEqual(self.app.dialog.heading.text(), msg)
        msg = 'Some developer-specified error text.'
        self.assertEqual(self.app.dialog.text.text(), msg)
        self.assertTrue(self.app.dialog.text.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _('Continue'))
        self.assertFalse(self.app.dialog.closed_button.isVisible())

    @patch.object(MainUserInterface, 'open_url')
    def test_1_crash_nodetails(self, *args):
        '''Crash report without showing details'''

        self.visible_progress = None

        def cont(*args):
            if self.app.dialog and self.app.dialog.continue_button.isVisible():
                self.app.dialog.continue_button.click()
                QTimer.singleShot(200, check_progress)
                return
            # try again
            QTimer.singleShot(1000, cont)

        def check_progress(*args):
            self.visible_progress = (self.app.progress is not None)

        QTimer.singleShot(1000, cont)
        self.app.run_crash(self.app.report_file)

        # we should have reported one crash
        self.assertEqual(self.app.crashdb.latest_id(), 0)
        r = self.app.crashdb.download(0)
        self.assertEqual(r['ProblemType'], 'Crash')
        self.assertEqual(r['ExecutablePath'], '/bin/bash')

        # should show a progress bar for info collection
        self.assertEqual(self.visible_progress, True)

        # data was collected
        self.assertTrue(r['Package'].startswith('bash '))
        self.assertTrue('libc' in r['Dependencies'])
        self.assertTrue('Stacktrace' in r)

        # URL was opened
        self.assertEqual(self.app.open_url.call_count, 1)

    @patch.object(MainUserInterface, 'open_url')
    def test_1_crash_details(self, *args):
        '''Crash report with showing details'''

        self.visible_progress = None

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
                QTimer.singleShot(200, check_progress)
                return
            # try again
            QTimer.singleShot(200, cont)

        def check_progress(*args):
            self.visible_progress = (self.app.progress is not None)

        QTimer.singleShot(200, show_details)
        self.app.run_crash(self.app.report_file)

        # we should have reported one crash
        self.assertEqual(self.app.crashdb.latest_id(), 0)
        r = self.app.crashdb.download(0)
        self.assertEqual(r['ProblemType'], 'Crash')
        self.assertEqual(r['ExecutablePath'], '/bin/bash')

        # we already collected details, do not show the progress dialog again
        self.assertFalse(self.visible_progress)

        # data was collected
        self.assertTrue(r['Package'].startswith('bash '))
        self.assertTrue('libc' in r['Dependencies'])
        self.assertTrue('Stacktrace' in r)

        # URL was opened
        self.assertEqual(self.app.open_url.call_count, 1)

    @patch.object(MainUserInterface, 'open_url')
    def test_1_crash_noaccept(self, *args):
        '''Crash report with non-accepting crash DB'''

        self.visible_progress = None

        def cont(*args):
            if self.app.dialog and self.app.dialog.continue_button.isVisible():
                self.app.dialog.continue_button.click()
                QTimer.singleShot(200, check_progress)
                return
            # try again
            QTimer.singleShot(1000, cont)

        def check_progress(*args):
            self.visible_progress = (self.app.progress is not None)

        QTimer.singleShot(1000, cont)
        self.app.crashdb.options['problem_types'] = ['bug']
        self.app.run_crash(self.app.report_file)

        # we should not have reported the crash
        self.assertEqual(self.app.crashdb.latest_id(), -1)
        self.assertEqual(self.app.open_url.call_count, 0)

        # no progress dialog for non-accepting DB
        self.assertNotEqual(self.visible_progress, True)

        # data was collected for whoopsie
        r = self.app.report
        self.assertEqual(r['ProblemType'], 'Crash')
        self.assertEqual(r['ExecutablePath'], '/bin/bash')
        self.assertTrue(r['Package'].startswith('bash '))
        self.assertTrue('libc' in r['Dependencies'])
        self.assertTrue('Stacktrace' in r)

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

    @patch.object(MainUserInterface, 'open_url')
    def test_1_update_report_different_binary_source(self, *args):
        '''Updating an existing report on a source package which does not have a binary of the same name'''

        self.app.report_file = None

        def cont(*args):
            if self.app.dialog and self.app.dialog.continue_button.isVisible():
                self.app.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(200, cont)

        kernel_pkg = apport.packaging.get_kernel_package()
        kernel_src = apport.packaging.get_source(kernel_pkg)
        self.assertNotEqual(kernel_pkg, kernel_src,
                            'this test assumes that the kernel binary package != kernel source package')
        self.assertNotEqual(apport.packaging.get_version(kernel_pkg), '',
                            'this test assumes that the kernel binary package %s is installed' % kernel_pkg)
        # this test assumes that the kernel source package name is not an
        # installed binary package
        self.assertRaises(ValueError, apport.packaging.get_version, kernel_src)

        # create source package hook, as otherwise there is nothing to collect
        with open(os.path.join(self.hook_dir, 'source_%s.py' % kernel_src), 'w') as f:
            f.write('def add_info(r, ui):\n r["MachineType"]="Laptop"\n')

        # upload empty report
        id = self.app.crashdb.upload({})
        self.assertEqual(id, 0)

        # run in update mode for that bug
        self.app.options.update_report = 0
        self.app.options.package = kernel_src

        QTimer.singleShot(200, cont)
        self.app.run_update_report()

        # no new bug reported
        self.assertEqual(self.app.crashdb.latest_id(), 0)

        # bug was updated
        r = self.app.crashdb.download(0)
        self.assertTrue('ProcEnviron' in r)
        self.assertTrue('DistroRelease' in r)
        self.assertTrue('Uname' in r)
        self.assertEqual(r['MachineType'], 'Laptop')

        # No URL in this mode
        self.assertEqual(self.app.open_url.call_count, 0)

    def test_administrator_disabled_reporting(self):
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(False)
        self.assertFalse(self.app.dialog.send_error_report.isVisible())
        self.assertFalse(self.app.dialog.send_error_report.isChecked())

app = QApplication(sys.argv)
app.applicationName = 'apport-kde'
app.applicationDisplayName = _('Apport')
app.windowIcon = QIcon.fromTheme('apport')

unittest.main()
