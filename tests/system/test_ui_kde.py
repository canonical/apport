"""Qt 5 Apport User Interface tests"""

# Copyright (C) 2015 Harald Sitter <sitter@kde.org>
# Copyright (C) 2012 Canonical Ltd.
# Author: Evan Dandrea <evan.dandrea@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.
import os
import shutil
import tempfile
import textwrap
import unittest
import unittest.mock

try:
    from PyQt5.QtCore import QCoreApplication, QTimer
    from PyQt5.QtGui import QIcon
    from PyQt5.QtWidgets import QApplication, QTreeWidget

    PYQT5_IMPORT_ERROR = None
except ImportError as error:
    PYQT5_IMPORT_ERROR = error

import apport.crashdb_impl.memory
import apport.report
from apport import unicode_gettext as _
from tests.helper import import_module_from_file, wrap_object
from tests.paths import is_local_source_directory, local_test_environment

if is_local_source_directory():
    apport_kde_path = "kde/apport-kde"
else:
    apport_kde_path = os.path.join(
        os.environ.get("APPORT_DATA_DIR", "/usr/share/apport"), "apport-kde"
    )
if not PYQT5_IMPORT_ERROR:
    apport_kde = import_module_from_file(apport_kde_path)
    MainUserInterface = apport_kde.MainUserInterface
else:
    MainUserInterface = None


@unittest.skipIf(
    PYQT5_IMPORT_ERROR, f"PyQt/PyKDE not available: {PYQT5_IMPORT_ERROR}"
)
class T(unittest.TestCase):
    COLLECTING_DIALOG = unittest.mock.call(
        os.path.dirname(apport_kde_path),
        "Collecting Problem Information",
        "Collecting problem information",
        "The collected information can be sent to the developers to improve "
        "the application. This might take a few minutes.",
    )
    UPLOADING_DIALOG = unittest.mock.call(
        os.path.dirname(apport_kde_path),
        "Uploading Problem Information",
        "Uploading problem information",
        "The collected information is being sent to the bug tracking system. "
        "This might take a few minutes.",
    )

    @classmethod
    def setUpClass(cls):
        cls.orig_environ = os.environ.copy()
        os.environ |= local_test_environment()
        os.environ["LANGUAGE"] = "C"

        cls.argv = [apport_kde_path]
        cls.app = QApplication(cls.argv)
        cls.app.applicationName = "apport-kde"
        cls.app.applicationDisplayName = _("Apport")
        cls.app.windowIcon = QIcon.fromTheme("apport")

        r = apport.report.Report()
        r.add_os_info()
        cls.distro = r["DistroRelease"]

    @classmethod
    def tearDownClass(cls):
        os.environ.clear()
        os.environ.update(cls.orig_environ)

    def setUp(self):
        self.report_dir = tempfile.mkdtemp()
        apport.fileutils.report_dir = self.report_dir
        os.environ["APPORT_REPORT_DIR"] = self.report_dir
        # do not cause eternal hangs because of error dialog boxes
        os.environ["APPORT_IGNORE_OBSOLETE_PACKAGES"] = "1"
        os.environ["APPORT_DISABLE_DISTRO_CHECK"] = "1"

        self.app = MainUserInterface(self.argv)
        # use in-memory crashdb
        self.app.crashdb = apport.crashdb_impl.memory.CrashDatabase(None, {})

        # disable package hooks, as they might ask for sudo password and other
        # interactive bits; allow tests to install their own hooks
        self.hook_dir = tempfile.mkdtemp()
        apport.report.GENERAL_HOOK_DIR = self.hook_dir
        apport.report.PACKAGE_HOOK_DIR = self.hook_dir

        # test report
        self.app.report_file = os.path.join(self.report_dir, "bash.crash")

        self.app.report = apport.report.Report()
        self.app.report["ExecutablePath"] = "/bin/bash"
        self.app.report["Signal"] = "11"
        self.app.report["CoreDump"] = b"\x01\x02"
        with open(self.app.report_file, "wb") as f:
            self.app.report.write(f)

    def tearDown(self):
        if self.app.dialog:
            QCoreApplication.processEvents()
            self.app.dialog.done(0)
            QCoreApplication.processEvents()

        shutil.rmtree(self.report_dir)
        shutil.rmtree(self.hook_dir)

    def test_close_button(self):
        """Clicking the close button on the window does not report the
        crash."""

        def c():
            self.app.dialog.reject()

        QTimer.singleShot(0, c)
        result = self.app.ui_present_report_details(True)
        self.assertFalse(result["report"])

    def test_kernel_crash_layout(self):
        """Display crash dialog for kernel crash.

        +-----------------------------------------------------------------+
        | [ logo ] YourDistro has experienced an internal error.          |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |                                                                 |
        | [ Show Details ]                                   [ Continue ] |
        +-----------------------------------------------------------------+
        """
        self.app.report["ProblemType"] = "KernelCrash"
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(), self.distro.split()[0])
        self.assertEqual(
            self.app.dialog.heading.text(),
            _("Sorry, %s has experienced an internal error.") % self.distro,
        )
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _("Continue"))
        self.assertFalse(self.app.dialog.closed_button.isVisible())
        self.assertFalse(self.app.dialog.text.isVisible())

    def test_package_crash_layout(self):
        """Display crash dialog for a failed package installation.

        +-----------------------------------------------------------------+
        | [ error  ] Sorry, a problem occurred while installing software. |
        |            Package: apport 1.2.3~0ubuntu1                       |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |                                                                 |
        | [ Show Details ]                                   [ Continue ] |
        +-----------------------------------------------------------------+
        """
        self.app.report["ProblemType"] = "Package"
        self.app.report["Package"] = "apport 1.2.3~0ubuntu1"
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(), self.distro.split()[0])
        self.assertEqual(
            self.app.dialog.heading.text(),
            _("Sorry, a problem occurred while installing software."),
        )
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _("Continue"))
        self.assertFalse(self.app.dialog.closed_button.isVisible())
        self.assertEqual(
            self.app.dialog.text.text(), _("Package: apport 1.2.3~0ubuntu1")
        )

    def test_regular_crash_thread_layout(self):
        """A thread of execution has failed, but the application persists."""
        self.app.report["ProblemType"] = "Crash"
        self.app.report["ProcStatus"] = "Name:\tupstart\nPid:\t1"
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(True)
        self.assertFalse(self.app.dialog.closed_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _("Continue"))

    def test_regular_crash_layout(self):
        """Display crash dialog for an application crash.

        +-----------------------------------------------------------------+
        | [ apport ] The application Apport has closed unexpectedly.      |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |            [ ] Ignore future problems of this program version.  |
        |                                                                 |
        | [ Show Details ]                                   [ Continue ] |
        +-----------------------------------------------------------------+
        """
        self.app.report["ProblemType"] = "Crash"
        self.app.report["CrashCounter"] = "1"
        self.app.report["Package"] = "apport 1.2.3~0ubuntu1"
        with tempfile.NamedTemporaryFile(mode="w+") as fp:
            fp.write(
                textwrap.dedent(
                    """\
                    [Desktop Entry]
                    Version=1.0
                    Name=Apport
                    Type=Application
                    """
                )
            )
            fp.flush()
            self.app.report["DesktopFile"] = fp.name
            QTimer.singleShot(0, QCoreApplication.quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(), self.distro.split()[0])
        self.assertEqual(
            self.app.dialog.heading.text(),
            _("The application Apport has closed unexpectedly."),
        )
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        # no ProcCmdline, cannot restart
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _("Continue"))
        self.assertFalse(self.app.dialog.closed_button.isVisible())
        self.assertFalse(self.app.dialog.text.isVisible())
        self.assertFalse(self.app.dialog.text.isVisible())
        self.assertTrue(self.app.dialog.ignore_future_problems.isVisible())
        self.assertTrue(
            str(self.app.dialog.ignore_future_problems.text()).endswith(
                "of this program version"
            )
        )

    def test_regular_crash_layout_restart(self):
        """Display crash dialog for an application crash offering a restart.

        +-----------------------------------------------------------------+
        | [ apport ] The application Apport has closed unexpectedly.      |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |            [ ] Ignore future problems of this program version.  |
        |                                                                 |
        | [ Show Details ]                 [ Leave Closed ]  [ Relaunch ] |
        +-----------------------------------------------------------------+
        """
        # pretend we got called through run_crashes() which sets offer_restart
        self.app.offer_restart = True
        self.app.report["ProblemType"] = "Crash"
        self.app.report["CrashCounter"] = "1"
        self.app.report["ProcCmdline"] = "apport-bug apport"
        self.app.report["Package"] = "apport 1.2.3~0ubuntu1"
        with tempfile.NamedTemporaryFile(mode="w+") as fp:
            fp.write(
                textwrap.dedent(
                    """\
                    [Desktop Entry]
                    Version=1.0
                    Name=Apport
                    Type=Application
                    """
                )
            )
            fp.flush()
            self.app.report["DesktopFile"] = fp.name
            QTimer.singleShot(0, QCoreApplication.quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(), self.distro.split()[0])
        self.assertEqual(
            self.app.dialog.heading.text(),
            _("The application Apport has closed unexpectedly."),
        )
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _("Relaunch"))
        self.assertTrue(self.app.dialog.closed_button.isVisible())
        self.assertFalse(self.app.dialog.text.isVisible())
        self.assertFalse(self.app.dialog.text.isVisible())
        self.assertTrue(self.app.dialog.ignore_future_problems.isVisible())
        self.assertTrue(
            str(self.app.dialog.ignore_future_problems.text()).endswith(
                "of this program version"
            )
        )

    def test_regular_crash_layout_norestart(self):
        """Display crash dialog for an application crash offering no restart.

        +-----------------------------------------------------------------+
        | [ apport ] The application Apport has closed unexpectedly.      |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |            [ ] Ignore future problems of this program version.  |
        |                                                                 |
        | [ Show Details ]                                   [ Continue ] |
        +-----------------------------------------------------------------+
        """
        # pretend we did not get called through run_crashes(),
        # thus no offer_restart
        self.app.report["ProblemType"] = "Crash"
        self.app.report["CrashCounter"] = "1"
        self.app.report["ProcCmdline"] = "apport-bug apport"
        self.app.report["Package"] = "apport 1.2.3~0ubuntu1"
        with tempfile.NamedTemporaryFile(mode="w+") as fp:
            fp.write(
                textwrap.dedent(
                    """\
                    [Desktop Entry]
                    Version=1.0
                    Name=Apport
                    Type=Application
                    """
                )
            )
            fp.flush()
            self.app.report["DesktopFile"] = fp.name
            QTimer.singleShot(0, QCoreApplication.quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(
            self.app.dialog.heading.text(),
            _("The application Apport has closed unexpectedly."),
        )
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _("Continue"))
        self.assertFalse(self.app.dialog.closed_button.isVisible())

    def test_system_crash_layout(self):
        """Display crash dialog for a system application crash.

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
        """
        self.app.report["ProblemType"] = "Crash"
        self.app.report["CrashCounter"] = "1"
        self.app.report["Package"] = "apport 1.2.3~0ubuntu1"
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(), self.distro.split()[0])
        self.assertEqual(
            self.app.dialog.heading.text(),
            _("Sorry, %s has experienced an internal error.") % self.distro,
        )
        self.assertEqual(
            self.app.dialog.text.text(),
            _("If you notice further problems, try restarting the computer."),
        )
        self.assertTrue(self.app.dialog.text.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _("Continue"))
        self.assertFalse(self.app.dialog.closed_button.isVisible())
        self.assertTrue(self.app.dialog.ignore_future_problems.isVisible())
        self.assertTrue(
            str(self.app.dialog.ignore_future_problems.text()).endswith(
                "of this type"
            )
        )

    def test_apport_bug_package_layout(self):
        """Display report detail dialog.

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
        """
        self.app.report_file = None
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(), self.distro.split()[0])
        self.assertEqual(
            self.app.dialog.heading.text(),
            _("Send problem report to the developers?"),
        )
        self.assertFalse(self.app.dialog.text.isVisible())
        self.assertFalse(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertFalse(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _("Send"))
        self.assertFalse(self.app.dialog.closed_button.isVisible())
        self.assertTrue(self.app.dialog.cancel_button.isVisible())
        self.assertTrue(self.app.dialog.treeview.isVisible())

    def test_recoverable_crash_layout(self):
        """Display crash dialog for a recoverable crash.

        +-----------------------------------------------------------------+
        | [ logo ] The application Foo has experienced an internal error. |
        |          Developer-specified error text.                        |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |                                                                 |
        | [ Show Details ]                                   [ Continue ] |
        +-----------------------------------------------------------------+
        """
        self.app.report["ProblemType"] = "RecoverableProblem"
        self.app.report["Package"] = "apport 1.2.3~0ubuntu1"
        self.app.report["DialogBody"] = "Some developer-specified error text."

        with tempfile.NamedTemporaryFile(mode="w+") as fp:
            fp.write(
                textwrap.dedent(
                    """\
                    [Desktop Entry]
                    Version=1.0
                    Name=Apport
                    Type=Application
                    """
                )
            )
            fp.flush()
            self.app.report["DesktopFile"] = fp.name
            QTimer.singleShot(0, QCoreApplication.quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(self.app.dialog.windowTitle(), self.distro.split()[0])
        msg = "The application Apport has experienced an internal error."
        self.assertEqual(self.app.dialog.heading.text(), msg)
        msg = "Some developer-specified error text."
        self.assertEqual(self.app.dialog.text.text(), msg)
        self.assertTrue(self.app.dialog.text.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isVisible())
        self.assertTrue(self.app.dialog.send_error_report.isChecked())
        self.assertTrue(self.app.dialog.details.isVisible())
        self.assertTrue(self.app.dialog.continue_button.isVisible())
        self.assertEqual(self.app.dialog.continue_button.text(), _("Continue"))
        self.assertFalse(self.app.dialog.closed_button.isVisible())

    def test_ui_question_choice_hide_dialog(self):
        """Test hiding/closing a UI question choice dialog.

        +---------------------+
        | Ultimate Question   |
        |                     |
        |   ( ) 7             |
        |   ( ) 42            |
        |   ( ) 69            |
        |                     |
        | [ Cancel ]   [ OK ] |
        +---------------------+
        """
        with wrap_object(
            apport_kde.Dialog, "__init__", include_instance=True
        ) as dialog_mock:

            def hide_dialog():
                if dialog_mock.call_count >= 1:
                    dialog = dialog_mock.call_args[0][0]
                    if dialog.isVisible():
                        dialog.hide()
                        return
                # try again
                QTimer.singleShot(200, hide_dialog)  # pragma: no cover

            QTimer.singleShot(200, hide_dialog)
            answer = self.app.ui_question_choice(
                "Ultimate Question", ["7", "42", "69"], False
            )
        self.assertEqual(answer, None)

    @unittest.mock.patch.object(
        MainUserInterface, "open_url", unittest.mock.MagicMock()
    )
    @unittest.mock.patch(
        "apport.report.Report.add_gdb_info", unittest.mock.MagicMock()
    )
    @unittest.mock.patch(
        "apport.fileutils.allowed_to_report",
        unittest.mock.MagicMock(return_value=True),
    )
    def test_1_crash_nodetails(self):
        """Crash report without showing details"""

        def cont():
            if self.app.dialog and self.app.dialog.continue_button.isVisible():
                self.app.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(1000, cont)  # pragma: no cover

        QTimer.singleShot(1000, cont)
        with wrap_object(
            apport_kde.ProgressDialog, "__init__"
        ) as progress_dialog:
            self.app.run_crash(self.app.report_file)

        # we should have reported one crash
        self.assertEqual(self.app.crashdb.latest_id(), 0)
        r = self.app.crashdb.download(0)
        self.assertEqual(r["ProblemType"], "Crash")
        self.assertEqual(r["ExecutablePath"], "/bin/bash")

        # should show a progress bar for info collection
        progress_dialog.assert_has_calls(
            [self.COLLECTING_DIALOG, self.UPLOADING_DIALOG]
        )

        # data was collected
        self.assertTrue(r["Package"].startswith("bash "))
        self.assertIn("libc", r["Dependencies"])

        # URL was opened
        self.assertEqual(self.app.open_url.call_count, 1)

    @unittest.mock.patch.object(
        MainUserInterface, "open_url", unittest.mock.MagicMock()
    )
    @unittest.mock.patch(
        "apport.report.Report.add_gdb_info", unittest.mock.MagicMock()
    )
    @unittest.mock.patch(
        "apport.fileutils.allowed_to_report",
        unittest.mock.MagicMock(return_value=True),
    )
    def test_1_crash_details(self):
        """Crash report with showing details"""

        def show_details():
            if self.app.dialog and self.app.dialog.show_details.isVisible():
                self.app.dialog.show_details.click()
                QTimer.singleShot(1000, cont)
                return

            # try again
            QTimer.singleShot(200, show_details)  # pragma: no cover

        def cont():
            # wait until data collection is done and tree filled
            details = self.app.dialog.findChild(QTreeWidget, "details")
            if details.topLevelItemCount() == 0:
                QTimer.singleShot(200, cont)
                return

            if self.app.dialog and self.app.dialog.continue_button.isVisible():
                self.app.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(200, cont)  # pragma: no cover

        QTimer.singleShot(200, show_details)
        with wrap_object(
            apport_kde.ProgressDialog, "__init__"
        ) as progress_dialog:
            self.app.run_crash(self.app.report_file)

        # we should have reported one crash
        self.assertEqual(self.app.crashdb.latest_id(), 0)
        r = self.app.crashdb.download(0)
        self.assertEqual(r["ProblemType"], "Crash")
        self.assertEqual(r["ExecutablePath"], "/bin/bash")

        # we already collected details, do not show the progress dialog again
        progress_dialog.assert_called_once_with(*self.UPLOADING_DIALOG.args)

        # data was collected
        self.assertTrue(r["Package"].startswith("bash "))
        self.assertIn("libc", r["Dependencies"])

        # URL was opened
        self.assertEqual(self.app.open_url.call_count, 1)

    @unittest.mock.patch.object(
        MainUserInterface, "open_url", unittest.mock.MagicMock()
    )
    @unittest.mock.patch(
        "apport.report.Report.add_gdb_info", unittest.mock.MagicMock()
    )
    @unittest.mock.patch(
        "apport.fileutils.allowed_to_report",
        unittest.mock.MagicMock(return_value=True),
    )
    def test_1_crash_noaccept(self):
        """Crash report with non-accepting crash DB"""

        def cont():
            if self.app.dialog and self.app.dialog.continue_button.isVisible():
                self.app.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(1000, cont)  # pragma: no cover

        QTimer.singleShot(1000, cont)
        self.app.crashdb.options["problem_types"] = ["bug"]
        with wrap_object(
            apport_kde.ProgressDialog, "__init__"
        ) as progress_dialog:
            self.app.run_crash(self.app.report_file)

        # we should not have reported the crash
        self.assertEqual(self.app.crashdb.latest_id(), -1)
        self.assertEqual(self.app.open_url.call_count, 0)

        # no progress dialog for non-accepting DB
        progress_dialog.assert_not_called()

        # data was collected for whoopsie
        r = self.app.report
        self.assertEqual(r["ProblemType"], "Crash")
        self.assertEqual(r["ExecutablePath"], "/bin/bash")
        self.assertTrue(r["Package"].startswith("bash "))
        self.assertIn("libc", r["Dependencies"])

    def test_bug_report_installed_package(self):
        """Bug report for installed package."""
        self.app.report_file = None
        self.app.args.package = "bash"

        def c():
            if self.app.dialog and self.app.dialog.cancel_button.isVisible():
                self.app.dialog.cancel_button.click()
                return
            # try again
            QTimer.singleShot(1000, c)  # pragma: no cover

        QTimer.singleShot(1000, c)
        self.app.run_report_bug()

        self.assertEqual(self.app.report["ProblemType"], "Bug")
        self.assertEqual(self.app.report["SourcePackage"], "bash")
        self.assertTrue(self.app.report["Package"].startswith("bash "))
        self.assertNotEqual(self.app.report["Dependencies"], "")

    def test_bug_report_uninstalled_package(self):
        """Bug report for uninstalled package"""
        pkg = apport.packaging.get_uninstalled_package()

        self.app.report_file = None
        self.app.args.package = pkg

        def c():
            if self.app.dialog and self.app.dialog.cancel_button.isVisible():
                self.app.dialog.cancel_button.click()
                return
            # try again
            QTimer.singleShot(1000, c)  # pragma: no cover

        QTimer.singleShot(1000, c)
        self.app.run_report_bug()

        self.assertEqual(self.app.report["ProblemType"], "Bug")
        self.assertEqual(
            self.app.report["SourcePackage"], apport.packaging.get_source(pkg)
        )
        self.assertEqual(
            self.app.report["Package"], "%s (not installed)" % pkg
        )

    @unittest.mock.patch.object(
        MainUserInterface, "open_url", unittest.mock.MagicMock()
    )
    def test_1_update_report(self):
        """Updating an existing report"""
        self.app.report_file = None

        def cont():
            if self.app.dialog and self.app.dialog.continue_button.isVisible():
                self.app.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(200, cont)  # pragma: no cover

        # upload empty report
        crash_id = self.app.crashdb.upload({})
        self.assertEqual(crash_id, 0)
        self.app.args.update_report = 0
        self.app.args.package = "bash"

        QTimer.singleShot(200, cont)
        self.app.run_update_report()

        # no new bug reported
        self.assertEqual(self.app.crashdb.latest_id(), 0)

        # bug was updated
        r = self.app.crashdb.download(0)
        self.assertTrue(r["Package"].startswith("bash "))
        self.assertIn("libc", r["Dependencies"])
        self.assertIn("DistroRelease", r)

        # No URL in this mode
        self.assertEqual(self.app.open_url.call_count, 0)

    @unittest.mock.patch.object(
        MainUserInterface, "open_url", unittest.mock.MagicMock()
    )
    def test_1_update_report_different_binary_source(self):
        """Updating an existing report on a source package which does not have
        a binary of the same name"""
        self.app.report_file = None

        def cont():
            if self.app.dialog and self.app.dialog.continue_button.isVisible():
                self.app.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(200, cont)  # pragma: no cover

        # this test assumes that the source package name is not an
        # installed binary package
        source_pkg = "shadow"
        self.assertRaises(ValueError, apport.packaging.get_version, source_pkg)

        # create source package hook, as otherwise there is nothing to collect
        with open(
            os.path.join(self.hook_dir, "source_%s.py" % source_pkg),
            "w",
            encoding="utf-8",
        ) as f:
            f.write('def add_info(r, ui):\n r["MachineType"]="Laptop"\n')

        # upload empty report
        crash_id = self.app.crashdb.upload({})
        self.assertEqual(crash_id, 0)

        # run in update mode for that bug
        self.app.args.update_report = 0
        self.app.args.package = source_pkg

        QTimer.singleShot(200, cont)
        self.app.run_update_report()

        # no new bug reported
        self.assertEqual(self.app.crashdb.latest_id(), 0)

        # bug was updated
        r = self.app.crashdb.download(0)
        self.assertIn("ProcEnviron", r)
        self.assertIn("DistroRelease", r)
        self.assertIn("Uname", r)
        self.assertEqual(r["MachineType"], "Laptop")

        # No URL in this mode
        self.assertEqual(self.app.open_url.call_count, 0)

    def test_administrator_disabled_reporting(self):
        QTimer.singleShot(0, QCoreApplication.quit)
        self.app.ui_present_report_details(False)
        self.assertFalse(self.app.dialog.send_error_report.isVisible())
        self.assertFalse(self.app.dialog.send_error_report.isChecked())
