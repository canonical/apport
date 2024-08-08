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

# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import os
import shutil
import tempfile
import textwrap
import unittest
import unittest.mock
from gettext import gettext as _
from unittest.mock import MagicMock

try:
    from PyQt5.QtCore import QCoreApplication, QTimer
    from PyQt5.QtWidgets import QFileDialog, QProgressBar, QTreeWidget

    PYQT5_IMPORT_ERROR = None
except ImportError as error:
    PYQT5_IMPORT_ERROR = error

import apport.crashdb_impl.memory
import apport.report
from tests.helper import import_module_from_file, wrap_object
from tests.paths import get_data_directory, local_test_environment

apport_kde_path = get_data_directory("kde") / "apport-kde"
if not PYQT5_IMPORT_ERROR:
    apport_kde = import_module_from_file(apport_kde_path)
    MainUserInterface = apport_kde.MainUserInterface
else:
    MainUserInterface = None


@unittest.skipIf(PYQT5_IMPORT_ERROR, f"PyQt/PyKDE not available: {PYQT5_IMPORT_ERROR}")
class T(unittest.TestCase):
    # pylint: disable=missing-class-docstring,missing-function-docstring
    # pylint: disable=too-many-public-methods
    COLLECTING_DIALOG = unittest.mock.call(
        str(apport_kde_path.parent),
        "Collecting Problem Information",
        "Collecting problem information",
        "The collected information can be sent to the developers to improve "
        "the application. This might take a few minutes.",
    )
    UPLOADING_DIALOG = unittest.mock.call(
        str(apport_kde_path.parent),
        "Uploading Problem Information",
        "Uploading problem information",
        "The collected information is being sent to the bug tracking system. "
        "This might take a few minutes.",
    )
    argv: list[str]
    distro: str
    orig_environ: dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.orig_environ = os.environ.copy()
        os.environ |= local_test_environment()
        os.environ["LANGUAGE"] = "C"

        cls.argv = [str(apport_kde_path)]
        r = apport.report.Report()
        r.add_os_info()
        cls.distro = r["DistroRelease"]

    @classmethod
    def tearDownClass(cls) -> None:
        os.environ.clear()
        os.environ.update(cls.orig_environ)

    def setUp(self) -> None:
        self.report_dir = tempfile.mkdtemp()
        apport.fileutils.report_dir = self.report_dir
        os.environ["APPORT_REPORT_DIR"] = self.report_dir
        # do not cause eternal hangs because of error dialog boxes
        os.environ["APPORT_IGNORE_OBSOLETE_PACKAGES"] = "1"
        os.environ["APPORT_DISABLE_DISTRO_CHECK"] = "1"

        self.ui = MainUserInterface(self.argv)
        # use in-memory crashdb
        self.ui.crashdb = apport.crashdb_impl.memory.CrashDatabase(None, {})

        # disable package hooks, as they might ask for sudo password and other
        # interactive bits; allow tests to install their own hooks
        self.hook_dir = tempfile.mkdtemp()
        apport.report.GENERAL_HOOK_DIR = self.hook_dir
        apport.report.PACKAGE_HOOK_DIR = self.hook_dir

        # test report
        self.ui.report_file = os.path.join(self.report_dir, "bash.crash")

        self.ui.report = apport.report.Report()
        self.ui.report["ExecutablePath"] = "/bin/bash"
        self.ui.report["Signal"] = "11"
        self.ui.report["CoreDump"] = b"\x01\x02"
        with open(self.ui.report_file, "wb") as f:
            self.ui.report.write(f)

    def tearDown(self) -> None:
        if self.ui.dialog:
            QCoreApplication.processEvents()
            self.ui.dialog.done(0)
            QCoreApplication.processEvents()
        self.ui.app.exit()
        del self.ui.app

        shutil.rmtree(self.report_dir)
        shutil.rmtree(self.hook_dir)

    def test_close_button(self) -> None:
        """Clicking the close button on the window does not report the
        crash."""

        def c() -> None:
            self.ui.dialog.reject()

        QTimer.singleShot(0, c)
        result = self.ui.ui_present_report_details(True)
        self.assertFalse(result.report)

    def test_kernel_crash_layout(self) -> None:
        """Display crash dialog for kernel crash.

        +-----------------------------------------------------------------+
        | [ logo ] YourDistro has experienced an internal error.          |
        |                                                                 |
        |            [x] Send an error report to help fix this problem.   |
        |                                                                 |
        | [ Show Details ]                                   [ Continue ] |
        +-----------------------------------------------------------------+
        """
        self.ui.report["ProblemType"] = "KernelCrash"
        QTimer.singleShot(0, QCoreApplication.quit)
        self.ui.ui_present_report_details(True)
        self.assertEqual(self.ui.dialog.windowTitle(), self.distro.split()[0])
        self.assertEqual(
            self.ui.dialog.heading.text(),
            _("Sorry, %s has experienced an internal error.") % self.distro,
        )
        self.assertTrue(self.ui.dialog.send_error_report.isVisible())
        self.assertTrue(self.ui.dialog.send_error_report.isChecked())
        self.assertTrue(self.ui.dialog.details.isVisible())
        self.assertTrue(self.ui.dialog.continue_button.isVisible())
        self.assertEqual(self.ui.dialog.continue_button.text(), _("Continue"))
        self.assertFalse(self.ui.dialog.closed_button.isVisible())
        self.assertFalse(self.ui.dialog.text.isVisible())

    def test_package_crash_layout(self) -> None:
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
        self.ui.report["ProblemType"] = "Package"
        self.ui.report["Package"] = "apport 1.2.3~0ubuntu1"
        QTimer.singleShot(0, QCoreApplication.quit)
        self.ui.ui_present_report_details(True)
        self.assertEqual(self.ui.dialog.windowTitle(), self.distro.split()[0])
        self.assertEqual(
            self.ui.dialog.heading.text(),
            _("Sorry, a problem occurred while installing software."),
        )
        self.assertTrue(self.ui.dialog.send_error_report.isVisible())
        self.assertTrue(self.ui.dialog.send_error_report.isChecked())
        self.assertTrue(self.ui.dialog.details.isVisible())
        self.assertTrue(self.ui.dialog.continue_button.isVisible())
        self.assertEqual(self.ui.dialog.continue_button.text(), _("Continue"))
        self.assertFalse(self.ui.dialog.closed_button.isVisible())
        self.assertEqual(
            self.ui.dialog.text.text(), _("Package: apport 1.2.3~0ubuntu1")
        )

    def test_regular_crash_thread_layout(self) -> None:
        """A thread of execution has failed, but the application persists."""
        self.ui.report["ProblemType"] = "Crash"
        self.ui.report["ProcStatus"] = "Name:\tsystemd\nPid:\t1"
        QTimer.singleShot(0, QCoreApplication.quit)
        self.ui.ui_present_report_details(True)
        self.assertFalse(self.ui.dialog.closed_button.isVisible())
        self.assertEqual(self.ui.dialog.continue_button.text(), _("Continue"))

    def test_regular_crash_layout(self) -> None:
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
        self.ui.report["ProblemType"] = "Crash"
        self.ui.report["CrashCounter"] = "1"
        self.ui.report["Package"] = "apport 1.2.3~0ubuntu1"
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
            self.ui.report["DesktopFile"] = fp.name
            QTimer.singleShot(0, QCoreApplication.quit)
            self.ui.ui_present_report_details(True)
        self.assertEqual(self.ui.dialog.windowTitle(), self.distro.split()[0])
        self.assertEqual(
            self.ui.dialog.heading.text(),
            _("The application Apport has closed unexpectedly."),
        )
        self.assertTrue(self.ui.dialog.send_error_report.isVisible())
        self.assertTrue(self.ui.dialog.send_error_report.isChecked())
        self.assertTrue(self.ui.dialog.details.isVisible())
        # no ProcCmdline, cannot restart
        self.assertTrue(self.ui.dialog.continue_button.isVisible())
        self.assertEqual(self.ui.dialog.continue_button.text(), _("Continue"))
        self.assertFalse(self.ui.dialog.closed_button.isVisible())
        self.assertFalse(self.ui.dialog.text.isVisible())
        self.assertFalse(self.ui.dialog.text.isVisible())
        self.assertTrue(self.ui.dialog.ignore_future_problems.isVisible())
        self.assertTrue(
            str(self.ui.dialog.ignore_future_problems.text()).endswith(
                "of this program version"
            )
        )

    def test_regular_crash_layout_restart(self) -> None:
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
        self.ui.offer_restart = True
        self.ui.report["ProblemType"] = "Crash"
        self.ui.report["CrashCounter"] = "1"
        self.ui.report["ProcCmdline"] = "apport-bug apport"
        self.ui.report["Package"] = "apport 1.2.3~0ubuntu1"
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
            self.ui.report["DesktopFile"] = fp.name
            QTimer.singleShot(0, QCoreApplication.quit)
            self.ui.ui_present_report_details(True)
        self.assertEqual(self.ui.dialog.windowTitle(), self.distro.split()[0])
        self.assertEqual(
            self.ui.dialog.heading.text(),
            _("The application Apport has closed unexpectedly."),
        )
        self.assertTrue(self.ui.dialog.send_error_report.isVisible())
        self.assertTrue(self.ui.dialog.send_error_report.isChecked())
        self.assertTrue(self.ui.dialog.details.isVisible())
        self.assertTrue(self.ui.dialog.continue_button.isVisible())
        self.assertEqual(self.ui.dialog.continue_button.text(), _("Relaunch"))
        self.assertTrue(self.ui.dialog.closed_button.isVisible())
        self.assertFalse(self.ui.dialog.text.isVisible())
        self.assertFalse(self.ui.dialog.text.isVisible())
        self.assertTrue(self.ui.dialog.ignore_future_problems.isVisible())
        self.assertTrue(
            str(self.ui.dialog.ignore_future_problems.text()).endswith(
                "of this program version"
            )
        )

    def test_regular_crash_layout_norestart(self) -> None:
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
        self.ui.report["ProblemType"] = "Crash"
        self.ui.report["CrashCounter"] = "1"
        self.ui.report["ProcCmdline"] = "apport-bug apport"
        self.ui.report["Package"] = "apport 1.2.3~0ubuntu1"
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
            self.ui.report["DesktopFile"] = fp.name
            QTimer.singleShot(0, QCoreApplication.quit)
            self.ui.ui_present_report_details(True)
        self.assertEqual(
            self.ui.dialog.heading.text(),
            _("The application Apport has closed unexpectedly."),
        )
        self.assertTrue(self.ui.dialog.send_error_report.isVisible())
        self.assertTrue(self.ui.dialog.send_error_report.isChecked())
        self.assertTrue(self.ui.dialog.details.isVisible())
        self.assertTrue(self.ui.dialog.continue_button.isVisible())
        self.assertEqual(self.ui.dialog.continue_button.text(), _("Continue"))
        self.assertFalse(self.ui.dialog.closed_button.isVisible())

    def test_system_crash_layout(self) -> None:
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
        self.ui.report["ProblemType"] = "Crash"
        self.ui.report["CrashCounter"] = "1"
        self.ui.report["Package"] = "apport 1.2.3~0ubuntu1"
        QTimer.singleShot(0, QCoreApplication.quit)
        self.ui.ui_present_report_details(True)
        self.assertEqual(self.ui.dialog.windowTitle(), self.distro.split()[0])
        self.assertEqual(
            self.ui.dialog.heading.text(),
            _("Sorry, %s has experienced an internal error.") % self.distro,
        )
        self.assertEqual(
            self.ui.dialog.text.text(),
            _("If you notice further problems, try restarting the computer."),
        )
        self.assertTrue(self.ui.dialog.text.isVisible())
        self.assertTrue(self.ui.dialog.send_error_report.isVisible())
        self.assertTrue(self.ui.dialog.send_error_report.isChecked())
        self.assertTrue(self.ui.dialog.details.isVisible())
        self.assertTrue(self.ui.dialog.continue_button.isVisible())
        self.assertEqual(self.ui.dialog.continue_button.text(), _("Continue"))
        self.assertFalse(self.ui.dialog.closed_button.isVisible())
        self.assertTrue(self.ui.dialog.ignore_future_problems.isVisible())
        self.assertTrue(
            str(self.ui.dialog.ignore_future_problems.text()).endswith("of this type")
        )

    def test_apport_bug_package_layout(self) -> None:
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
        self.ui.report_file = None
        QTimer.singleShot(0, QCoreApplication.quit)
        self.ui.ui_present_report_details(True)
        self.assertEqual(self.ui.dialog.windowTitle(), self.distro.split()[0])
        self.assertEqual(
            self.ui.dialog.heading.text(), _("Send problem report to the developers?")
        )
        self.assertFalse(self.ui.dialog.text.isVisible())
        self.assertFalse(self.ui.dialog.send_error_report.isVisible())
        self.assertTrue(self.ui.dialog.send_error_report.isChecked())
        self.assertFalse(self.ui.dialog.details.isVisible())
        self.assertTrue(self.ui.dialog.continue_button.isVisible())
        self.assertEqual(self.ui.dialog.continue_button.text(), _("Send"))
        self.assertFalse(self.ui.dialog.closed_button.isVisible())
        self.assertTrue(self.ui.dialog.cancel_button.isVisible())
        self.assertTrue(self.ui.dialog.treeview.isVisible())

    def test_recoverable_crash_layout(self) -> None:
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
        self.ui.report["ProblemType"] = "RecoverableProblem"
        self.ui.report["Package"] = "apport 1.2.3~0ubuntu1"
        self.ui.report["DialogBody"] = "Some developer-specified error text."

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
            self.ui.report["DesktopFile"] = fp.name
            QTimer.singleShot(0, QCoreApplication.quit)
            self.ui.ui_present_report_details(True)
        self.assertEqual(self.ui.dialog.windowTitle(), self.distro.split()[0])
        msg = "The application Apport has experienced an internal error."
        self.assertEqual(self.ui.dialog.heading.text(), msg)
        msg = "Some developer-specified error text."
        self.assertEqual(self.ui.dialog.text.text(), msg)
        self.assertTrue(self.ui.dialog.text.isVisible())
        self.assertTrue(self.ui.dialog.send_error_report.isVisible())
        self.assertTrue(self.ui.dialog.send_error_report.isChecked())
        self.assertTrue(self.ui.dialog.details.isVisible())
        self.assertTrue(self.ui.dialog.continue_button.isVisible())
        self.assertEqual(self.ui.dialog.continue_button.text(), _("Continue"))
        self.assertFalse(self.ui.dialog.closed_button.isVisible())

    def test_ui_question_choice_hide_dialog(self) -> None:
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

            def hide_dialog() -> None:
                if dialog_mock.call_count >= 1:
                    dialog = dialog_mock.call_args[0][0]
                    if dialog.isVisible():
                        dialog.hide()
                        return
                # try again
                QTimer.singleShot(200, hide_dialog)  # pragma: no cover

            QTimer.singleShot(200, hide_dialog)
            answer = self.ui.ui_question_choice(
                "Ultimate Question", ["7", "42", "69"], False
            )
        self.assertIsNone(answer)

    @unittest.mock.patch.object(MainUserInterface, "open_url", MagicMock())
    @unittest.mock.patch("apport.report.Report.add_gdb_info", MagicMock())
    @unittest.mock.patch(
        "apport.fileutils.allowed_to_report", MagicMock(return_value=True)
    )
    def test_1_crash_nodetails(self) -> None:
        """Crash report without showing details"""

        def cont() -> None:
            if self.ui.dialog and self.ui.dialog.continue_button.isVisible():
                self.ui.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(1000, cont)  # pragma: no cover

        QTimer.singleShot(1000, cont)
        with wrap_object(apport_kde.ProgressDialog, "__init__") as progress_dialog:
            self.ui.run_crash(self.ui.report_file)

        # we should have reported one crash
        self.assertEqual(self.ui.crashdb.latest_id(), 0)
        r = self.ui.crashdb.download(0)
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
        self.assertEqual(self.ui.open_url.call_count, 1)

    @unittest.mock.patch.object(MainUserInterface, "open_url", MagicMock())
    @unittest.mock.patch("apport.report.Report.add_gdb_info", MagicMock())
    @unittest.mock.patch(
        "apport.fileutils.allowed_to_report", MagicMock(return_value=True)
    )
    def test_1_crash_details(self) -> None:
        """Crash report with showing details"""

        def show_details() -> None:
            if self.ui.dialog and self.ui.dialog.show_details.isVisible():
                self.ui.dialog.show_details.click()
                QTimer.singleShot(1000, cont)
                return

            # try again
            QTimer.singleShot(200, show_details)  # pragma: no cover

        def cont() -> None:
            # wait until data collection is done and tree filled
            details = self.ui.dialog.findChild(QTreeWidget, "details")
            assert isinstance(details, QTreeWidget)
            if details.topLevelItemCount() == 0:
                QTimer.singleShot(200, cont)
                return

            if self.ui.dialog and self.ui.dialog.continue_button.isVisible():
                self.ui.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(200, cont)  # pragma: no cover

        QTimer.singleShot(200, show_details)
        with wrap_object(apport_kde.ProgressDialog, "__init__") as progress_dialog:
            self.ui.run_crash(self.ui.report_file)

        # we should have reported one crash
        self.assertEqual(self.ui.crashdb.latest_id(), 0)
        r = self.ui.crashdb.download(0)
        self.assertEqual(r["ProblemType"], "Crash")
        self.assertEqual(r["ExecutablePath"], "/bin/bash")

        # we already collected details, do not show the progress dialog again
        progress_dialog.assert_called_once_with(*self.UPLOADING_DIALOG.args)

        # data was collected
        self.assertTrue(r["Package"].startswith("bash "))
        self.assertIn("libc", r["Dependencies"])

        # URL was opened
        self.assertEqual(self.ui.open_url.call_count, 1)

    @unittest.mock.patch.object(MainUserInterface, "open_url", MagicMock())
    @unittest.mock.patch("apport.report.Report.add_gdb_info", MagicMock())
    @unittest.mock.patch(
        "apport.fileutils.allowed_to_report", MagicMock(return_value=True)
    )
    def test_1_crash_noaccept(self) -> None:
        """Crash report with non-accepting crash DB"""

        def cont() -> None:
            if self.ui.dialog and self.ui.dialog.continue_button.isVisible():
                self.ui.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(1000, cont)  # pragma: no cover

        QTimer.singleShot(1000, cont)
        self.ui.crashdb.options["problem_types"] = ["bug"]
        with wrap_object(apport_kde.ProgressDialog, "__init__") as progress_dialog:
            self.ui.run_crash(self.ui.report_file)

        # we should not have reported the crash
        self.assertEqual(self.ui.crashdb.latest_id(), -1)
        self.assertEqual(self.ui.open_url.call_count, 0)

        # no progress dialog for non-accepting DB
        progress_dialog.assert_not_called()

        # data was collected for whoopsie
        r = self.ui.report
        self.assertEqual(r["ProblemType"], "Crash")
        self.assertEqual(r["ExecutablePath"], "/bin/bash")
        self.assertTrue(r["Package"].startswith("bash "))
        self.assertIn("libc", r["Dependencies"])

    def test_bug_report_installed_package(self) -> None:
        """Bug report for installed package."""
        self.ui.report_file = None
        self.ui.args.package = "bash"

        def c() -> None:
            if self.ui.dialog and self.ui.dialog.cancel_button.isVisible():
                self.ui.dialog.cancel_button.click()
                return
            # try again
            QTimer.singleShot(1000, c)  # pragma: no cover

        QTimer.singleShot(1000, c)
        self.ui.run_report_bug()

        self.assertEqual(self.ui.report["ProblemType"], "Bug")
        self.assertEqual(self.ui.report["SourcePackage"], "bash")
        self.assertTrue(self.ui.report["Package"].startswith("bash "))
        self.assertNotEqual(self.ui.report["Dependencies"], "")

    def test_bug_report_uninstalled_package(self) -> None:
        """Bug report for uninstalled package"""
        pkg = apport.packaging.get_uninstalled_package()

        self.ui.report_file = None
        self.ui.args.package = pkg

        def c() -> None:
            if self.ui.dialog and self.ui.dialog.cancel_button.isVisible():
                self.ui.dialog.cancel_button.click()
                return
            # try again
            QTimer.singleShot(1000, c)  # pragma: no cover

        QTimer.singleShot(1000, c)
        self.ui.run_report_bug()

        self.assertEqual(self.ui.report["ProblemType"], "Bug")
        self.assertEqual(
            self.ui.report["SourcePackage"], apport.packaging.get_source(pkg)
        )
        self.assertEqual(self.ui.report["Package"], f"{pkg} (not installed)")

    @unittest.mock.patch.object(MainUserInterface, "open_url", MagicMock())
    def test_1_update_report(self) -> None:
        """Updating an existing report"""
        self.ui.report_file = None

        def cont() -> None:
            if self.ui.dialog and self.ui.dialog.continue_button.isVisible():
                self.ui.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(200, cont)  # pragma: no cover

        # upload empty report
        crash_id = self.ui.crashdb.upload({})
        self.assertEqual(crash_id, 0)
        self.ui.args.update_report = 0
        self.ui.args.package = "bash"

        QTimer.singleShot(200, cont)
        self.ui.run_update_report()

        # no new bug reported
        self.assertEqual(self.ui.crashdb.latest_id(), 0)

        # bug was updated
        r = self.ui.crashdb.download(0)
        self.assertTrue(r["Package"].startswith("bash "))
        self.assertIn("libc", r["Dependencies"])
        self.assertIn("DistroRelease", r)

        # No URL in this mode
        self.assertEqual(self.ui.open_url.call_count, 0)

    @unittest.mock.patch.object(MainUserInterface, "open_url", MagicMock())
    def test_1_update_report_different_binary_source(self) -> None:
        """Updating an existing report on a source package which does not have
        a binary of the same name"""
        self.ui.report_file = None

        def cont() -> None:
            if self.ui.dialog and self.ui.dialog.continue_button.isVisible():
                self.ui.dialog.continue_button.click()
                return
            # try again
            QTimer.singleShot(200, cont)  # pragma: no cover

        # this test assumes that the source package name is not an
        # installed binary package
        source_pkg = "shadow"
        self.assertRaises(ValueError, apport.packaging.get_version, source_pkg)

        # create source package hook, as otherwise there is nothing to collect
        with open(
            os.path.join(self.hook_dir, f"source_{source_pkg}.py"),
            "w",
            encoding="utf-8",
        ) as f:
            f.write('def add_info(r, ui):\n r["MachineType"]="Laptop"\n')

        # upload empty report
        crash_id = self.ui.crashdb.upload({})
        self.assertEqual(crash_id, 0)

        # run in update mode for that bug
        self.ui.args.update_report = 0
        self.ui.args.package = source_pkg

        QTimer.singleShot(200, cont)
        self.ui.run_update_report()

        # no new bug reported
        self.assertEqual(self.ui.crashdb.latest_id(), 0)

        # bug was updated
        r = self.ui.crashdb.download(0)
        self.assertIn("ProcEnviron", r)
        self.assertIn("DistroRelease", r)
        self.assertIn("Uname", r)
        self.assertEqual(r["MachineType"], "Laptop")

        # No URL in this mode
        self.assertEqual(self.ui.open_url.call_count, 0)

    def test_administrator_disabled_reporting(self) -> None:
        QTimer.singleShot(0, QCoreApplication.quit)
        self.ui.ui_present_report_details(False)
        self.assertFalse(self.ui.dialog.send_error_report.isVisible())
        self.assertFalse(self.ui.dialog.send_error_report.isChecked())

    def test_ui_run_terminal(self) -> None:
        """Test ui_run_terminal."""
        if not self.ui.ui_has_terminal():
            self.skipTest("installed terminal application needed")
        self.ui.ui_run_terminal("true")

    def test_ui_set_upload_progress(self) -> None:
        self.ui.ui_start_upload_progress()
        try:
            self.ui.ui_set_upload_progress(0.5)
            progress = self.ui.progress.findChild(QProgressBar, "progress")
            assert isinstance(progress, QProgressBar)
            self.assertEqual(progress.value(), 500)
        finally:
            self.ui.ui_stop_upload_progress()

    def test_ui_question_file_close(self) -> None:
        def cont() -> None:
            for widget in self.ui.app.allWidgets():
                if isinstance(widget, QFileDialog):
                    widget.close()
                    return

            # try again
            QTimer.singleShot(10, cont)  # pragma: no cover

        QTimer.singleShot(10, cont)
        self.assertIsNone(self.ui.ui_question_file("Please select a file"))
