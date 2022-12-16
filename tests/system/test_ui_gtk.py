"""GTK Apport user interface tests."""

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
import subprocess
import tempfile
import textwrap
import unittest
import unittest.mock

import gi

gi.require_version("Gtk", "3.0")  # noqa: E402, pylint: disable=C0413
from gi.repository import GLib, GObject, Gtk

import apport.crashdb_impl.memory
import apport.report
from apport import unicode_gettext as _
from tests.helper import import_module_from_file
from tests.paths import get_data_directory, local_test_environment

GLib.log_set_always_fatal(
    GLib.LogLevelFlags.LEVEL_WARNING | GLib.LogLevelFlags.LEVEL_CRITICAL
)


apport_gtk_path = os.path.join(get_data_directory("gtk"), "apport-gtk")
kernel_oops_path = os.path.join(get_data_directory(), "kernel_oops")
apport_gtk = import_module_from_file(apport_gtk_path)
GTKUserInterface = apport_gtk.GTKUserInterface


class T(unittest.TestCase):
    POLLING_INTERVAL_MS = 10

    @classmethod
    def setUpClass(cls):
        cls.orig_environ = os.environ.copy()
        os.environ |= local_test_environment()
        os.environ["LANGUAGE"] = "C"
        r = apport.report.Report()
        r.add_os_info()
        cls.distro = r["DistroRelease"].split()[0]

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

        self.app = GTKUserInterface([apport_gtk_path])

        # use in-memory crashdb
        self.app.crashdb = apport.crashdb_impl.memory.CrashDatabase(None, {})

        # test report
        self.app.report_file = os.path.join(self.report_dir, "bash.crash")

        self.app.report = apport.report.Report()
        self.app.report["ExecutablePath"] = "/bin/bash"
        self.app.report["Signal"] = "11"
        self.app.report["CoreDump"] = b"\x01\x02"
        self.app.report["DistroRelease"] = self.distro
        with open(self.app.report_file, "wb") as f:
            self.app.report.write(f)

        # disable package hooks, as they might ask for sudo password and other
        # interactive bits; allow tests to install their own hooks
        self.hook_dir = tempfile.mkdtemp()
        apport.report.GENERAL_HOOK_DIR = self.hook_dir
        apport.report.PACKAGE_HOOK_DIR = self.hook_dir

    def tearDown(self):
        shutil.rmtree(self.report_dir)
        shutil.rmtree(self.hook_dir)

    def test_close_button(self):
        """Clicking the close button on the window does not report the
        crash."""

        def c():
            self.app.w("dialog_crash_new").destroy()

        GLib.idle_add(c)
        result = self.app.ui_present_report_details(True)
        self.assertFalse(result["report"])

    def test_kernel_crash_layout(self):
        """Display crash dialog for kernel crash.

        +-----------------------------------------------------------------+
        | [ logo] YourDistro has experienced an internal error.           |
        |            Send problem report to the developers?               |
        |                                                                 |
        |            [ ] Remember this in future                          |
        |                                                                 |
        | [ Show Details ]                      [ Don't send ]   [ Send ] |
        +-----------------------------------------------------------------+
        """
        self.app.report["ProblemType"] = "KernelCrash"
        GLib.idle_add(Gtk.main_quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(
            self.app.w("dialog_crash_new").get_title(), self.distro
        )
        self.assertEqual(
            self.app.w("title_label").get_text(),
            _("Sorry, %s has experienced an internal error.") % self.distro,
        )
        self.assertTrue(
            self.app.w("send_problem_notice_label").get_property("visible")
        )
        remember_send_error_report = self.app.w("remember_send_report_choice")
        self.assertTrue(remember_send_error_report.get_property("visible"))
        self.assertFalse(remember_send_error_report.get_active())
        self.assertTrue(self.app.w("show_details").get_property("visible"))
        self.assertTrue(self.app.w("dont_send_button").get_property("visible"))
        self.assertTrue(self.app.w("continue_button").get_property("visible"))
        self.assertEqual(self.app.w("continue_button").get_label(), _("Send"))
        self.assertFalse(self.app.w("subtitle_label").get_property("visible"))
        self.assertFalse(
            self.app.w("ignore_future_problems").get_property("visible")
        )

    def test_package_crash_layout(self):
        """Display crash dialog for a failed package installation.

        +-----------------------------------------------------------------+
        | [ error  ] Sorry, a problem occurred while installing software. |
        |            Send problem report to the developers?               |
        |            Package: apport 1.2.3~0ubuntu1                       |
        |                                                                 |
        |            [ ] Remember this in future                          |
        |                                                                 |
        | [ Show Details ]                      [ Don't send ]   [ Send ] |
        +-----------------------------------------------------------------+
        """
        self.app.report["ProblemType"] = "Package"
        self.app.report["Package"] = "apport 1.2.3~0ubuntu1"
        GLib.idle_add(Gtk.main_quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(
            self.app.w("dialog_crash_new").get_title(), self.distro
        )
        self.assertEqual(
            self.app.w("title_label").get_text(),
            _("Sorry, a problem occurred while installing software."),
        )
        self.assertTrue(
            self.app.w("send_problem_notice_label").get_property("visible")
        )
        remember_send_error_report = self.app.w("remember_send_report_choice")
        self.assertTrue(remember_send_error_report.get_property("visible"))
        self.assertFalse(remember_send_error_report.get_active())
        self.assertTrue(self.app.w("show_details").get_property("visible"))
        self.assertTrue(self.app.w("dont_send_button").get_property("visible"))
        self.assertTrue(self.app.w("continue_button").get_property("visible"))
        self.assertEqual(self.app.w("continue_button").get_label(), _("Send"))
        self.assertTrue(self.app.w("subtitle_label").get_property("visible"))
        self.assertEqual(
            self.app.w("subtitle_label").get_text(),
            _("Package: apport 1.2.3~0ubuntu1"),
        )

    def test_regular_crash_thread_layout(self):
        """A thread of execution has failed, but the application persists.

        +-----------------------------------------------------------------+
        | [ logo] YourDistro has experienced an internal error.           |
        |            Send problem report to the developers?               |
        |            If you notice further problems, try restarting the   |
        |            computer.                                            |
        |                                                                 |
        |            [ ] Remember this in future                          |
        |                                                                 |
        | [ Show Details ]                      [ Don't send ]   [ Send ] |
        +-----------------------------------------------------------------+
        """
        self.app.report["ProblemType"] = "Crash"
        self.app.report["ProcStatus"] = "Name:\tupstart\nPid:\t1"
        GLib.idle_add(Gtk.main_quit)
        self.app.ui_present_report_details(True)
        self.assertTrue(self.app.w("dont_send_button").get_property("visible"))
        self.assertEqual(self.app.w("continue_button").get_label(), _("Send"))

    def test_regular_crash_layout(self):
        """Display crash dialog for an application crash.

        +-----------------------------------------------------------------+
        | [ apport ] The application Apport has closed unexpectedly.      |
        |            Send problem report to the developers?               |
        |                                                                 |
        |            [ ] Remember this in future                          |
        |            [ ] Ignore future problems of this program version   |
        |                                                                 |
        | [ Show Details ]                      [ Don't send ]   [ Send ] |
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
            GLib.idle_add(Gtk.main_quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(
            self.app.w("dialog_crash_new").get_title(), self.distro
        )
        self.assertEqual(
            self.app.w("title_label").get_text(),
            _("The application Apport has closed unexpectedly."),
        )
        self.assertTrue(
            self.app.w("send_problem_notice_label").get_property("visible")
        )
        remember_send_error_report = self.app.w("remember_send_report_choice")
        self.assertTrue(remember_send_error_report.get_property("visible"))
        self.assertFalse(remember_send_error_report.get_active())
        self.assertTrue(self.app.w("show_details").get_property("visible"))
        self.assertTrue(self.app.w("dont_send_button").get_property("visible"))
        # no ProcCmdline, cannot restart
        self.assertTrue(self.app.w("continue_button").get_property("visible"))
        self.assertEqual(self.app.w("continue_button").get_label(), _("Send"))
        self.assertFalse(self.app.w("subtitle_label").get_property("visible"))
        self.assertTrue(
            self.app.w("ignore_future_problems").get_property("visible")
        )
        self.assertTrue(
            self.app.w("ignore_future_problems")
            .get_label()
            .endswith("of this program version")
        )

    def test_regular_crash_layout_restart(self):
        """Display crash dialog for an application crash offering a restart.

        +-----------------------------------------------------------------+
        | [ apport ] The application Apport has closed unexpectedly.      |
        |            Send problem report to the developers?               |
        |                                                                 |
        |            [ ] Remember this in future                          |
        |            [ ] Ignore future problems of this program version   |
        |            [X] Relaunch this application                        |
        |                                                                 |
        | [ Show Details ]                      [ Don't send ]   [ Send ] |
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
            GLib.idle_add(Gtk.main_quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(
            self.app.w("dialog_crash_new").get_title(), self.distro
        )
        self.assertEqual(
            self.app.w("title_label").get_text(),
            _("The application Apport has closed unexpectedly."),
        )
        self.assertTrue(
            self.app.w("send_problem_notice_label").get_property("visible")
        )
        remember_send_error_report = self.app.w("remember_send_report_choice")
        self.assertTrue(remember_send_error_report.get_property("visible"))
        self.assertFalse(remember_send_error_report.get_active())
        self.assertTrue(self.app.w("show_details").get_property("visible"))
        self.assertTrue(self.app.w("dont_send_button").get_property("visible"))
        self.assertTrue(self.app.w("continue_button").get_property("visible"))
        self.assertEqual(self.app.w("continue_button").get_label(), _("Send"))
        self.assertFalse(self.app.w("subtitle_label").get_property("visible"))
        self.assertTrue(
            self.app.w("ignore_future_problems").get_property("visible")
        )
        self.assertTrue(
            self.app.w("ignore_future_problems")
            .get_label()
            .endswith("of this program version")
        )
        self.assertTrue(self.app.w("relaunch_app").get_property("visible"))
        self.assertTrue(self.app.w("relaunch_app").get_active())

    def test_regular_crash_layout_norestart(self):
        """Display crash dialog for an application crash offering no restart.

        +-----------------------------------------------------------------+
        | [ apport ] The application Apport has closed unexpectedly.      |
        |            Send problem report to the developers?               |
        |                                                                 |
        |            [ ] Remember this in future                          |
        |            [ ] Ignore future problems of this program version.  |
        |                                                                 |
        | [ Show Details ]                      [ Don't send ]   [ Send ] |
        +-----------------------------------------------------------------+
        """
        # pretend we did not get called through run_crashes(), thus
        # no offer_restart
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
            GLib.idle_add(Gtk.main_quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(
            self.app.w("dialog_crash_new").get_title(), self.distro
        )
        self.assertEqual(
            self.app.w("title_label").get_text(),
            _("The application Apport has closed unexpectedly."),
        )
        self.assertTrue(
            self.app.w("send_problem_notice_label").get_property("visible")
        )
        remember_send_error_report = self.app.w("remember_send_report_choice")
        self.assertTrue(remember_send_error_report.get_property("visible"))
        self.assertFalse(remember_send_error_report.get_active())
        self.assertTrue(self.app.w("show_details").get_property("visible"))
        self.assertTrue(self.app.w("dont_send_button").get_property("visible"))
        self.assertTrue(self.app.w("continue_button").get_property("visible"))
        self.assertEqual(self.app.w("continue_button").get_label(), _("Send"))

    def test_hang_layout(self):
        """Display crash dialog for a hanging process.

        +-----------------------------------------------------------------+
        | [ apport ] The application Apport has stopped responding.       |
        |            Send problem report to the developers?               |
        |            You can wait to see if it wakes up, or close, or     |
        |            relaunch it.                                         |
        |                                                                 |
        |            [ ] Remember this in future                          |
        |            [X] Relaunch this application                        |
        |                                                                 |
        | [ Show Details ]                      [ Don't send ]   [ Send ] |
        +-----------------------------------------------------------------+
        """
        # pretend we got called through run_crashes() which sets offer_restart
        self.app.offer_restart = True
        self.app.report["ProblemType"] = "Hang"
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
            GLib.idle_add(Gtk.main_quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(
            self.app.w("dialog_crash_new").get_title(), self.distro
        )
        self.assertEqual(
            self.app.w("title_label").get_text(),
            _("The application Apport has stopped responding."),
        )
        self.assertEqual(
            self.app.w("subtitle_label").get_text(),
            _(
                "You can wait to see if it wakes up, or close or "
                "relaunch it."
            ),
        )
        self.assertTrue(
            self.app.w("send_problem_notice_label").get_property("visible")
        )
        remember_send_error_report = self.app.w("remember_send_report_choice")
        self.assertTrue(remember_send_error_report.get_property("visible"))
        self.assertFalse(remember_send_error_report.get_active())
        self.assertTrue(self.app.w("show_details").get_property("visible"))
        self.assertTrue(self.app.w("dont_send_button").get_property("visible"))
        self.assertTrue(self.app.w("continue_button").get_property("visible"))
        self.assertEqual(self.app.w("continue_button").get_label(), _("Send"))
        self.assertTrue(self.app.w("subtitle_label").get_property("visible"))
        self.assertFalse(
            self.app.w("ignore_future_problems").get_property("visible")
        )

    def test_system_crash_layout(self):
        """Display crash dialog for a system application crash.

        +---------------------------------------------------------------+
        | [ logo ] Sorry, YourDistro has experienced an internal error. |
        |          Send problem report to the developers?               |
        |          If you notice further problems, try restarting the   |
        |          computer                                             |
        |                                                               |
        |            [ ] Remember this in future                        |
        |            [ ] Ignore future problems of this type.           |
        |                                                               |
        | [ Show Details ]                    [ Don't send ]   [ Send ] |
        +---------------------------------------------------------------+
        """
        self.app.report["ProblemType"] = "Crash"
        self.app.report["CrashCounter"] = "1"
        self.app.report["Package"] = "bash 5"
        GLib.idle_add(Gtk.main_quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(
            self.app.w("dialog_crash_new").get_title(), self.distro
        )
        self.assertEqual(
            self.app.w("title_label").get_text(),
            _("Sorry, %s has experienced an internal error.") % self.distro,
        )
        self.assertEqual(
            self.app.w("subtitle_label").get_text(),
            _("If you notice further problems, try restarting the computer."),
        )
        self.assertTrue(self.app.w("subtitle_label").get_property("visible"))
        self.assertTrue(
            self.app.w("send_problem_notice_label").get_property("visible")
        )
        remember_send_error_report = self.app.w("remember_send_report_choice")
        self.assertTrue(remember_send_error_report.get_property("visible"))
        self.assertFalse(remember_send_error_report.get_active())
        self.assertTrue(self.app.w("show_details").get_property("visible"))
        self.assertTrue(self.app.w("dont_send_button").get_property("visible"))
        self.assertTrue(self.app.w("continue_button").get_property("visible"))
        self.assertEqual(self.app.w("continue_button").get_label(), _("Send"))
        self.assertTrue(
            self.app.w("ignore_future_problems").get_property("visible")
        )
        self.assertTrue(
            self.app.w("ignore_future_problems")
            .get_label()
            .endswith("of this type")
        )

    def test_system_crash_from_console_layout(self):
        """Display crash dialog from console.

        +-------------------------------------------------------------------+
        | [ ubuntu ] Sorry, the application apport has closed unexpectedly. |
        |            Send problem report to the developers?                 |
        |            If you notice further problems, try restarting the     |
        |            computer                                               |
        |                                                                   |
        |            [ ] Remember this in future                            |
        |                                                                   |
        | [ Show Details ]                      [ Don't send ]   [ Send ]   |
        +-------------------------------------------------------------------+
        """
        self.app.report["ProblemType"] = "Crash"
        self.app.report["Package"] = "bash 5"
        self.app.report[
            "ProcEnviron"
        ] = "LANGUAGE=en_GB:en\nSHELL=/bin/sh\nTERM=xterm"
        self.app.report["ExecutablePath"] = "/usr/bin/apport"
        # This will be set by apport/ui.py in load_report()
        self.app.cur_package = "apport"
        GLib.idle_add(Gtk.main_quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(
            self.app.w("dialog_crash_new").get_title(), self.distro
        )
        self.assertEqual(
            self.app.w("title_label").get_text(),
            _("Sorry, the application apport has stopped unexpectedly."),
        )
        self.assertEqual(
            self.app.w("subtitle_label").get_text(),
            _("If you notice further problems, try restarting the computer."),
        )
        self.assertTrue(self.app.w("subtitle_label").get_property("visible"))
        self.assertTrue(
            self.app.w("send_problem_notice_label").get_property("visible")
        )
        remember_send_error_report = self.app.w("remember_send_report_choice")
        self.assertTrue(remember_send_error_report.get_property("visible"))
        self.assertFalse(remember_send_error_report.get_active())
        self.assertTrue(self.app.w("show_details").get_property("visible"))
        self.assertTrue(self.app.w("dont_send_button").get_property("visible"))
        self.assertTrue(self.app.w("continue_button").get_property("visible"))
        self.assertEqual(self.app.w("continue_button").get_label(), _("Send"))

        del self.app.report["ExecutablePath"]
        GLib.idle_add(Gtk.main_quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(
            self.app.w("title_label").get_text(),
            _("Sorry, apport has closed unexpectedly."),
        )

        # no crash counter
        self.assertFalse(
            self.app.w("ignore_future_problems").get_property("visible")
        )

    @unittest.mock.patch.object(
        GTKUserInterface, "can_examine_locally", unittest.mock.MagicMock()
    )
    def test_examine_button(self):
        """Crash dialog showing or not showing "Examine locally".

        +---------------------------------------------------------------------+
        | [ apport ] The application Apport has closed unexpectedly.          |
        |            Send problem report to the developers?                   |
        |                                                                     |
        |            [ ] Remember this in future                              |
        |                                                                     |
        | [ Show Details ] [ Examine locally ]      [ Don't send ]   [ Send ] |
        +---------------------------------------------------------------------+
        """
        self.app.report["ProblemType"] = "Crash"
        self.app.report["Package"] = "bash 5"

        GLib.idle_add(Gtk.main_quit)
        self.app.can_examine_locally.return_value = False
        self.app.ui_present_report_details(True)
        self.assertFalse(self.app.w("examine").get_property("visible"))

        GLib.idle_add(self.app.w("examine").clicked)
        self.app.can_examine_locally.return_value = True
        result = self.app.ui_present_report_details(True)
        self.assertTrue(self.app.w("examine").get_property("visible"))
        self.assertTrue(result["examine"])

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
        |                                         [ Don't send ]   [ Send ] |
        +-------------------------------------------------------------------+
        """
        self.app.report_file = None
        GLib.idle_add(Gtk.main_quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(
            self.app.w("title_label").get_text(),
            _("Send problem report to the developers?"),
        )
        self.assertFalse(self.app.w("subtitle_label").get_property("visible"))
        self.assertFalse(
            self.app.w("send_problem_notice_label").get_property("visible")
        )
        remember_send_error_report = self.app.w("remember_send_report_choice")
        self.assertFalse(remember_send_error_report.get_property("visible"))
        self.assertFalse(remember_send_error_report.get_active())
        self.assertFalse(self.app.w("show_details").get_property("visible"))
        self.assertTrue(self.app.w("continue_button").get_property("visible"))
        self.assertEqual(self.app.w("continue_button").get_label(), _("Send"))
        self.assertTrue(self.app.w("dont_send_button").get_property("visible"))
        self.assertTrue(
            self.app.w("details_scrolledwindow").get_property("visible")
        )
        self.assertTrue(self.app.w("dialog_crash_new").get_resizable())

    def test_apport_bug_package_layout_load_file(self):
        """Bug layout from a loaded report."""
        self.app.report_file = "/tmp/foo.apport"
        self.app.report = apport.report.Report("Bug")
        self.app.report["Package"] = "libfoo1"
        self.app.report["SourcePackage"] = "foo"

        GLib.idle_add(Gtk.main_quit)
        self.app.ui_present_report_details(True)
        self.assertEqual(
            self.app.w("title_label").get_text(),
            _("Send problem report to the developers?"),
        )
        self.assertFalse(self.app.w("subtitle_label").get_property("visible"))
        self.assertFalse(
            self.app.w("send_problem_notice_label").get_property("visible")
        )
        remember_send_error_report = self.app.w("remember_send_report_choice")
        self.assertFalse(remember_send_error_report.get_property("visible"))
        self.assertFalse(remember_send_error_report.get_active())
        self.assertFalse(self.app.w("show_details").get_property("visible"))
        self.assertTrue(self.app.w("continue_button").get_property("visible"))
        self.assertEqual(self.app.w("continue_button").get_label(), _("Send"))
        self.assertTrue(self.app.w("dont_send_button").get_property("visible"))
        self.assertTrue(
            self.app.w("details_scrolledwindow").get_property("visible")
        )
        self.assertTrue(self.app.w("dialog_crash_new").get_resizable())

    def test_recoverable_crash_layout(self):
        """Display crash dialog for a recoverable crash.

        +-----------------------------------------------------------------+
        | [ logo ] The application Foo has experienced an internal error. |
        |            Send problem report to the developers?               |
        |          Developer-specified error text.                        |
        |                                                                 |
        |            [ ] Remember this in future                          |
        |                                                                 |
        | [ Show Details ]                      [ Don't send ]   [ Send ] |
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
            GLib.idle_add(Gtk.main_quit)
            self.app.ui_present_report_details(True)
        self.assertEqual(
            self.app.w("dialog_crash_new").get_title(), self.distro
        )
        msg = "The application Apport has experienced an internal error."
        self.assertEqual(self.app.w("title_label").get_text(), msg)
        msg = "Some developer-specified error text."
        self.assertEqual(self.app.w("subtitle_label").get_text(), msg)
        self.assertTrue(self.app.w("subtitle_label").get_property("visible"))
        self.assertTrue(
            self.app.w("send_problem_notice_label").get_property("visible")
        )
        remember_send_error_report = self.app.w("remember_send_report_choice")
        self.assertTrue(remember_send_error_report.get_property("visible"))
        self.assertFalse(remember_send_error_report.get_active())
        self.assertTrue(self.app.w("show_details").get_property("visible"))
        self.assertTrue(self.app.w("continue_button").get_property("visible"))
        self.assertEqual(self.app.w("continue_button").get_label(), _("Send"))

    def test_administrator_disabled_reporting(self):
        GLib.idle_add(Gtk.main_quit)
        self.app.ui_present_report_details(False)
        self.assertFalse(
            self.app.w("send_problem_notice_label").get_property("visible")
        )
        remember_send_error_report = self.app.w("remember_send_report_choice")
        self.assertFalse(remember_send_error_report.get_property("visible"))
        self.assertFalse(remember_send_error_report.get_active())

    @unittest.mock.patch.object(
        GTKUserInterface, "open_url", unittest.mock.MagicMock()
    )
    @unittest.mock.patch.object(
        GTKUserInterface, "ui_start_upload_progress", unittest.mock.MagicMock()
    )
    @unittest.mock.patch.object(
        GTKUserInterface, "ui_stop_upload_progress", unittest.mock.MagicMock()
    )
    @unittest.mock.patch(
        "apport.report.Report.add_gdb_info", unittest.mock.MagicMock()
    )
    @unittest.mock.patch(
        "apport.fileutils.allowed_to_report",
        unittest.mock.MagicMock(return_value=True),
    )
    def test_crash_nodetails(self):
        """Crash report without showing details"""

        def cont():
            if Gtk.events_pending():
                return True  # pragma: no cover
            if not self.app.w("continue_button").get_visible():
                return True  # pragma: no cover
            self.app.w("continue_button").clicked()
            return False

        GLib.timeout_add(self.POLLING_INTERVAL_MS, cont)
        info_collection_window = self.app.w("window_information_collection")
        with unittest.mock.patch.object(
            info_collection_window, "show", wraps=info_collection_window.show
        ) as info_collection_window_show_mock:
            self.app.run_crash(self.app.report_file)

        # we should have reported one crash
        self.assertEqual(self.app.crashdb.latest_id(), 0)
        r = self.app.crashdb.download(0)
        self.assertEqual(r["ProblemType"], "Crash")
        self.assertEqual(r["ExecutablePath"], "/bin/bash")

        # should show a progress bar for info collection
        info_collection_window_show_mock.assert_called_once_with()

        # data was collected
        self.assertTrue(r["Package"].startswith("bash "))
        self.assertIn("libc", r["Dependencies"])

        # upload dialog shown
        self.assertEqual(self.app.ui_start_upload_progress.call_count, 1)
        self.assertEqual(self.app.ui_stop_upload_progress.call_count, 1)

        # URL was opened
        self.assertEqual(self.app.open_url.call_count, 1)

    @unittest.mock.patch.object(
        GTKUserInterface, "open_url", unittest.mock.MagicMock()
    )
    @unittest.mock.patch.object(
        GTKUserInterface, "ui_start_upload_progress", unittest.mock.MagicMock()
    )
    @unittest.mock.patch.object(
        GTKUserInterface, "ui_stop_upload_progress", unittest.mock.MagicMock()
    )
    @unittest.mock.patch(
        "apport.report.Report.add_gdb_info", unittest.mock.MagicMock()
    )
    @unittest.mock.patch(
        "apport.fileutils.allowed_to_report",
        unittest.mock.MagicMock(return_value=True),
    )
    def test_crash_details(self):
        """Crash report with showing details"""

        def show_details():
            if Gtk.events_pending():
                return True  # pragma: no cover
            if not self.app.w("show_details").get_visible():
                return True  # pragma: no cover
            self.app.w("show_details").clicked()
            GLib.timeout_add(self.POLLING_INTERVAL_MS, cont)
            return False

        def cont():
            if Gtk.events_pending():
                return True  # pragma: no cover
            # wait until data collection is done and tree filled
            if self.app.tree_model.get_iter_first() is None:
                return True  # pragma: no cover

            self.assertTrue(self.app.w("continue_button").get_visible())
            self.app.w("continue_button").clicked()
            return False

        GLib.timeout_add(self.POLLING_INTERVAL_MS, show_details)
        info_collection_window = self.app.w("window_information_collection")
        with unittest.mock.patch.object(
            info_collection_window, "show", wraps=info_collection_window.show
        ) as info_collection_window_show_mock:
            self.app.run_crash(self.app.report_file)

        # we should have reported one crash
        self.assertEqual(self.app.crashdb.latest_id(), 0)
        r = self.app.crashdb.download(0)
        self.assertEqual(r["ProblemType"], "Crash")
        self.assertEqual(r["ExecutablePath"], "/bin/bash")

        # we already collected details, do not show the progress dialog again
        info_collection_window_show_mock.assert_not_called()

        # data was collected
        self.assertTrue(r["Package"].startswith("bash "))
        self.assertIn("libc", r["Dependencies"])

        # upload dialog shown
        self.assertEqual(self.app.ui_start_upload_progress.call_count, 1)
        self.assertEqual(self.app.ui_stop_upload_progress.call_count, 1)

        # URL was opened
        self.assertEqual(self.app.open_url.call_count, 1)

    @unittest.mock.patch.object(
        GTKUserInterface, "open_url", unittest.mock.MagicMock()
    )
    @unittest.mock.patch.object(
        GTKUserInterface, "ui_start_upload_progress", unittest.mock.MagicMock()
    )
    @unittest.mock.patch.object(
        GTKUserInterface, "ui_stop_upload_progress", unittest.mock.MagicMock()
    )
    @unittest.mock.patch(
        "apport.fileutils.allowed_to_report",
        unittest.mock.MagicMock(return_value=True),
    )
    def test_broken_crash_details(self):
        """Broken crash report with showing details."""
        # pylint: disable=attribute-defined-outside-init
        self.error_title = None
        self.error_text = None

        def show_details():
            if Gtk.events_pending():
                return True  # pragma: no cover
            if not self.app.w("show_details").get_visible():
                return True  # pragma: no cover
            self.app.w("show_details").clicked()
            GLib.timeout_add(self.POLLING_INTERVAL_MS, cont)
            return False

        def cont():
            # wait until data collection is done and tree filled
            if Gtk.events_pending():
                return True  # pragma: no cover
            if self.app.tree_model.get_iter_first() is None:
                return True  # pragma: no cover

            self.assertTrue(self.app.w("continue_button").get_visible())
            self.app.w("continue_button").clicked()
            GLib.timeout_add(self.POLLING_INTERVAL_MS, ack_error)
            return False

        def ack_error():
            # wait until error dialog gets visible
            if Gtk.events_pending():
                return True  # pragma: no cover
            if not self.app.md:
                return True  # pragma: no cover
            self.error_title = self.app.md.get_title()
            self.error_text = self.app.md.get_property("text")
            self.app.md.response(0)
            return False

        # damage core dump in report file
        with open(self.app.report_file, encoding="utf-8") as f:
            lines = f.readlines()
        lines[-1] = " iiiiiiiiiiiiAAAA\n"
        with open(self.app.report_file, "w", encoding="utf-8") as f:
            f.write("".join(lines))
        self.app.report = None
        GLib.timeout_add(self.POLLING_INTERVAL_MS, show_details)
        self.app.run_crash(self.app.report_file)

        # upload dialog not shown
        self.assertEqual(self.app.ui_start_upload_progress.call_count, 0)
        self.assertEqual(self.app.ui_stop_upload_progress.call_count, 0)

        # no URL was opened
        self.assertEqual(self.app.open_url.call_count, 0)

        # no crash uploaded
        self.assertEqual(self.app.crashdb.latest_id(), -1)

        # proper error message
        self.assertNotEqual(self.error_title, None)
        self.assertIn("cannot be reported", self.error_text)
        self.assertIn("decompressing", self.error_text)

    @unittest.mock.patch.object(
        GTKUserInterface, "open_url", unittest.mock.MagicMock()
    )
    @unittest.mock.patch(
        "apport.fileutils.allowed_to_report",
        unittest.mock.MagicMock(return_value=True),
    )
    def test_crash_noaccept(self):
        """Crash report with non-accepting crash DB"""

        def cont():
            if Gtk.events_pending():
                return True  # pragma: no cover
            if not self.app.w("continue_button").get_visible():
                return True  # pragma: no cover
            self.app.w("continue_button").clicked()
            return False

        GLib.timeout_add(self.POLLING_INTERVAL_MS, cont)
        self.app.crashdb.options["problem_types"] = ["bug"]
        info_collection_window = self.app.w("window_information_collection")
        with unittest.mock.patch.object(
            info_collection_window, "show", wraps=info_collection_window.show
        ) as info_collection_window_show_mock:
            self.app.run_crash(self.app.report_file)

        # we should not have reported the crash
        self.assertEqual(self.app.crashdb.latest_id(), -1)
        self.assertEqual(self.app.open_url.call_count, 0)

        # no progress dialog for non-accepting DB
        info_collection_window_show_mock.assert_not_called()

        # data was collected for whoopsie
        r = self.app.report
        self.assertEqual(r["ProblemType"], "Crash")
        self.assertEqual(r["ExecutablePath"], "/bin/bash")
        self.assertTrue(r["Package"].startswith("bash "))
        self.assertIn("libc", r["Dependencies"])

    @unittest.mock.patch.object(
        GTKUserInterface, "open_url", unittest.mock.MagicMock()
    )
    @unittest.mock.patch(
        "apport.fileutils.allowed_to_report",
        unittest.mock.MagicMock(return_value=True),
    )
    def test_kerneloops_nodetails(self):
        """Kernel oops report without showing details"""

        def cont():
            if Gtk.events_pending():
                return True  # pragma: no cover
            if not self.app.w("continue_button").get_visible():
                return True  # pragma: no cover
            self.app.w("continue_button").clicked()
            return False

        # remove the crash from setUp() and create a kernel oops
        os.remove(self.app.report_file)
        subprocess.run(
            [kernel_oops_path],
            check=True,
            input=b"Plasma conduit phase misalignment",
        )

        GLib.timeout_add(self.POLLING_INTERVAL_MS, cont)
        self.app.run_crashes()

        # we should have reported one crash
        self.assertEqual(self.app.crashdb.latest_id(), 0)
        r = self.app.crashdb.download(0)
        self.assertEqual(r["ProblemType"], "KernelOops")
        self.assertEqual(r["OopsText"], "Plasma conduit phase misalignment")

        # data was collected
        self.assertIn("linux", r["Package"])
        self.assertIn("Plasma conduit", r["Title"])
        if not r["Package"].endswith(" (not installed)"):
            self.assertIn("Dependencies", r)

        # URL was opened
        self.assertEqual(self.app.open_url.call_count, 1)

    def test_bug_report_installed_package(self):
        """Bug report for installed package"""

        def c():
            if Gtk.events_pending():
                return True  # pragma: no cover
            dont_send_button = self.app.w("dont_send_button")
            if not self.has_click_event_connected(dont_send_button):
                return True  # pragma: no cover
            dont_send_button.clicked()
            return False

        self.app.report_file = None
        self.app.args.package = "bash"
        GLib.timeout_add(self.POLLING_INTERVAL_MS, c)
        self.app.run_report_bug()

        self.assertEqual(self.app.report["ProblemType"], "Bug")
        self.assertEqual(self.app.report["SourcePackage"], "bash")
        self.assertTrue(self.app.report["Package"].startswith("bash "))
        self.assertNotEqual(self.app.report["Dependencies"], "")

    def test_bug_report_uninstalled_package(self):
        """Bug report for uninstalled package"""

        def c():
            if Gtk.events_pending():
                return True  # pragma: no cover
            dont_send_button = self.app.w("dont_send_button")
            if not self.has_click_event_connected(dont_send_button):
                return True  # pragma: no cover
            dont_send_button.clicked()
            return False

        pkg = apport.packaging.get_uninstalled_package()
        self.app.report_file = None
        self.app.args.package = pkg
        GLib.timeout_add(self.POLLING_INTERVAL_MS, c)
        self.app.run_report_bug()

        self.assertEqual(self.app.report["ProblemType"], "Bug")
        self.assertEqual(
            self.app.report["SourcePackage"], apport.packaging.get_source(pkg)
        )
        self.assertEqual(
            self.app.report["Package"], "%s (not installed)" % pkg
        )

    @unittest.mock.patch.object(
        GTKUserInterface, "open_url", unittest.mock.MagicMock()
    )
    def test_update_report(self):
        """Updating an existing report."""
        self.app.report_file = None

        def cont():
            if Gtk.events_pending():
                return True  # pragma: no cover
            if self.app.tree_model.get_iter_first() is None:
                return True  # pragma: no cover
            self.app.w("continue_button").clicked()
            return False

        # upload empty report
        crash_id = self.app.crashdb.upload({})
        self.assertEqual(crash_id, 0)
        self.app.args.update_report = 0
        self.app.args.package = "bash"

        GLib.timeout_add(self.POLLING_INTERVAL_MS, cont)
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
        GTKUserInterface, "open_url", unittest.mock.MagicMock()
    )
    def test_update_report_different_binary_source(self):
        """Updating an existing report on a source package which does not have
        a binary of the same name"""
        self.app.report_file = None

        def cont():
            if Gtk.events_pending():
                return True  # pragma: no cover
            if self.app.tree_model.get_iter_first() is None:
                return True  # pragma: no cover
            self.app.w("continue_button").clicked()
            return False

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

        GLib.timeout_add(self.POLLING_INTERVAL_MS, cont)
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

    @unittest.mock.patch.object(
        GTKUserInterface, "get_desktop_entry", unittest.mock.MagicMock()
    )
    def test_missing_icon(self):
        # LP: 937354
        self.app.report["ProblemType"] = "Crash"
        self.app.report["Package"] = "apport 1.2.3~0ubuntu1"
        self.app.get_desktop_entry.return_value = {
            "name": "apport",
            "icon": "nonexistent",
        }
        GLib.idle_add(Gtk.main_quit)
        self.app.ui_present_report_details(True)

    def test_resizing(self):
        """Problem report window resizability and sizing."""

        def show_details(data):
            if not self.app.w("show_details").get_visible():
                return True  # pragma: no cover

            data["orig_size"] = self.app.w("dialog_crash_new").get_size()
            data["orig_resizable"] = self.app.w(
                "dialog_crash_new"
            ).get_resizable()
            self.app.w("show_details").clicked()
            GLib.timeout_add(200, hide_details, data)
            return False

        def hide_details(data):
            # wait until data collection is done and tree filled
            if self.app.tree_model.get_iter_first() is None:
                return True  # pragma: no cover

            data["detail_size"] = self.app.w("dialog_crash_new").get_size()
            data["detail_resizable"] = self.app.w(
                "dialog_crash_new"
            ).get_resizable()
            self.app.w("show_details").clicked()
            GLib.timeout_add(200, details_hidden, data)
            return False

        def details_hidden(data):
            # wait until data collection is done and tree filled
            if self.app.w("details_scrolledwindow").get_visible():
                return True  # pragma: no cover

            data["hidden_size"] = self.app.w("dialog_crash_new").get_size()
            data["hidden_resizable"] = self.app.w(
                "dialog_crash_new"
            ).get_resizable()
            Gtk.main_quit()
            return False

        data = {}
        GLib.timeout_add(200, show_details, data)
        self.app.run_crash(self.app.report_file)

        # when showing details, dialog should get considerably bigger
        self.assertGreater(data["detail_size"][1], data["orig_size"][1] + 100)

        # when hiding details, original size should be restored
        self.assertEqual(data["orig_size"], data["hidden_size"])

        # should only be resizable in details mode
        self.assertFalse(data["orig_resizable"])
        self.assertTrue(data["detail_resizable"])
        self.assertFalse(data["hidden_resizable"])

    def test_dialog_nonascii(self):
        """Non-ASCII title/text in dialogs"""

        def close(response):
            if Gtk.events_pending():
                return True  # pragma: no cover
            if not self.app.md:
                return True  # pragma: no cover
            self.app.md.response(response)
            return False

        # unicode arguments
        GLib.timeout_add(self.POLLING_INTERVAL_MS, close, 0)
        self.app.ui_info_message(
            b"title \xe2\x99\xaa".decode("UTF-8"),
            b"text \xe2\x99\xaa".decode("UTF-8"),
        )

        # with URLs
        GLib.timeout_add(self.POLLING_INTERVAL_MS, close, 0)
        self.app.ui_info_message(
            "title", b"http://example.com \xe2\x99\xaa".decode("UTF-8")
        )

    def test_immediate_close(self):
        """Close details window immediately."""
        # this reproduces https://launchpad.net/bugs/938090
        self.app.w("dialog_crash_new").destroy()
        GLib.idle_add(Gtk.main_quit)
        self.app.run_crash(self.app.report_file)

    @unittest.mock.patch.object(
        GTKUserInterface, "ui_start_upload_progress", unittest.mock.MagicMock()
    )
    def test_close_during_collect(self):
        """Close details window during information collection"""

        def show_details():
            if Gtk.events_pending():
                return True  # pragma: no cover
            if not self.app.w("show_details").get_visible():
                return True  # pragma: no cover
            self.app.w("show_details").clicked()
            GLib.timeout_add(self.POLLING_INTERVAL_MS, close)
            return False

        def close():
            if Gtk.events_pending():
                return True  # pragma: no cover
            self.app.w("dialog_crash_new").destroy()
            return False

        GLib.timeout_add(self.POLLING_INTERVAL_MS, show_details)
        self.app.run_crash(self.app.report_file)

        self.assertEqual(self.app.ui_start_upload_progress.call_count, 0)

    def test_text_to_markup(self):
        """Test text_to_markup() with different URLs."""
        urls = ["https://example.com", "https://example.com/file-bug-report"]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(
                    apport_gtk.text_to_markup(
                        f"Contact them via {url} for help."
                    ),
                    f'Contact them via <a href="{url}">{url}</a> for help.',
                )

    def test_text_to_markup_url_followed_by_dot(self):
        """Test text_to_markup() with https URL followed by a dot."""
        url = "https://example.com/file-bug-report"
        self.assertEqual(
            apport_gtk.text_to_markup(f"Für Hilfe gehen Sie über {url}."),
            f'Für Hilfe gehen Sie über <a href="{url}">{url}</a>.',
        )

    def test_ui_update_view_destroyed(self):
        """Test ui_update_view if the dialog is already destroyed."""
        self.app.w("details_treeview").destroy()
        self.app.ui_update_view()

    @staticmethod
    def has_click_event_connected(widget):
        signal_id = GObject.signal_lookup("clicked", widget)
        signal_handler_id = GObject.signal_handler_find(
            widget,
            GObject.SignalMatchType.ID | GObject.SignalMatchType.UNBLOCKED,
            signal_id,
            0,
            None,
            0,
            0,
        )
        return signal_handler_id != 0
