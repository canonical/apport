"""Integration tests for the apport.ui module."""

# pylint: disable=too-many-lines

import errno
import glob
import io
import locale
import os
import pwd
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest
import unittest.mock
import urllib.error
from typing import Any
from unittest.mock import MagicMock, patch

import apport.crashdb_impl.memory
import apport.fileutils
import apport.report
import apport.ui
import problem_report
from apport.packaging_impl import impl as packaging
from apport.ui import _, run_as_real_user
from tests.helper import (
    pids_of,
    run_test_executable,
    skip_if_command_is_missing,
    wait_for_process_to_appear,
)
from tests.paths import local_test_environment, patch_data_dir, restore_data_dir

ORIGINAL_SUBPROCESS_RUN = subprocess.run


def mock_run_calls_except_pgrep(
    args: list[str], check: bool = False, **kwargs: Any
) -> subprocess.CompletedProcess:
    """Wrap subprocess.run() doing no-ops except for pgrep."""
    if args[0] == "pgrep":
        return ORIGINAL_SUBPROCESS_RUN(args, check=check, **kwargs)
    return subprocess.CompletedProcess(args, 0)


class UserInterfaceMock(apport.ui.UserInterface):
    # pylint: disable=too-many-instance-attributes
    """Concrete apport.ui.UserInterface suitable for automatic testing"""

    crashdb: apport.crashdb_impl.memory.CrashDatabase

    def __init__(self, argv: list[str] | None = None) -> None:
        # use our memory crashdb which is designed for testing
        # closed in __del__, pylint: disable=consider-using-with
        self.crashdb_conf = tempfile.NamedTemporaryFile()
        self.crashdb_conf.write(
            textwrap.dedent(
                """\
                default = 'testsuite'
                databases = {
                    'testsuite': {
                        'impl': 'memory',
                        'bug_pattern_url': None,
                    },
                    'debug': {
                        'impl': 'memory',
                        'distro': 'debug',
                    },
                }
                """
            ).encode()
        )
        self.crashdb_conf.flush()

        os.environ["APPORT_CRASHDB_CONF"] = self.crashdb_conf.name

        if argv is None:
            argv = ["ui-test"]
        apport.ui.UserInterface.__init__(self, argv)

        self.crashdb = apport.crashdb_impl.memory.CrashDatabase(
            None, {"sample_data": 1, "dupdb_url": ""}
        )

        # state of progress dialogs
        self.ic_progress_active = False
        self.ic_progress_pulses = 0  # count the pulses
        self.upload_progress_active = False
        self.upload_progress_pulses = 0

        # store last message box
        self.msg_title: str | None = None
        self.msg_text: str | None = None
        self.msg_severity: str | None = None
        self.msg_choices: list[str] | None = None

        # these store the choices the ui_present_* calls do
        self.present_package_error_response = None
        self.present_kernel_error_response = None
        self.present_details_response: apport.ui.Action | None = None
        self.question_yesno_response: bool | None = None
        self.question_choice_response: list[int] | None = None
        self.question_file_response: str | None = None

        self.opened_url: str | None = None
        self.present_details_shown = False

        self.clear_msg()

    def __del__(self) -> None:
        self.crashdb_conf.close()

    def clear_msg(self) -> None:
        """Clear the recorded messages"""
        # last message box
        self.msg_title = None
        self.msg_text = None
        self.msg_severity = None  # 'warning' or 'error'
        self.msg_choices = None

    def ui_present_report_details(
        self, allowed_to_report: bool = True, modal_for: int | None = None
    ) -> apport.ui.Action:
        self.present_details_shown = True
        assert modal_for is None or isinstance(modal_for, int)
        assert self.present_details_response
        return self.present_details_response

    def ui_info_message(self, title: str, text: str) -> None:
        self.msg_title = title
        self.msg_text = text
        self.msg_severity = "info"

    def ui_error_message(self, title: str, text: str) -> None:
        self.msg_title = title
        self.msg_text = text
        self.msg_severity = "error"

    def ui_start_info_collection_progress(self) -> None:
        self.ic_progress_pulses = 0
        self.ic_progress_active = True

    def ui_pulse_info_collection_progress(self) -> None:
        assert self.ic_progress_active
        self.ic_progress_pulses += 1

    def ui_stop_info_collection_progress(self) -> None:
        self.ic_progress_active = False

    def ui_start_upload_progress(self) -> None:
        self.upload_progress_pulses = 0
        self.upload_progress_active = True

    def ui_set_upload_progress(self, progress: float | None) -> None:
        assert self.upload_progress_active
        self.upload_progress_pulses += 1

    def ui_stop_upload_progress(self) -> None:
        self.upload_progress_active = False

    def ui_has_terminal(self) -> bool:
        # The tests are already running in a terminal
        return True

    def ui_run_terminal(self, command: str) -> None:
        subprocess.call(command, shell=True)

    def open_url(self, url: str) -> None:
        self.opened_url = url

    def ui_question_yesno(self, text: str) -> bool | None:
        self.msg_text = text
        return self.question_yesno_response

    def ui_question_choice(
        self, text: str, options: list[str], multiple: bool
    ) -> list[int] | None:
        self.msg_text = text
        self.msg_choices = options
        return self.question_choice_response

    def ui_question_file(self, text: str) -> str | None:
        self.msg_text = text
        return self.question_file_response


@unittest.mock.patch(
    "apport.hookutils._root_command_prefix", MagicMock(return_value=[])
)
class T(unittest.TestCase):
    # pylint: disable=missing-function-docstring,too-many-instance-attributes
    # pylint: disable=too-many-public-methods
    """Integration tests for apport.ui."""

    TEST_EXECUTABLE = os.path.realpath("/bin/sleep")
    TEST_ARGS = ["86400"]

    def setUp(self) -> None:
        self.orig_environ = os.environ.copy()
        os.environ |= local_test_environment()

        # we test a few strings, don't get confused by translations
        for v in ("LANG", "LANGUAGE", "LC_MESSAGES", "LC_ALL"):
            try:
                del os.environ[v]
            except KeyError:
                pass

        self.orig_data_dir = patch_data_dir(apport.report)

        # pylint: disable=protected-access
        self.workdir = tempfile.mkdtemp()
        self.orig_report_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = os.path.join(self.workdir, "crash")
        os.mkdir(apport.fileutils.report_dir)
        self.orig_symptom_script_dir = apport.ui.symptom_script_dir
        apport.ui.symptom_script_dir = os.path.join(self.workdir, "symptoms")
        os.mkdir(apport.ui.symptom_script_dir)
        self.orig_ignore_file = apport.report._ignore_file
        apport.report._ignore_file = os.path.join(self.workdir, "apport-ignore.xml")
        os.mknod(apport.report._ignore_file)

        # demo report
        self.report = apport.Report()
        self.report["ExecutablePath"] = "/bin/bash"
        self.report["Package"] = "libfoo1 1-1"
        self.report["SourcePackage"] = "foo"
        self.report["Foo"] = "A" * 1000
        self.report["CoreDump"] = problem_report.CompressedValue(b"\x01" * 100000)

        # write demo report into temporary file
        # closed in tearDown, pylint: disable=consider-using-with
        self.report_file = tempfile.NamedTemporaryFile()
        self.update_report_file()

        # set up our local hook directory
        self.hookdir = os.path.join(self.workdir, "package-hooks")
        os.mkdir(self.hookdir)
        self.orig_package_hook_dir = apport.report.PACKAGE_HOOK_DIR
        apport.report.PACKAGE_HOOK_DIR = self.hookdir

        # test suite should not stumble over local packages
        os.environ["APPORT_IGNORE_OBSOLETE_PACKAGES"] = "1"
        os.environ["APPORT_DISABLE_DISTRO_CHECK"] = "1"

        self.running_test_executables = pids_of(self.TEST_EXECUTABLE)

    def update_report_file(self) -> None:
        self.report_file.seek(0)
        self.report_file.truncate()
        self.report.write(self.report_file)
        self.report_file.flush()

    def tearDown(self):
        apport.fileutils.report_dir = self.orig_report_dir
        self.orig_report_dir = None
        apport.ui.symptom_script_dir = self.orig_symptom_script_dir
        self.orig_symptom_script_dir = None

        # pylint: disable=protected-access
        os.unlink(apport.report._ignore_file)
        apport.report._ignore_file = self.orig_ignore_file

        self.report_file.close()

        self.assertEqual(
            pids_of(self.TEST_EXECUTABLE) - self.running_test_executables,
            set(),
            "no stray test processes",
        )

        apport.report.PACKAGE_HOOK_DIR = self.orig_package_hook_dir
        shutil.rmtree(self.workdir)
        os.environ.clear()
        os.environ.update(self.orig_environ)

        restore_data_dir(apport.report, self.orig_data_dir)

    @staticmethod
    def _write_symptom_script(script_name: str, content: str) -> None:
        path = os.path.join(apport.ui.symptom_script_dir, script_name)
        with open(path, "w", encoding="utf-8") as symptom_script:
            symptom_script.write(content)

    def test_format_filesize(self) -> None:
        """format_filesize()"""
        ui = UserInterfaceMock()
        locale_numeric = locale.getlocale(locale.LC_NUMERIC)
        locale.setlocale(locale.LC_NUMERIC, "C")
        try:
            self.assertEqual(ui.format_filesize(0), "0.0 KB")
            self.assertEqual(ui.format_filesize(2048), "2.0 KB")
            self.assertEqual(ui.format_filesize(2560), "2.6 KB")
            self.assertEqual(ui.format_filesize(999999), "1000.0 KB")
            self.assertEqual(ui.format_filesize(1000000), "1.0 MB")
            self.assertEqual(ui.format_filesize(2_700_000), "2.7 MB")
            self.assertEqual(ui.format_filesize(1_024_000_000), "1.0 GB")
            self.assertEqual(ui.format_filesize(2_560_000_000), "2.6 GB")
        finally:
            locale.setlocale(locale.LC_NUMERIC, locale_numeric)

    def test_get_size_loaded(self) -> None:
        """get_complete_size() and get_reduced_size() for loaded Reports"""
        ui = UserInterfaceMock()
        ui.load_report(self.report_file.name)

        fsize = os.path.getsize(self.report_file.name)
        complete_ratio = float(ui.get_complete_size()) / fsize
        self.assertAlmostEqual(complete_ratio, 1.0, delta=0.1)

        rs = ui.get_reduced_size()
        self.assertTrue(rs > 1000)
        self.assertTrue(rs < 10000)

        # now add some information (e. g. from package hooks)
        assert ui.report
        ui.report["ExtraInfo"] = "A" * 50000
        s = ui.get_complete_size()
        self.assertTrue(s >= fsize + 49900)
        self.assertTrue(s < fsize + 60000)

        rs = ui.get_reduced_size()
        self.assertTrue(rs > 51000)
        self.assertTrue(rs < 60000)

    def test_get_size_constructed(self) -> None:
        """get_complete_size() and get_reduced_size() for on-the-fly Reports"""
        ui = UserInterfaceMock()
        ui.report = apport.Report("Bug")
        ui.report["Hello"] = "World"

        s = ui.get_complete_size()
        self.assertTrue(s > 5)
        self.assertTrue(s < 100)

        self.assertEqual(s, ui.get_reduced_size())

    def test_load_report(self) -> None:
        """load_report()"""
        ui = UserInterfaceMock()
        # valid report
        ui.load_report(self.report_file.name)
        assert ui.report
        self.assertEqual(set(ui.report.keys()), set(self.report.keys()))
        self.assertEqual(ui.report["Package"], self.report["Package"])
        self.assertEqual(
            ui.report["CoreDump"].get_value(), self.report["CoreDump"].get_value()
        )
        self.assertIsNone(ui.msg_title)

        ui.clear_msg()

        # invalid base64 encoding
        self.report_file.seek(0)
        self.report_file.truncate()
        self.report_file.write(
            textwrap.dedent(
                """\
                Type: test
                Package: foo 1-1
                CoreDump: base64
                bOgUs=
                """
            ).encode()
        )
        self.report_file.flush()

        ui.load_report(self.report_file.name)
        self.assertTrue(ui.report is None)
        self.assertEqual(ui.msg_title, _("Invalid problem report"))
        self.assertEqual(ui.msg_severity, "error")

    def test_restart(self) -> None:
        """restart()"""
        ui = UserInterfaceMock()
        # test with only ProcCmdline
        p = os.path.join(apport.fileutils.report_dir, "ProcCmdline")
        r = os.path.join(apport.fileutils.report_dir, "Custom")
        self.report["ProcCmdline"] = f"touch {p}"
        self.update_report_file()
        ui.load_report(self.report_file.name)

        ui.restart()
        time.sleep(1)  # FIXME: race condition
        self.assertTrue(os.path.exists(p))
        self.assertTrue(not os.path.exists(r))
        os.unlink(p)

        # test with RespawnCommand
        self.report["RespawnCommand"] = f"touch {r}"
        self.update_report_file()
        ui.load_report(self.report_file.name)

        ui.restart()
        time.sleep(1)  # FIXME: race condition
        self.assertTrue(not os.path.exists(p))
        self.assertTrue(os.path.exists(r))
        os.unlink(r)

        # test that invalid command does not make us fall apart
        del self.report["RespawnCommand"]
        self.report["ProcCmdline"] = "/nonexisting"
        self.update_report_file()
        ui.load_report(self.report_file.name)

    def test_collect_info_distro(self) -> None:
        """collect_info() on report without information (distro bug)"""
        ui = UserInterfaceMock()
        # report without any information (distro bug)
        ui.report = apport.Report("Bug")
        ui.collect_info()
        self.assertTrue(
            set(["Date", "Uname", "DistroRelease", "ProblemType"]).issubset(
                set(ui.report.keys())
            )
        )
        self.assertEqual(
            ui.ic_progress_pulses,
            0,
            "no progress dialog for distro bug info collection",
        )

    def test_collect_info_exepath(self) -> None:
        """collect_info() on report with only ExecutablePath"""
        ui = UserInterfaceMock()
        # report with only package information
        self.report = apport.Report("Bug")
        self.report["ExecutablePath"] = "/bin/bash"
        self.update_report_file()
        ui.load_report(self.report_file.name)
        # add some tuple values, for robustness testing (might be added by
        # apport hooks)
        assert ui.report
        ui.report["Fstab"] = ("/etc/fstab", True)
        ui.report["CompressedValue"] = problem_report.CompressedValue(b"Test")
        ui.collect_info()
        self.assertTrue(
            set(
                [
                    "SourcePackage",
                    "Package",
                    "ProblemType",
                    "Uname",
                    "Dependencies",
                    "DistroRelease",
                    "Date",
                    "ExecutablePath",
                ]
            ).issubset(set(ui.report.keys()))
        )
        self.assertTrue(
            ui.ic_progress_pulses > 0, "progress dialog for package bug info collection"
        )
        self.assertEqual(
            ui.ic_progress_active,
            False,
            "progress dialog for package bug info collection finished",
        )

    def test_collect_info_package(self) -> None:
        """collect_info() on report with a package"""
        ui = UserInterfaceMock()
        # report with only package information
        ui.report = apport.Report("Bug")
        ui.cur_package = "bash"

        def search_bug_patterns(url: str) -> str | None:
            progress_pulses = ui.ic_progress_pulses
            # wait for ui_pulse_info_collection_progress() call
            while ui.ic_progress_pulses == progress_pulses:
                time.sleep(0.01)
            assert ui.report
            return apport.report.Report.search_bug_patterns(ui.report, url)

        with unittest.mock.patch.object(
            ui.report, "search_bug_patterns", side_effect=search_bug_patterns
        ) as search_bug_patterns_mock:
            ui.collect_info()

        search_bug_patterns_mock.assert_called_once()
        self.assertTrue(
            set(
                [
                    "SourcePackage",
                    "Package",
                    "ProblemType",
                    "Uname",
                    "Dependencies",
                    "DistroRelease",
                    "Date",
                ]
            ).issubset(set(ui.report.keys()))
        )
        self.assertTrue(
            ui.ic_progress_pulses > 0, "progress dialog for package bug info collection"
        )
        self.assertEqual(
            ui.ic_progress_active,
            False,
            "progress dialog for package bug info collection finished",
        )

    def test_collect_info_permissions(self) -> None:
        """collect_info() leaves the report accessible to the group"""
        ui = UserInterfaceMock()
        ui.report = apport.Report("Bug")
        ui.cur_package = "bash"
        ui.report_file = self.report_file.name
        ui.collect_info()
        self.assertTrue(os.stat(self.report_file.name).st_mode & stat.S_IRGRP)

    def _write_crashdb_config_hook(
        self, crashdb: str, bash_hook: str | None = None
    ) -> None:
        """Write source_bash.py hook that sets CrashDB"""
        with open(
            os.path.join(self.hookdir, "source_bash.py"), "w", encoding="utf-8"
        ) as f:
            f.write(
                textwrap.dedent(
                    f'''\
                    def add_info(report, ui):
                        report['CrashDB'] = """{crashdb}"""
                    '''
                )
            )
            if bash_hook:
                f.write(f"    report['BashHook'] = '{bash_hook}'\n")

    def test_collect_info_crashdb_spec(self) -> None:
        """collect_info() with package hook that defines a CrashDB"""
        ui = UserInterfaceMock()
        self._write_crashdb_config_hook("{ 'impl': 'memory', 'local_opt': '1' }", "Moo")
        ui.report = apport.Report("Bug")
        ui.cur_package = "bash"
        ui.collect_info()
        self.assertIn("CrashDB", ui.report)
        self.assertNotIn("UnreportableReason", ui.report)
        self.assertEqual(ui.report["BashHook"], "Moo")
        self.assertEqual(ui.crashdb.options["local_opt"], "1")

    def test_collect_info_crashdb_name(self) -> None:
        """collect_info() with package hook that chooses a different CrashDB"""
        ui = UserInterfaceMock()
        self._write_crashdb_config_hook("debug", "Moo")
        ui.report = apport.Report("Bug")
        ui.cur_package = "bash"
        ui.collect_info()
        self.assertNotIn("UnreportableReason", ui.report)
        self.assertEqual(ui.report["BashHook"], "Moo")
        self.assertEqual(ui.crashdb.options["distro"], "debug")

    def test_collect_info_crashdb_errors(self) -> None:
        """collect_info() with package hook setting a broken CrashDB field"""
        ui = UserInterfaceMock()
        # nonexisting implementation
        self._write_crashdb_config_hook("{ 'impl': 'nonexisting', 'local_opt': '1' }")
        ui.report = apport.Report("Bug")
        ui.cur_package = "bash"
        ui.collect_info()
        self.assertIn("nonexisting", ui.report["UnreportableReason"])

        # invalid syntax
        self._write_crashdb_config_hook("{ 'impl': 'memory', 'local_opt'")
        ui.report = apport.Report("Bug")
        ui.cur_package = "bash"
        ui.collect_info()
        self.assertIn("package hook", ui.report["UnreportableReason"])

        # nonexisting name
        self._write_crashdb_config_hook("nonexisting")
        ui.report = apport.Report("Bug")
        ui.cur_package = "bash"
        ui.collect_info()
        self.assertIn("nonexisting", ui.report["UnreportableReason"])

        # string with unsafe contents
        self._write_crashdb_config_hook(
            """{'impl': 'memory',"""
            """ 'trap': exec('open("/tmp/pwned", "w").close()')}"""
        )
        ui.report = apport.Report("Bug")
        ui.cur_package = "bash"
        ui.collect_info()
        self.assertIn("package hook", ui.report["UnreportableReason"])
        self.assertFalse(os.path.exists("/tmp/pwned"))

    def test_handle_duplicate(self) -> None:
        """handle_duplicate()"""
        ui = UserInterfaceMock()
        ui.load_report(self.report_file.name)
        self.assertEqual(ui.handle_duplicate(), False)
        self.assertIsNone(ui.msg_title)
        self.assertIsNone(ui.opened_url)

        demo_url = "http://example.com/1"
        self.report["_KnownReport"] = demo_url
        self.update_report_file()
        ui.load_report(self.report_file.name)
        self.assertEqual(ui.handle_duplicate(), True)
        self.assertEqual(ui.msg_severity, "info")
        self.assertEqual(ui.opened_url, demo_url)

        ui.opened_url = None
        demo_url = "http://example.com/1"
        self.report["_KnownReport"] = "1"
        self.update_report_file()
        ui.load_report(self.report_file.name)
        self.assertEqual(ui.handle_duplicate(), True)
        self.assertEqual(ui.msg_severity, "info")
        self.assertIsNone(ui.opened_url)

    def test_run_nopending(self) -> None:
        """Run the frontend without any pending reports."""
        ui = UserInterfaceMock()
        self.assertEqual(ui.run_argv(), False)

    def test_run_restart(self) -> None:
        """Running the frontend with pending reports offers restart."""
        r = self._gen_test_crash()
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")
        with open(report_file, "wb") as f:
            r.write(f)
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action()
        ui.run_argv()
        self.assertEqual(ui.offer_restart, True)

    def test_run_report_bug_noargs(self) -> None:
        """run_report_bug() without specifying arguments"""
        ui = UserInterfaceMock(["ui-test", "-f"])
        self.assertEqual(ui.run_argv(), False)
        self.assertEqual(ui.msg_severity, "error")

    @unittest.mock.patch("sys.stdout", new_callable=io.StringIO)
    def test_run_version(self, stdout_mock: MagicMock) -> None:
        """run_report_bug() as "ubuntu-bug" with version argument"""
        ui = UserInterfaceMock(["ubuntu-bug", "-v"])
        self.assertEqual(ui.run_argv(), True)
        self.assertEqual(stdout_mock.getvalue(), f"{apport.ui.__version__}\n")

    def test_file_report_nodelay(self) -> None:
        """file_report() happy path without polling"""
        ui = UserInterfaceMock()
        ui.report = self.report
        previous_id = ui.crashdb.latest_id()
        ui.file_report()
        self.assertNotEqual(ui.crashdb.latest_id(), previous_id)
        self.assertIsNone(ui.msg_severity)
        self.assertIsNone(ui.msg_title)
        self.assertIsNone(ui.msg_text)

    def test_file_report_upload_delay(self) -> None:
        """file_report() with some polling during upload"""
        ui = UserInterfaceMock()
        ui.report = self.report
        ui.crashdb.upload_delay = 0.2  # Arbitrary value
        previous_id = ui.crashdb.latest_id()
        ui.file_report()
        self.assertNotEqual(ui.crashdb.latest_id(), previous_id)
        self.assertIsNone(ui.msg_severity)
        self.assertIsNone(ui.msg_title)
        self.assertIsNone(ui.msg_text)

    def test_file_report_upload_message(self) -> None:
        """file_report() with a message to the user"""
        ui = UserInterfaceMock()
        ui.report = self.report
        ui.crashdb.upload_msg = ("test title", "test content")
        previous_id = ui.crashdb.latest_id()
        ui.file_report()
        self.assertNotEqual(ui.crashdb.latest_id(), previous_id)
        self.assertEqual(ui.msg_severity, "info")
        self.assertEqual(ui.msg_title, "test title")
        self.assertEqual(ui.msg_text, "test content")

    def test_file_report_http_error(self) -> None:
        """file_report() fails with HTTPError."""
        ui = UserInterfaceMock()
        ui.report = self.report
        with unittest.mock.patch.object(ui.crashdb, "upload") as upload_mock:
            # False positive for hdrs in urllib.error.HTTPError
            # See https://github.com/python/typeshed/issues/10092
            upload_mock.side_effect = urllib.error.HTTPError(
                "https://example.com/", 502, "Bad Gateway", {}, fp=None  # type: ignore
            )
            ui.file_report()
        self.assertEqual(ui.msg_severity, "error")
        self.assertEqual(ui.msg_title, "Network problem")
        self.assertEqual(
            ui.msg_text,
            "Cannot connect to crash database, please check your Internet"
            " connection.\n\nHTTP Error 502: Bad Gateway",
        )

    def test_run_report_bug_package(self) -> None:
        """run_report_bug() for a package"""
        ui = UserInterfaceMock(["ui-test", "-f", "-p", "bash"])
        ui.present_details_response = apport.ui.Action(report=True)
        self.assertEqual(ui.run_argv(), True)

        self.assertIsNone(ui.msg_severity)
        self.assertIsNone(ui.msg_title)
        self.assertTrue(ui.present_details_shown)
        self.assertEqual(
            ui.opened_url, f"http://bash.bugs.example.com/{ui.crashdb.latest_id()}"
        )

        assert ui.report
        self.assertTrue(ui.ic_progress_pulses > 0)
        self.assertEqual(ui.report["SourcePackage"], "bash")
        self.assertIn("Dependencies", ui.report)
        self.assertIn("ProcEnviron", ui.report)
        self.assertEqual(ui.report["ProblemType"], "Bug")

        # should not crash on nonexisting package
        argv = ["ui-test", "-f", "-p", "nonexisting_gibberish"]
        ui = UserInterfaceMock(argv)
        try:
            ui.run_argv()
        except SystemExit:
            pass

        self.assertEqual(ui.msg_severity, "error")

    def test_run_report_bug_pid_tags(self) -> None:
        """run_report_bug() for a pid with extra tags"""
        with run_test_executable() as pid:
            # report a bug on text executable process
            argv = ["ui-test", "-f", "--tag", "foo", "-P", str(pid)]
            ui = UserInterfaceMock(argv)
            ui.present_details_response = apport.ui.Action(report=True)
            self.assertEqual(ui.run_argv(), True)

        assert ui.report
        self.assertIn("SourcePackage", ui.report)
        self.assertIn("Dependencies", ui.report)
        self.assertIn("ProcMaps", ui.report)
        self.assertEqual(ui.report["ExecutablePath"], self.TEST_EXECUTABLE)
        self.assertNotIn("ProcCmdline", ui.report)  # privacy!
        self.assertIn("ProcEnviron", ui.report)
        self.assertEqual(ui.report["ProblemType"], "Bug")
        self.assertIn("foo", ui.report.get_tags())

        self.assertIsNone(ui.msg_severity)
        self.assertIsNone(ui.msg_title)
        self.assertEqual(
            ui.opened_url, f"http://coreutils.bugs.example.com/{ui.crashdb.latest_id()}"
        )
        self.assertTrue(ui.present_details_shown)
        self.assertTrue(ui.ic_progress_pulses > 0)

    @staticmethod
    def _find_unused_pid() -> int:
        """Find and return an unused PID."""
        pid = 1
        while True:
            pid += 1
            try:
                os.kill(pid, 0)
            except OSError as error:
                if error.errno == errno.ESRCH:
                    break
        return pid

    def test_run_report_bug_wrong_pid(self) -> None:
        """run_report_bug() for a nonexisting pid"""
        # silently ignore missing PID; this happens when the user closes
        # the application prematurely
        pid = self._find_unused_pid()
        ui = UserInterfaceMock(["ui-test", "-f", "-P", str(pid)])
        ui.run_argv()

    def test_run_report_bug_noperm_pid(self) -> None:
        """run_report_bug() for a pid which runs as a different user"""
        restore_root = False
        if os.getuid() == 0:
            # temporarily drop to normal user "mail"
            os.setresuid(8, 8, -1)
            restore_root = True

        try:
            ui = UserInterfaceMock(["ui-test", "-f", "-P", "1"])
            ui.run_argv()

            self.assertEqual(ui.msg_severity, "error")
        finally:
            if restore_root:
                os.setresuid(0, 0, -1)

    def test_run_report_bug_unpackaged_pid(self) -> None:
        """run_report_bug() for a pid of an unpackaged program"""
        # create unpackaged test program
        (fd, exename) = tempfile.mkstemp()
        with open(self.TEST_EXECUTABLE, "rb") as f:
            os.write(fd, f.read())
        os.close(fd)
        os.chmod(exename, 0o755)

        with run_test_executable([exename] + self.TEST_ARGS) as pid:
            ui = UserInterfaceMock(["ui-test", "-f", "-P", str(pid)])
            self.assertRaises(SystemExit, ui.run_argv)

        os.unlink(exename)
        self.assertEqual(ui.msg_severity, "error")

    def test_run_report_hanging(self) -> None:
        with run_test_executable() as pid:
            ui = UserInterfaceMock(["ui-test", "--hanging", str(pid)])
            ui.present_details_response = apport.ui.Action(report=True)
            self.assertTrue(ui.run_argv())

        assert ui.report
        for expected_key in (
            "ProblemType",
            "ExecutablePath",
            "Package",
            "SourcePackage",
        ):
            self.assertIn(expected_key, ui.report)
        self.assertEqual(ui.report["ProblemType"], "Hang")
        self.assertEqual(ui.report["ExecutablePath"], self.TEST_EXECUTABLE)
        self.assertIn(
            ui.report["Package"].split(" ")[0],
            {"coreutils", "gnu-coreutils", "rust-coreutils"},
        )
        self.assertIn(
            ui.report["SourcePackage"],
            {"busybox", "coreutils", "rust-coreutils", "toybox"},
        )

    @unittest.mock.patch("apport.packaging_impl.impl.get_version")
    def test_run_report_bug_kernel_thread(self, get_version_mock: MagicMock) -> None:
        """run_report_bug() for a pid of a kernel thread"""
        # The kernel package might not be installed in chroot environments.
        # Therefore mock get_version for the kernel package.
        get_version_mock.return_value = "5.15.0-33.34"

        for path in glob.glob("/proc/[0-9]*/stat"):
            with open(path, encoding="utf-8") as f:
                proc_stat = f.read().split()
            flags = int(proc_stat[8])
            if flags & apport.ui.PF_KTHREAD:
                pid = int(proc_stat[0])
                break
        else:
            self.skipTest("no kernel thread found")

        ui = UserInterfaceMock(["ui-test", "-f", "-P", str(pid)])
        ui.present_details_response = apport.ui.Action(report=True)
        ui.run_argv()
        assert ui.report

        kernel_package = packaging.get_kernel_package()
        self.assertEqual(
            ui.report["Package"], f"{kernel_package} {get_version_mock.return_value}"
        )
        get_version_mock.assert_any_call(kernel_package)

    def test_run_report_bug_file(self) -> None:
        """run_report_bug() with saving report into a file"""
        d = os.path.join(apport.fileutils.report_dir, "home")
        os.mkdir(d)
        reportfile = os.path.join(d, "bashisbad.apport")

        argv = ["ui-test", "-f", "-p", "bash", "--save", reportfile]
        ui = UserInterfaceMock(argv)
        self.assertEqual(ui.run_argv(), True)

        self.assertIsNone(ui.msg_severity)
        self.assertIsNone(ui.msg_title)
        self.assertIsNone(ui.opened_url)
        self.assertFalse(ui.present_details_shown)

        self.assertTrue(ui.ic_progress_pulses > 0)

        r = apport.Report()
        with open(reportfile, "rb") as f:
            r.load(f)

        self.assertEqual(r["SourcePackage"], "bash")
        self.assertIn("Dependencies", r)
        self.assertIn("ProcEnviron", r)
        self.assertEqual(r["ProblemType"], "Bug")

        # report it
        ui = UserInterfaceMock(["ui-test", "-c", reportfile])
        ui.present_details_response = apport.ui.Action(report=True)
        self.assertEqual(ui.run_argv(), True)

        self.assertIsNone(ui.msg_text)
        self.assertIsNone(ui.msg_severity)
        self.assertTrue(ui.present_details_shown)

    def _gen_test_crash(self) -> apport.Report:
        """Generate a Report with real crash data."""
        core_path = os.path.join(self.workdir, "core")
        try:
            with subprocess.Popen(
                [
                    "gdb",
                    "--batch",
                    "-iex",
                    "set debuginfod enable off",
                    "--ex",
                    f"run {' '.join(self.TEST_ARGS)}",
                    "--ex",
                    f"generate-core-file {core_path}",
                    self.TEST_EXECUTABLE,
                ],
                env={"HOME": self.workdir},
                stdout=subprocess.PIPE,
            ) as gdb:

                try:
                    pid = wait_for_process_to_appear(
                        self.TEST_EXECUTABLE,
                        self.running_test_executables,
                        timeout=10.0,
                    )
                    # generate crash report
                    r = apport.Report()
                    r["ExecutablePath"] = self.TEST_EXECUTABLE
                    r["Signal"] = "11"
                    r.add_proc_info(pid)
                    r.add_user_info()
                    r.add_os_info()
                    r.add_package_info()

                    # generate a core dump
                    os.kill(pid, signal.SIGSEGV)
                    os.waitpid(gdb.pid, 0)
                    assert os.path.exists(core_path)
                    r["CoreDump"] = (core_path,)
                finally:
                    gdb.kill()
        except FileNotFoundError as error:
            self.skipTest(f"{error.filename} not available")
        return r

    def test_run_crash(self) -> None:
        """run_crash()"""
        r = self._gen_test_crash()

        # write crash report
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")

        # cancel crash notification dialog
        with open(report_file, "wb") as f:
            r.write(f)
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action()
        ui.run_crash(report_file)
        self.assertIsNone(ui.msg_severity)
        self.assertIsNone(ui.msg_title)
        self.assertIsNone(ui.opened_url)
        self.assertEqual(ui.ic_progress_pulses, 0)
        self.assertEqual(ui.offer_restart, False)

        # report in crash notification dialog, send full report
        with open(report_file, "wb") as f:
            r.write(f)
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action(report=True)
        ui.run_crash(report_file)
        self.assertIsNone(ui.msg_severity, ui.msg_text)
        self.assertIsNone(ui.msg_title)
        self.assertEqual(
            ui.opened_url, f"http://coreutils.bugs.example.com/{ui.crashdb.latest_id()}"
        )
        self.assertFalse(ui.ic_progress_active)
        self.assertNotEqual(ui.ic_progress_pulses, 0)
        self.assertTrue(ui.present_details_shown)

        assert ui.report
        self.assertIn("SourcePackage", ui.report)
        self.assertIn("Dependencies", ui.report)
        self.assertIn("Stacktrace", ui.report)
        self.assertIn("ProcEnviron", ui.report)
        self.assertNotIn("ExecutableTimestamp", ui.report)
        self.assertNotIn("StacktraceAddressSignature", ui.report)
        self.assertEqual(ui.report["ProblemType"], "Crash")
        self.assertTrue(len(ui.report["CoreDump"]) > 10000)
        self.assertTrue(
            ui.report["Title"].startswith(
                f"{os.path.basename(self.TEST_EXECUTABLE)} crashed with SIGSEGV"
            )
        )

        # so far we did not ignorelist, verify that
        self.assertTrue(not ui.report.check_ignored())

        # cancel crash notification dialog and ignorelist
        with open(report_file, "wb") as f:
            r.write(f)
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action(ignore=True)
        ui.run_crash(report_file)
        self.assertIsNone(ui.msg_severity)
        self.assertIsNone(ui.msg_title)
        self.assertIsNone(ui.opened_url)
        self.assertEqual(ui.ic_progress_pulses, 0)

        assert ui.report
        self.assertTrue(ui.report.check_ignored())
        self.assertEqual(ui.offer_restart, False)

    def test_run_crash_abort(self) -> None:
        """run_crash() for an abort() without assertion message"""
        ui = UserInterfaceMock()
        r = self._gen_test_crash()
        r["Signal"] = "6"
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")
        with open(report_file, "wb") as f:
            r.write(f)

        ui.present_details_response = apport.ui.Action(report=True)
        ui.run_crash(report_file)
        self.assertIsNone(ui.msg_severity, ui.msg_text)

        assert ui.report
        self.assertIn("SourcePackage", ui.report)
        self.assertIn("Dependencies", ui.report)
        self.assertIn("Stacktrace", ui.report)
        self.assertIn("ProcEnviron", ui.report)
        self.assertNotIn("ExecutableTimestamp", ui.report)
        self.assertEqual(ui.report["Signal"], "6")

        # we disable the ABRT filtering, we want these crashes after all
        # self.assertIn('assert', ui.msg_text, '%s: %s' %
        #     (ui.msg_title, ui.msg_text))
        # self.assertEqual(ui.msg_severity, 'info')
        self.assertIsNone(ui.msg_severity)
        self.assertTrue(ui.present_details_shown)

    @skip_if_command_is_missing("gdb")
    def test_run_crash_broken(self) -> None:
        """run_crash() for an invalid core dump"""
        ui = UserInterfaceMock()
        # generate broken crash report
        r = apport.Report()
        r["ExecutablePath"] = self.TEST_EXECUTABLE
        r["Signal"] = "11"
        r["CoreDump"] = problem_report.CompressedValue(compressed_value=b"AAAAAAAA")
        r.add_user_info()

        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")
        with open(report_file, "wb") as f:
            r.write(f)

        ui.present_details_response = apport.ui.Action(report=True)
        ui.run_crash(report_file)
        self.assertEqual(ui.msg_severity, "info", ui.msg_text)
        assert ui.msg_text is not None
        self.assertIn("decompress", ui.msg_text)
        self.assertTrue(ui.present_details_shown)

    @unittest.mock.patch("apport.report.Report.add_gdb_info", MagicMock())
    @unittest.mock.patch("apport.hookutils.attach_conffiles", MagicMock())
    def test_run_crash_argv_file(self) -> None:
        """run_crash() through a file specified on the command line"""
        # valid
        self.report["Package"] = "bash"
        self.update_report_file()

        argv = ["ui-test", "-c", self.report_file.name]
        ui = UserInterfaceMock(argv)
        ui.present_details_response = apport.ui.Action(report=True)

        self.assertEqual(ui.run_argv(), True)

        self.assertIsNone(ui.msg_text)
        self.assertIsNone(ui.msg_severity)
        self.assertTrue(ui.present_details_shown)

        # unreportable
        self.report["Package"] = "bash"
        self.report["UnreportableReason"] = b"It stinks. \xe2\x99\xa5".decode("UTF-8")
        self.update_report_file()

        argv = ["ui-test", "-c", self.report_file.name]
        ui = UserInterfaceMock(argv)
        ui.present_details_response = apport.ui.Action(report=True)
        self.assertEqual(ui.run_argv(), True)

        assert ui.msg_text is not None
        self.assertIn("It stinks.", ui.msg_text, f"{ui.msg_title}: {ui.msg_text}")
        self.assertEqual(ui.msg_severity, "info")

        # should not die with an exception on an invalid name
        argv = ["ui-test", "-c", "/nonexisting.crash"]
        ui = UserInterfaceMock(argv)
        self.assertEqual(ui.run_argv(), True)
        self.assertEqual(ui.msg_severity, "error")

    @unittest.mock.patch("apport.report.Report.add_gdb_info", MagicMock())
    def test_run_crash_unreportable(self) -> None:
        """run_crash() on a crash with the UnreportableReason field"""
        ui = UserInterfaceMock()
        self.report["UnreportableReason"] = "It stinks."
        self.report["ExecutablePath"] = "/bin/bash"
        self.report["Package"] = "bash 1"
        self.update_report_file()
        ui.present_details_response = apport.ui.Action(report=True)

        ui.run_crash(self.report_file.name)

        assert ui.msg_text is not None
        self.assertIn("It stinks.", ui.msg_text, f"{ui.msg_title}: {ui.msg_text}")
        self.assertEqual(ui.msg_severity, "info")

    @unittest.mock.patch("apport.report.Report.add_gdb_info", MagicMock())
    def test_run_crash_malicious_crashdb(self) -> None:
        """run_crash() on a crash with malicious CrashDB"""
        ui = UserInterfaceMock()
        self.report["ExecutablePath"] = "/bin/bash"
        self.report["Package"] = "bash 1"
        self.report["CrashDB"] = (
            "{'impl': 'memory', 'crash_config': open('/tmp/pwned', 'w').close()}"
        )
        self.update_report_file()
        ui.present_details_response = apport.ui.Action(report=True)

        ui.run_crash(self.report_file.name)

        self.assertFalse(os.path.exists("/tmp/pwned"))
        assert ui.msg_text is not None
        self.assertIn("invalid crash database definition", ui.msg_text)

    @unittest.mock.patch("apport.report.Report.add_gdb_info", MagicMock())
    def test_run_crash_malicious_package(self) -> None:
        """Package: path traversal"""
        ui = UserInterfaceMock()
        with tempfile.NamedTemporaryFile(suffix=".py") as bad_hook:
            bad_hook.write(b"def add_info(r, u):\n  open('/tmp/pwned', 'w').close()")
            bad_hook.flush()

            self.report["ExecutablePath"] = "/bin/bash"
            self.report["Package"] = "../" * 20 + os.path.splitext(bad_hook.name)[0]
            self.update_report_file()
            ui.present_details_response = apport.ui.Action(report=True)

            ui.run_crash(self.report_file.name)

            self.assertFalse(os.path.exists("/tmp/pwned"))
            assert ui.msg_text is not None
            self.assertIn("invalid Package:", ui.msg_text)

    def test_run_crash_malicious_exec_path(self) -> None:
        """ExecutablePath: path traversal"""
        ui = UserInterfaceMock()
        hook_dir = "/tmp/share/apport/package-hooks"
        os.makedirs(hook_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=hook_dir, suffix=".py") as bad_hook:
            bad_hook.write(b"def add_info(r, u):\n  open('/tmp/pwned', 'w').close()")
            bad_hook.flush()

            self.report["ExecutablePath"] = f"/opt/../{hook_dir}"
            self.report["Package"] = os.path.splitext(bad_hook.name)[0].replace(
                hook_dir, ""
            )
            self.update_report_file()
            ui.present_details_response = apport.ui.Action(report=True)

            ui.run_crash(self.report_file.name)

            self.assertFalse(os.path.exists("/tmp/pwned"))

    def test_run_crash_ignore(self) -> None:
        """run_crash() on a crash with the Ignore field"""
        ui = UserInterfaceMock()
        self.report["Ignore"] = "True"
        self.report["ExecutablePath"] = "/bin/bash"
        self.report["Package"] = "bash 1"
        self.update_report_file()

        ui.run_crash(self.report_file.name)
        self.assertIsNone(ui.msg_severity)

    def test_run_crash_nocore(self) -> None:
        """run_crash() for a crash dump without CoreDump"""
        # create a test executable
        with run_test_executable() as pid:
            # generate crash report
            r = apport.Report()
            r["ExecutablePath"] = self.TEST_EXECUTABLE
            r["Signal"] = "42"
            r.add_proc_info(pid)
            r.add_user_info()

        # write crash report
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")
        with open(report_file, "wb") as f:
            r.write(f)

        # run
        ui = UserInterfaceMock()
        ui.run_crash(report_file)
        self.assertEqual(ui.msg_severity, "error")
        assert ui.msg_text is not None
        self.assertIn("memory", ui.msg_text, f"{ui.msg_title}: {ui.msg_text}")

    def test_run_crash_preretraced(self) -> None:
        """run_crash() pre-retraced reports.

        This happens with crashes which are pre-processed by
        apport-retrace.
        """
        r = self._gen_test_crash()

        #  effect of apport-retrace -c
        r.add_gdb_info()
        del r["CoreDump"]

        # write crash report
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")

        # report in crash notification dialog, cancel details report
        with open(report_file, "wb") as f:
            r.write(f)
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action()
        ui.run_crash(report_file)
        self.assertEqual(
            ui.msg_severity,
            None,
            f"has {ui.msg_severity} message:" f" {ui.msg_title}: {ui.msg_text}",
        )
        self.assertIsNone(ui.msg_title)
        self.assertTrue(ui.present_details_shown)

    def test_run_crash_precollected(self) -> None:
        """run_crash() on complete report on uninstalled package

        This happens when reporting a problem from a different machine through
        copying a .crash file.
        """
        ui = UserInterfaceMock()
        ui.report = self._gen_test_crash()
        ui.collect_info()

        # now pretend to move it to a machine where the package is not
        # installed
        ui.report["Package"] = "uninstalled_pkg 1"
        ui.report["ExecutablePath"] = "/usr/bin/uninstalled_program"
        ui.report["InterpreterPath"] = "/usr/bin/uninstalled_interpreter"

        # write crash report
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")
        with open(report_file, "wb") as f:
            ui.report.write(f)

        # report it
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action(report=True)
        ui.run_crash(report_file)
        self.assertEqual(ui.cur_package, "uninstalled_pkg")
        self.assertEqual(
            ui.msg_severity,
            None,
            f"has {ui.msg_severity} message:" f" {ui.msg_title}: {ui.msg_text}",
        )
        assert ui.opened_url is not None
        self.assertTrue(ui.opened_url.startswith("http://coreutils.bugs.example.com"))
        self.assertTrue(ui.present_details_shown)

    def test_run_crash_errors(self) -> None:
        """run_crash() on various error conditions"""
        ui = UserInterfaceMock()
        # crash report with invalid Package name
        r = apport.Report()
        r["ExecutablePath"] = "/bin/bash"
        r["Package"] = "foobarbaz"
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")
        with open(report_file, "wb") as f:
            r.write(f)

        ui.present_details_response = apport.ui.Action(report=True)
        self.assertRaises(SystemExit, ui.run_crash, report_file)

        self.assertEqual(ui.msg_title, _("Invalid problem report"))
        self.assertEqual(ui.msg_severity, "error")

    def test_run_crash_uninstalled(self) -> None:
        """run_crash() on reports with subsequently uninstalled packages"""
        ui = UserInterfaceMock()
        # program got uninstalled between crash and report
        r = self._gen_test_crash()
        r["ExecutablePath"] = "/bin/nonexisting"
        r["Package"] = "bash"
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")
        with open(report_file, "wb") as f:
            r.write(f)

        ui.present_details_response = apport.ui.Action(report=True)
        ui.run_crash(report_file)

        self.assertEqual(ui.msg_title, _("Problem in bash"))
        assert ui.msg_text is not None
        self.assertIn("not installed any more", ui.msg_text)

        # interpreted program got uninstalled between crash and report
        r = apport.Report()
        r["ExecutablePath"] = "/bin/nonexisting"
        r["InterpreterPath"] = "/usr/bin/python"
        r["Traceback"] = "ZeroDivisionError: integer division or modulo by zero"

        ui.run_crash(report_file)

        self.assertEqual(ui.msg_title, _("Problem in bash"))
        assert ui.msg_text is not None
        self.assertIn("not installed any more", ui.msg_text)

        # interpreter got uninstalled between crash and report
        r = apport.Report()
        r["ExecutablePath"] = "/bin/sh"
        r["InterpreterPath"] = "/usr/bin/nonexisting"
        r["Traceback"] = "ZeroDivisionError: integer division or modulo by zero"

        ui.run_crash(report_file)

        self.assertEqual(ui.msg_title, _("Problem in bash"))
        assert ui.msg_text is not None
        self.assertIn("not installed any more", ui.msg_text)

    def test_run_crash_updated_binary(self) -> None:
        """run_crash() on binary that got updated in the meantime"""
        ui = UserInterfaceMock()
        r = self._gen_test_crash()
        r["ExecutableTimestamp"] = str(int(r["ExecutableTimestamp"]) - 10)
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")
        with open(report_file, "wb") as f:
            r.write(f)

        ui.present_details_response = apport.ui.Action(report=True)
        ui.run_crash(report_file)

        assert ui.report
        self.assertNotIn("ExecutableTimestamp", ui.report)
        assert ui.msg_text is not None
        self.assertIn(
            ui.report["ExecutablePath"], ui.msg_text, f"{ui.msg_title}: {ui.msg_text}"
        )
        self.assertIn("changed", ui.msg_text, f"{ui.msg_title}: {ui.msg_text}")
        self.assertEqual(ui.msg_severity, "info")

    def test_run_crash_package(self) -> None:
        """run_crash() for a package error"""
        # generate crash report
        r = apport.Report("Package")
        r["Package"] = "bash"
        r["SourcePackage"] = "bash"
        r["ErrorMessage"] = "It broke"
        r["VarLogPackagerlog"] = "foo\nbar"
        r.add_os_info()

        # write crash report
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")

        # cancel crash notification dialog
        with open(report_file, "wb") as f:
            r.write(f)
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action()
        ui.run_crash(report_file)
        self.assertIsNone(ui.msg_severity)
        self.assertIsNone(ui.msg_title)
        self.assertIsNone(ui.opened_url)
        self.assertEqual(ui.ic_progress_pulses, 0)
        self.assertTrue(ui.present_details_shown)

        # report in crash notification dialog, send report
        with open(report_file, "wb") as f:
            r.write(f)
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action(report=True)
        ui.run_crash(report_file)
        self.assertIsNone(ui.msg_severity)
        self.assertIsNone(ui.msg_title)
        self.assertEqual(
            ui.opened_url, f"http://bash.bugs.example.com/{ui.crashdb.latest_id()}"
        )
        self.assertTrue(ui.present_details_shown)

        assert ui.report
        self.assertIn("SourcePackage", ui.report)
        self.assertIn("Package", ui.report)
        self.assertEqual(ui.report["ProblemType"], "Package")

        # verify that additional information has been collected
        self.assertIn("Architecture", ui.report)
        self.assertIn("DistroRelease", ui.report)
        self.assertIn("Uname", ui.report)

    def test_run_crash_kernel(self) -> None:
        """run_crash() for a kernel error"""
        package = packaging.get_kernel_package()
        try:
            src_pkg = packaging.get_source(package)
        except ValueError:
            # Kernel package not installed (e.g. in container)
            src_pkg = "linux"

        # set up hook
        with open(
            os.path.join(self.hookdir, f"source_{src_pkg}.py"), "w", encoding="utf-8"
        ) as hook:
            hook.write(
                textwrap.dedent(
                    """\
                    def add_info(report, ui):
                        report['KernelDebug'] = 'LotsMoreInfo'
                    """
                )
            )

        # generate crash report
        r = apport.Report("KernelCrash")
        r["Package"] = package
        r["SourcePackage"] = src_pkg

        # write crash report
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")

        # cancel crash notification dialog
        with open(report_file, "wb") as f:
            r.write(f)
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action()
        ui.run_crash(report_file)
        self.assertEqual(
            ui.msg_severity, None, f"error: {ui.msg_title} - {ui.msg_text}"
        )
        self.assertIsNone(ui.msg_title)
        self.assertIsNone(ui.opened_url)
        self.assertEqual(ui.ic_progress_pulses, 0)
        self.assertTrue(ui.present_details_shown)

        # report in crash notification dialog, send report
        with open(report_file, "wb") as f:
            r.write(f)
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action(report=True)
        ui.run_crash(report_file)
        self.assertEqual(
            ui.msg_severity, None, f"{str(ui.msg_title)} {str(ui.msg_text)}"
        )
        self.assertIsNone(ui.msg_title)
        self.assertEqual(
            ui.opened_url, f"http://{src_pkg}.bugs.example.com/{ui.crashdb.latest_id()}"
        )
        self.assertTrue(ui.present_details_shown)

        assert ui.report
        self.assertIn("SourcePackage", ui.report)
        # did we run the hooks properly?
        self.assertIn("KernelDebug", ui.report)
        self.assertEqual(ui.report["ProblemType"], "KernelCrash")

    @staticmethod
    def _get_sensitive_strings() -> list[str]:
        p = pwd.getpwuid(os.getuid())
        sensitive_strings = [
            os.uname().nodename,
            p.pw_name,
            p.pw_gecos.split(",")[0],
            p.pw_dir,
            os.getcwd(),
        ]
        return [s for s in sensitive_strings if s]

    def test_run_crash_anonymity(self) -> None:
        """run_crash() anonymization"""
        r = self._gen_test_crash()
        utf8_val = b"\xc3\xa4 " + os.uname()[1].encode("UTF-8") + b" \xe2\x99\xa5 "
        r["ProcUnicodeValue"] = utf8_val.decode("UTF-8")
        r["ProcByteArrayValue"] = utf8_val
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")
        with open(report_file, "wb") as f:
            r.write(f)
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action(report=True)
        ui.run_crash(report_file)
        self.assertIsNone(ui.msg_severity, ui.msg_text)

        assert ui.report
        self.assertNotIn("ProcCwd", ui.report)

        dump = io.BytesIO()
        # this contains more or less random characters which might contain the
        # user name
        del ui.report["CoreDump"]
        ui.report.write(dump)
        report = dump.getvalue().decode("UTF-8")

        sensitive_strings = self._get_sensitive_strings()

        # In some environment the UID is just a generic name, e.g. buildd, that
        # tends to also be used in image names and the likes.
        build_name = ui.report.get("CloudBuildName", "")
        for s in sensitive_strings:
            if s in build_name:  # pragma: no cover
                self.skipTest("Environment too generic for the test to be meaningful.")

        for s in sensitive_strings:
            self.assertIsNone(
                re.search(rf"\b{re.escape(s)}\b", report),
                f"dump contains sensitive word '{s}':\n{report}",
            )
            if s == "ubuntu" or len(s) < 5 and "/" not in s:
                continue
            self.assertNotIn(
                s, report, f"dump contains sensitive string: {s}:\n{report}"
            )

    @unittest.mock.patch("apport.report.Report.add_gdb_info", autospec=True)
    def test_run_crash_anonymity_order(self, add_gdb_info_mock: MagicMock) -> None:
        """run_crash() anonymization runs after info and duplicate
        collection"""
        # pretend the hostname looks like a hex number which matches
        # the stack trace address
        uname = os.uname()
        uname_mock = os.uname_result(
            (uname[0], "0xDEADBEEF", uname[2], uname[3], uname[4])
        )

        def fake_add_gdb_info(self: apport.report.Report) -> None:
            self["Stacktrace"] = textwrap.dedent(
                """\
                #0  0xDEADBEEF in h (p=0x0) at crash.c:25
                #1  0x10000042 in g (x=1, y=42) at crash.c:26
                #1  0x10000001 in main () at crash.c:40
                """
            )
            self["ProcMaps"] = (
                "10000000-DEADBEF0 r-xp 00000000 08:02 100000           /bin/crash\n"
            )
            assert self.crash_signature_addresses() is not None

        add_gdb_info_mock.side_effect = fake_add_gdb_info
        with unittest.mock.patch("os.uname", return_value=uname_mock):
            r = self._gen_test_crash()
            r["ProcAuxInfo"] = "my 0xDEADBEEF"
            report_file = os.path.join(apport.fileutils.report_dir, "test.crash")
            with open(report_file, "wb") as f:
                r.write(f)

            # if this runs anonymization before the duplicate signature, then
            # this will fail, as 0xDEADhostname is an invalid address
            ui = UserInterfaceMock()
            ui.present_details_response = apport.ui.Action(report=True)
            ui.run_crash(report_file)
            self.assertIsNone(ui.msg_severity, ui.msg_text)

            assert ui.report
            self.assertEqual(ui.report["ProcAuxInfo"], "my hostname")
            # after anonymization this should mess up Stacktrace; this mostly
            # confirms that our test logic works
            self.assertIsNone(ui.report.crash_signature_addresses())
        add_gdb_info_mock.assert_called_once()

    def test_run_crash_anonymity_substring(self) -> None:
        """run_crash() anonymization only catches whole words"""
        # pretend the hostname is "ed", a substring of e. g. "crashed"
        uname = os.uname()
        uname_mock = os.uname_result((uname[0], "ed", uname[2], uname[3], uname[4]))
        with unittest.mock.patch("os.uname", return_value=uname_mock):
            r = self._gen_test_crash()
            r["ProcInfo1"] = "my ed"
            r["ProcInfo2"] = '"ed.localnet"'
            r["ProcInfo3"] = "education"
            report_file = os.path.join(apport.fileutils.report_dir, "test.crash")
            with open(report_file, "wb") as f:
                r.write(f)

            ui = UserInterfaceMock()
            ui.present_details_response = apport.ui.Action(report=True)
            ui.run_crash(report_file)
            self.assertIsNone(ui.msg_severity, ui.msg_text)

            assert ui.report
            self.assertTrue(
                ui.report["Title"].startswith(
                    f"{os.path.basename(self.TEST_EXECUTABLE)} crashed with SIGSEGV"
                ),
                ui.report["Title"],
            )
            self.assertEqual(ui.report["ProcInfo1"], "my hostname")
            self.assertEqual(ui.report["ProcInfo2"], '"hostname.localnet"')
            self.assertEqual(ui.report["ProcInfo3"], "education")

    def test_run_crash_anonymity_escaping(self) -> None:
        """run_crash() anonymization escapes special chars"""
        # inject GECOS field with regexp control chars
        orig_getpwuid = pwd.getpwuid
        orig_getuid = os.getuid

        def fake_getpwuid(_unused_uid: int) -> pwd.struct_passwd:
            r = list(orig_getpwuid(orig_getuid()))
            r[4] = "Joe (Hacker,+1 234,,"
            return pwd.struct_passwd(r)

        pwd.getpwuid = fake_getpwuid
        os.getuid = lambda: 1234

        try:
            r = self._gen_test_crash()
            r["ProcInfo1"] = "That was Joe (Hacker and friends"
            r["ProcInfo2"] = "Call +1 234!"
            r["ProcInfo3"] = "(Hacker should stay"
            report_file = os.path.join(apport.fileutils.report_dir, "test.crash")
            with open(report_file, "wb") as f:
                r.write(f)

            ui = UserInterfaceMock()
            ui.present_details_response = apport.ui.Action(report=True)
            ui.run_crash(report_file)
            self.assertIsNone(ui.msg_severity, ui.msg_text)

            assert ui.report
            self.assertEqual(ui.report["ProcInfo1"], "That was User Name and friends")
            self.assertEqual(ui.report["ProcInfo2"], "Call User Name!")
            self.assertEqual(ui.report["ProcInfo3"], "(Hacker should stay")
        finally:
            pwd.getpwuid = orig_getpwuid
            os.getuid = orig_getuid

    def test_run_crash_known(self) -> None:
        """run_crash() for already known problem"""
        r = self._gen_test_crash()
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action(report=True)

        # known without URL
        with open(report_file, "wb") as f:
            r.write(f)
        with patch.object(ui.crashdb, "known", return_value=True) as mock:
            ui.run_crash(report_file)
        mock.assert_called()
        assert ui.report
        self.assertEqual(ui.report["_KnownReport"], "1")
        self.assertEqual(ui.msg_severity, "info")
        self.assertIsNone(ui.opened_url)

        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action(report=True)
        # known with URL
        with open(report_file, "wb") as f:
            r.write(f)
        with patch.object(
            ui.crashdb, "known", return_value="http://myreport/1"
        ) as mock:
            ui.run_crash(report_file)
        mock.assert_called()
        assert ui.report
        self.assertEqual(ui.report["_KnownReport"], "http://myreport/1")
        self.assertEqual(ui.msg_severity, "info")
        self.assertEqual(ui.opened_url, "http://myreport/1")

    def test_run_crash_private_keys(self) -> None:
        """Do not upload private keys to crash DB."""
        r = self._gen_test_crash()
        r["_Temp"] = "boring"

        # write crash report
        report_file = os.path.join(apport.fileutils.report_dir, "test.crash")

        # report
        with open(report_file, "wb") as f:
            r.write(f)
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action(report=True)
        ui.run_crash(report_file)
        self.assertEqual(
            ui.opened_url, f"http://coreutils.bugs.example.com/{ui.crashdb.latest_id()}"
        )
        # internal key should not be uploaded to the crash db
        r = ui.crashdb.download(ui.crashdb.latest_id())
        self.assertIn("SourcePackage", r)
        self.assertNotIn("_Temp", r)

    def test_run_update_report_nonexisting_package_from_bug(self) -> None:
        """run_update_report() on a nonexisting package (from bug)"""
        ui = UserInterfaceMock(["ui-test", "-u", "1"])

        self.assertEqual(ui.run_argv(), False)
        assert ui.msg_text is not None
        self.assertIn("No additional information collected.", ui.msg_text)
        self.assertFalse(ui.present_details_shown)

    def test_run_update_report_nonexisting_package_cli(self) -> None:
        """run_update_report() on a nonexisting package (CLI argument)"""
        ui = UserInterfaceMock(["ui-test", "-u", "1", "-p", "bar"])

        self.assertEqual(ui.run_argv(), False)
        assert ui.msg_text is not None
        self.assertIn("No additional information collected.", ui.msg_text)
        self.assertFalse(ui.present_details_shown)

    def test_run_update_report_existing_package_from_bug(self) -> None:
        """run_update_report() on an existing package (from bug)"""
        ui = UserInterfaceMock(["ui-test", "-u", "1"])
        ui.present_details_response = apport.ui.Action(report=True)

        ui.crashdb.download(1)["SourcePackage"] = "bash"
        ui.crashdb.download(1)["Package"] = "bash"
        self.assertEqual(ui.run_argv(), True)
        self.assertIsNone(ui.msg_severity, ui.msg_text)
        self.assertIsNone(ui.msg_title)
        self.assertIsNone(ui.opened_url)
        self.assertTrue(ui.present_details_shown)

        self.assertTrue(ui.ic_progress_pulses > 0)
        assert ui.report
        self.assertTrue(ui.report["Package"].startswith("bash "))
        self.assertIn("Dependencies", ui.report)
        self.assertIn("ProcEnviron", ui.report)

    def test_run_update_report_existing_package_cli_tags(self) -> None:
        """run_update_report() on an existing package (CLI argument)
        with extra tag"""
        argv = ["ui-test", "-u", "1", "-p", "bash", "--tag", "foo"]
        ui = UserInterfaceMock(argv)
        ui.present_details_response = apport.ui.Action(report=True)

        self.assertEqual(ui.run_argv(), True)
        self.assertIsNone(ui.msg_severity, ui.msg_text)
        self.assertIsNone(ui.msg_title)
        self.assertIsNone(ui.opened_url)
        self.assertTrue(ui.present_details_shown)

        self.assertTrue(ui.ic_progress_pulses > 0)
        assert ui.report
        self.assertTrue(ui.report["Package"].startswith("bash "))
        self.assertIn("Dependencies", ui.report)
        self.assertIn("ProcEnviron", ui.report)
        self.assertIn("foo", ui.report.get_tags())

    def test_run_update_report_existing_package_cli_cmdname(self) -> None:
        """run_update_report() on an existing package (-collect program)"""
        ui = UserInterfaceMock(["apport-collect", "-p", "bash", "1"])
        ui.present_details_response = apport.ui.Action(report=True)

        self.assertEqual(ui.run_argv(), True)
        self.assertIsNone(ui.msg_severity, ui.msg_text)
        self.assertIsNone(ui.msg_title)
        self.assertIsNone(ui.opened_url)
        self.assertTrue(ui.present_details_shown)

        self.assertTrue(ui.ic_progress_pulses > 0)
        assert ui.report
        self.assertTrue(ui.report["Package"].startswith("bash "))
        self.assertIn("Dependencies", ui.report)
        self.assertIn("ProcEnviron", ui.report)

    def test_run_update_report_noninstalled_but_hook(self) -> None:
        """run_update_report() on an uninstalled package with a source hook"""
        ui = UserInterfaceMock(["ui-test", "-u", "1"])
        ui.present_details_response = apport.ui.Action(report=True)

        with open(
            os.path.join(self.hookdir, "source_foo.py"), "w", encoding="utf-8"
        ) as f:
            f.write('def add_info(r, ui):\n  r["MachineType"]="Laptop"\n')

        self.assertEqual(ui.run_argv(), True, ui.report)
        self.assertIsNone(ui.msg_severity, ui.msg_text)
        self.assertIsNone(ui.msg_title)
        self.assertIsNone(ui.opened_url)
        self.assertTrue(ui.present_details_shown)

        self.assertTrue(ui.ic_progress_pulses > 0)
        assert ui.report
        self.assertEqual(ui.report["Package"], "foo (not installed)")
        self.assertEqual(ui.report["MachineType"], "Laptop")
        self.assertIn("ProcEnviron", ui.report)

    def test_run_update_report_different_binary_source(self) -> None:
        """run_update_report() on a source package which does not have
        a binary of the same name"""
        # this test assumes that the source package name is not an
        # installed binary package
        source_pkg = "shadow"
        self.assertRaises(ValueError, packaging.get_version, source_pkg)

        argv = ["ui-test", "-p", source_pkg, "-u", "1"]
        ui = UserInterfaceMock(argv)
        ui.present_details_response = apport.ui.Action(report=True)

        with open(
            os.path.join(self.hookdir, f"source_{source_pkg}.py"), "w", encoding="utf-8"
        ) as f:
            f.write('def add_info(r, ui):\n  r["MachineType"]="Laptop"\n')

        self.assertEqual(ui.run_argv(), True, ui.report)
        self.assertIsNone(ui.msg_severity, ui.msg_text)
        self.assertIsNone(ui.msg_title)
        self.assertIsNone(ui.opened_url)
        self.assertTrue(ui.present_details_shown)

        self.assertTrue(ui.ic_progress_pulses > 0)
        assert ui.report
        self.assertEqual(ui.report["Package"], f"{source_pkg} (not installed)")
        self.assertEqual(ui.report["MachineType"], "Laptop")
        self.assertIn("ProcEnviron", ui.report)

    def _run_hook(self, ui: UserInterfaceMock, code: str) -> None:
        with open(
            os.path.join(self.hookdir, "coreutils.py"), "w", encoding="utf-8"
        ) as hook:
            hook.write(
                "def add_info(report, ui):\n%s\n"
                % "\n".join([f"    {line}" for line in code.splitlines()])
            )
        ui.args.package = "coreutils"
        ui.run_report_bug()

    def test_interactive_hooks_information(self) -> None:
        """Interactive hooks: HookUI.information()"""
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action()
        self._run_hook(
            ui,
            textwrap.dedent(
                """\
                report['begin'] = '1'
                ui.information('InfoText')
                report['end'] = '1'
                """
            ),
        )
        assert ui.report
        self.assertEqual(ui.report["begin"], "1")
        self.assertEqual(ui.report["end"], "1")
        self.assertEqual(ui.msg_text, "InfoText")

    def test_interactive_hooks_yesno(self) -> None:
        """Interactive hooks: HookUI.yesno()"""
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action(report=True)
        ui.question_yesno_response = True
        self._run_hook(
            ui,
            textwrap.dedent(
                """\
                report['begin'] = '1'
                report['answer'] = str(ui.yesno('YesNo?'))
                report['end'] = '1'
                """
            ),
        )
        assert ui.report
        self.assertEqual(ui.report["begin"], "1")
        self.assertEqual(ui.report["end"], "1")
        self.assertEqual(ui.msg_text, "YesNo?")
        self.assertEqual(ui.report["answer"], "True")

        ui.question_yesno_response = False
        ui.run_report_bug()
        self.assertEqual(ui.report["answer"], "False")
        self.assertEqual(ui.report["end"], "1")

        ui.question_yesno_response = None
        ui.run_report_bug()
        self.assertEqual(ui.report["answer"], "None")
        self.assertEqual(ui.report["end"], "1")

    def test_interactive_hooks_file(self) -> None:
        """Interactive hooks: HookUI.file()"""
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action(report=True)
        ui.question_file_response = "/etc/fstab"
        self._run_hook(
            ui,
            textwrap.dedent(
                """\
                report['begin'] = '1'
                report['answer'] = str(ui.file('YourFile?'))
                report['end'] = '1'
                """
            ),
        )
        assert ui.report
        self.assertEqual(ui.report["begin"], "1")
        self.assertEqual(ui.report["end"], "1")
        self.assertEqual(ui.msg_text, "YourFile?")
        self.assertEqual(ui.report["answer"], "/etc/fstab")

        ui.question_file_response = None
        ui.run_report_bug()
        self.assertEqual(ui.report["answer"], "None")
        self.assertEqual(ui.report["end"], "1")

    def test_interactive_hooks_choices(self) -> None:
        """Interactive hooks: HookUI.choice()"""
        ui = UserInterfaceMock()
        ui.present_details_response = apport.ui.Action(report=True)
        ui.question_choice_response = [1]
        self._run_hook(
            ui,
            textwrap.dedent(
                """\
                report['begin'] = '1'
                answer = ui.choice('YourChoice?', ['foo', 'bar'])
                report['answer'] = str(answer)
                report['end'] = '1'
                """
            ),
        )
        assert ui.report
        self.assertEqual(ui.report["begin"], "1")
        self.assertEqual(ui.report["end"], "1")
        self.assertEqual(ui.msg_text, "YourChoice?")
        self.assertEqual(ui.report["answer"], "[1]")

        ui.question_choice_response = None
        ui.run_report_bug()
        self.assertEqual(ui.report["answer"], "None")
        self.assertEqual(ui.report["end"], "1")

    def test_hooks_choices_db_no_accept(self) -> None:
        """HookUI.choice() but DB does not accept report."""
        ui = UserInterfaceMock()
        with patch.object(ui.crashdb, "accepts", return_value=False) as mock:
            ui.present_details_response = apport.ui.Action(report=True)
            ui.question_choice_response = [1]
            self._run_hook(
                ui,
                textwrap.dedent(
                    """\
                    report['begin'] = '1'
                    answer = ui.choice('YourChoice?', ['foo', 'bar'])
                    report['answer'] = str(answer)
                    report['end'] = '1'
                    """
                ),
            )
        assert ui.report
        self.assertEqual(ui.report["answer"], "None")
        mock.assert_called()

    def test_interactive_hooks_cancel(self) -> None:
        """Interactive hooks: user cancels"""
        ui = UserInterfaceMock()
        self.assertRaises(
            SystemExit,
            self._run_hook,
            ui,
            textwrap.dedent(
                """\
                report['begin'] = '1'
                raise StopIteration
                report['end'] = '1'
                """
            ),
        )

    @unittest.mock.patch("apport.hookutils.attach_conffiles", MagicMock())
    @unittest.mock.patch("sys.stderr", new_callable=io.StringIO)
    def test_run_symptom(self, stderr_mock: MagicMock) -> None:
        # TODO: Split into separate test cases
        # pylint: disable=too-many-statements
        """run_symptom()"""
        ui = UserInterfaceMock()
        # unknown symptom
        ui = UserInterfaceMock(["ui-test", "-s", "foobar"])
        ui.present_details_response = apport.ui.Action(report=True)
        self.assertEqual(ui.run_argv(), True)
        assert ui.msg_text is not None
        self.assertIn('foobar" is not known', ui.msg_text)
        self.assertEqual(ui.msg_severity, "error")

        # does not determine package
        self._write_symptom_script("nopkg.py", "def run(report, ui):\n    pass\n")
        ui = UserInterfaceMock(["ui-test", "-s", "nopkg"])
        stderr_mock.truncate(0)
        self.assertRaises(SystemExit, ui.run_argv)
        err = stderr_mock.getvalue()
        self.assertIn("did not determine the affected package", err)

        # does not define run()
        self._write_symptom_script("norun.py", "def something(x, y):\n    return 1\n")
        ui = UserInterfaceMock(["ui-test", "-s", "norun"])
        stderr_mock.truncate(0)
        self.assertRaises(SystemExit, ui.run_argv)
        err = stderr_mock.getvalue()
        self.assertIn("norun.py crashed:", err)

        # crashing script
        self._write_symptom_script("crash.py", "def run(report, ui):\n    return 1/0\n")
        ui = UserInterfaceMock(["ui-test", "-s", "crash"])
        stderr_mock.truncate(0)
        self.assertRaises(SystemExit, ui.run_argv)
        err = stderr_mock.getvalue()
        self.assertIn("crash.py crashed:", err)
        self.assertIn("ZeroDivisionError:", err)

        # working noninteractive script
        self._write_symptom_script(
            "itching.py",
            "def run(report, ui):\n"
            '  report["itch"] = "scratch"\n'
            '  return "bash"\n',
        )
        ui = UserInterfaceMock(["ui-test", "-s", "itching"])
        ui.present_details_response = apport.ui.Action(report=True)
        self.assertEqual(ui.run_argv(), True)
        self.assertIsNone(ui.msg_text)
        self.assertIsNone(ui.msg_severity)
        self.assertTrue(ui.present_details_shown)

        assert ui.report
        self.assertEqual(ui.report["itch"], "scratch")
        self.assertIn("DistroRelease", ui.report)
        self.assertEqual(ui.report["SourcePackage"], "bash")
        self.assertTrue(ui.report["Package"].startswith("bash "))
        self.assertEqual(ui.report["ProblemType"], "Bug")

        # working noninteractive script with extra tag
        argv = ["ui-test", "--tag", "foo", "-s", "itching"]
        ui = UserInterfaceMock(argv)
        ui.present_details_response = apport.ui.Action(report=True)
        self.assertEqual(ui.run_argv(), True)
        self.assertIsNone(ui.msg_text)
        self.assertIsNone(ui.msg_severity)
        self.assertTrue(ui.present_details_shown)

        assert ui.report
        self.assertEqual(ui.report["itch"], "scratch")
        self.assertIn("foo", ui.report.get_tags())

        # working interactive script
        self._write_symptom_script(
            "itching.py",
            textwrap.dedent(
                """\
                def run(report, ui):
                    report['itch'] = 'slap'
                    report['q'] = str(ui.yesno('do you?'))
                    return 'bash'
                """
            ),
        )
        ui = UserInterfaceMock(["ui-test", "-s", "itching"])
        ui.present_details_response = apport.ui.Action(report=True)
        ui.question_yesno_response = True
        self.assertEqual(ui.run_argv(), True)
        self.assertTrue(ui.present_details_shown)
        self.assertEqual(ui.msg_text, "do you?")

        assert ui.report
        self.assertEqual(ui.report["itch"], "slap")
        self.assertIn("DistroRelease", ui.report)
        self.assertEqual(ui.report["SourcePackage"], "bash")
        self.assertTrue(ui.report["Package"].startswith("bash "))
        self.assertEqual(ui.report["ProblemType"], "Bug")
        self.assertEqual(ui.report["q"], "True")

    def test_run_report_bug_list_symptoms(self) -> None:
        """run_report_bug() without specifying arguments and available
        symptoms"""
        self._write_symptom_script(
            "foo.py",
            textwrap.dedent(
                """\
                description = 'foo does not work'
                def run(report, ui):
                    return 'bash'
                """
            ),
        )
        self._write_symptom_script(
            "bar.py", 'def run(report, ui):\n  return "coreutils"\n'
        )

        ui = UserInterfaceMock(["ui-test", "-f"])
        ui.present_details_response = apport.ui.Action(report=True)

        ui.question_choice_response = None
        self.assertEqual(ui.run_argv(), True)
        self.assertIsNone(ui.msg_severity)
        assert ui.msg_text is not None
        self.assertIn("kind of problem", ui.msg_text)
        assert ui.msg_choices is not None
        self.assertEqual(
            set(ui.msg_choices), set(["bar", "foo does not work", "Other problem"])
        )

        # cancelled
        self.assertEqual(ui.ic_progress_pulses, 0)
        self.assertIsNone(ui.report)
        self.assertFalse(ui.present_details_shown)

        # now, choose foo -> bash report
        ui.question_choice_response = [ui.msg_choices.index("foo does not work")]
        self.assertEqual(ui.run_argv(), True)
        self.assertIsNone(ui.msg_severity)
        self.assertTrue(ui.ic_progress_pulses > 0)
        self.assertTrue(ui.present_details_shown)
        assert ui.report
        self.assertTrue(ui.report["Package"].startswith("bash"))

    @unittest.mock.patch("sys.stderr", new_callable=io.StringIO)
    def test_parse_argv_single_arg(self, stderr_mock: MagicMock) -> None:
        """parse_args() option inference for a single argument"""

        def _chk(
            program_name: str,
            arg: str | None,
            expected_opts: dict[str, bool | int | str | list[str] | None],
        ) -> None:
            argv = [program_name]
            if arg:
                argv.append(arg)
            ui = apport.ui.UserInterface(argv)
            expected_opts["version"] = False
            self.assertEqual(ui.args.__dict__, expected_opts)
            self.assertEqual(stderr_mock.getvalue(), "")

        # no arguments -> show pending crashes
        _chk(
            "apport-gtk",
            None,
            {
                "filebug": False,
                "package": None,
                "pid": None,
                "crash_file": None,
                "symptom": None,
                "update_report": None,
                "save": None,
                "window": False,
                "tags": [],
                "hanging": False,
            },
        )
        # updating report not allowed without args
        self.assertRaises(SystemExit, _chk, "apport-collect", None, {})
        self.assertIn(
            "error: the following arguments are required: report_number",
            stderr_mock.getvalue(),
        )
        stderr_mock.truncate(0)

        # package
        _chk(
            "apport-kde",
            "coreutils",
            {
                "filebug": True,
                "package": "coreutils",
                "pid": None,
                "crash_file": None,
                "symptom": None,
                "update_report": None,
                "save": None,
                "window": False,
                "tags": [],
                "hanging": False,
            },
        )

        # symptom is preferred over package
        self._write_symptom_script(
            "coreutils.py",
            textwrap.dedent(
                """\
                description = 'foo does not work'
                def run(report, ui):
                    return 'bash'
                """
            ),
        )
        _chk(
            "apport-cli",
            "coreutils",
            {
                "filebug": True,
                "package": None,
                "pid": None,
                "crash_file": None,
                "symptom": "coreutils",
                "update_report": None,
                "save": None,
                "window": False,
                "tags": [],
                "hanging": False,
            },
        )

        # PID
        _chk(
            "apport-cli",
            "1234",
            {
                "filebug": True,
                "package": None,
                "pid": "1234",
                "crash_file": None,
                "symptom": None,
                "update_report": None,
                "save": None,
                "window": False,
                "tags": [],
                "hanging": False,
            },
        )

        # .crash/.apport files; check correct handling of spaces
        for suffix in (".crash", ".apport"):
            _chk(
                "apport-cli",
                f"/tmp/f oo{suffix}",
                {
                    "filebug": False,
                    "package": None,
                    "pid": None,
                    "crash_file": f"/tmp/f oo{suffix}",
                    "symptom": None,
                    "update_report": None,
                    "save": None,
                    "window": False,
                    "tags": [],
                    "hanging": False,
                },
            )

        # executable
        _chk(
            "apport-cli",
            "/usr/bin/gzip",
            {
                "filebug": True,
                "package": "gzip",
                "pid": None,
                "crash_file": None,
                "symptom": None,
                "update_report": None,
                "save": None,
                "window": False,
                "tags": [],
                "hanging": False,
            },
        )

        # update existing report
        _chk(
            "apport-collect",
            "1234",
            {
                "filebug": False,
                "package": None,
                "crash_file": None,
                "symptom": None,
                "update_report": 1234,
                "tags": [],
                "hanging": False,
            },
        )
        _chk(
            "apport-update-bug",
            "1234",
            {
                "filebug": False,
                "package": None,
                "crash_file": None,
                "symptom": None,
                "update_report": 1234,
                "tags": [],
                "hanging": False,
            },
        )

    @unittest.mock.patch("sys.stderr", new_callable=io.StringIO)
    def test_parse_argv_apport_bug(self, stderr_mock: MagicMock) -> None:
        """parse_args() option inference when invoked as *-bug"""

        def _chk(
            args: list[str],
            expected_opts: dict[str, bool | int | str | list[str] | None],
        ) -> None:
            ui = apport.ui.UserInterface(["apport-bug"] + args)
            expected_opts["version"] = False
            self.assertEqual(ui.args.__dict__, expected_opts)
            self.assertEqual(stderr_mock.getvalue(), "")

        #
        # no arguments: default to 'ask for symptom' bug mode
        #
        _chk(
            [],
            {
                "filebug": True,
                "package": None,
                "pid": None,
                "crash_file": None,
                "symptom": None,
                "update_report": None,
                "save": None,
                "window": False,
                "tags": [],
                "hanging": False,
            },
        )

        #
        # single arguments
        #

        # package
        _chk(
            ["coreutils"],
            {
                "filebug": True,
                "package": "coreutils",
                "pid": None,
                "crash_file": None,
                "symptom": None,
                "update_report": None,
                "save": None,
                "window": False,
                "tags": [],
                "hanging": False,
            },
        )

        # symptom (preferred over package)
        self._write_symptom_script(
            "coreutils.py",
            textwrap.dedent(
                """\
                description = 'foo does not work'
                def run(report, ui):
                    return 'bash'
                """
            ),
        )
        _chk(
            ["coreutils"],
            {
                "filebug": True,
                "package": None,
                "pid": None,
                "crash_file": None,
                "symptom": "coreutils",
                "update_report": None,
                "save": None,
                "window": False,
                "tags": [],
                "hanging": False,
            },
        )
        os.unlink(os.path.join(apport.ui.symptom_script_dir, "coreutils.py"))

        # PID
        _chk(
            ["1234"],
            {
                "filebug": True,
                "package": None,
                "pid": "1234",
                "crash_file": None,
                "symptom": None,
                "update_report": None,
                "save": None,
                "window": False,
                "tags": [],
                "hanging": False,
            },
        )

        # .crash/.apport files; check correct handling of spaces
        for suffix in (".crash", ".apport"):
            _chk(
                [f"/tmp/f oo{suffix}"],
                {
                    "filebug": False,
                    "package": None,
                    "pid": None,
                    "crash_file": f"/tmp/f oo{suffix}",
                    "symptom": None,
                    "update_report": None,
                    "save": None,
                    "window": False,
                    "tags": [],
                    "hanging": False,
                },
            )

        # executable name
        _chk(
            ["/usr/bin/gzip"],
            {
                "filebug": True,
                "package": "gzip",
                "pid": None,
                "crash_file": None,
                "symptom": None,
                "update_report": None,
                "save": None,
                "window": False,
                "tags": [],
                "hanging": False,
            },
        )

        #
        # supported options
        #

        # --save
        _chk(
            ["--save", "foo.apport", "coreutils"],
            {
                "filebug": True,
                "package": "coreutils",
                "pid": None,
                "crash_file": None,
                "symptom": None,
                "update_report": None,
                "save": "foo.apport",
                "window": False,
                "tags": [],
                "hanging": False,
            },
        )

        # --tag
        _chk(
            ["--tag", "foo", "coreutils"],
            {
                "filebug": True,
                "package": "coreutils",
                "pid": None,
                "crash_file": None,
                "symptom": None,
                "update_report": None,
                "save": None,
                "window": False,
                "tags": ["foo"],
                "hanging": False,
            },
        )
        _chk(
            ["--tag", "foo", "--tag", "bar", "coreutils"],
            {
                "filebug": True,
                "package": "coreutils",
                "pid": None,
                "crash_file": None,
                "symptom": None,
                "update_report": None,
                "save": None,
                "window": False,
                "tags": ["foo", "bar"],
                "hanging": False,
            },
        )

        # mutually exclusive options
        self.assertRaises(SystemExit, _chk, ["-c", "/tmp/foo.report", "-u", "1234"], {})

    def test_can_examine_locally_crash(self) -> None:
        """can_examine_locally() for a crash report"""
        ui = UserInterfaceMock()
        ui.load_report(self.report_file.name)

        orig_path = os.environ["PATH"]
        try:
            os.environ["PATH"] = ""
            with patch.object(ui, "ui_has_terminal", return_value=True) as mock:
                self.assertEqual(ui.can_examine_locally(), False)

                src_bindir = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "bin"
                )
                # this will only work for running the tests in the source tree
                if os.access(os.path.join(src_bindir, "apport-retrace"), os.X_OK):
                    os.environ["PATH"] += f"{src_bindir}:{orig_path}"
                    self.assertEqual(ui.can_examine_locally(), True)
                    mock.assert_called_with()
                else:
                    # if we run tests in installed system, we just check that
                    # it doesn't crash
                    self.assertIn(ui.can_examine_locally(), [False, True])

            with patch.object(ui, "ui_has_terminal", return_value=False):
                self.assertEqual(ui.can_examine_locally(), False)

            # does not crash on NotImplementedError
            self.assertEqual(ui.can_examine_locally(), False)

        finally:
            os.environ["PATH"] = orig_path

    def test_can_examine_locally_nocrash(self) -> None:
        """can_examine_locally() for a non-crash report"""
        ui = UserInterfaceMock()
        ui.load_report(self.report_file.name)
        assert ui.report
        del ui.report["CoreDump"]

        self.assertEqual(ui.can_examine_locally(), False)

    def test_db_no_accept(self) -> None:
        """Crash database does not accept report."""
        # FIXME: This behaviour is not really correct, but necessary as long as
        # we only support a single crashdb and have whoopsie hardcoded
        # (see LP#957177)
        ui = UserInterfaceMock()
        latest_id_before = ui.crashdb.latest_id()

        ui = UserInterfaceMock(["ui-test", "-f", "-p", "bash"])

        # Pretend it does not accept report
        with patch.object(ui.crashdb, "accepts", return_value=False) as mock:
            ui.present_details_response = apport.ui.Action(report=True)
            self.assertEqual(ui.run_argv(), True)

        self.assertIsNone(ui.msg_severity)
        self.assertIsNone(ui.msg_title)
        self.assertTrue(ui.present_details_shown)
        mock.assert_called()

        # data was collected for whoopsie
        assert ui.report
        self.assertEqual(ui.report["SourcePackage"], "bash")
        self.assertIn("Dependencies", ui.report)
        self.assertIn("ProcEnviron", ui.report)
        self.assertEqual(ui.report["ProblemType"], "Bug")

        # no upload happened
        self.assertIsNone(ui.opened_url)
        self.assertEqual(ui.upload_progress_pulses, 0)
        self.assertEqual(ui.crashdb.latest_id(), latest_id_before)

    def test_get_desktop_entry(self) -> None:
        """Parsee .desktop files."""
        ui = UserInterfaceMock()
        with tempfile.NamedTemporaryFile(mode="w+") as desktop_file:
            desktop_file.write(
                textwrap.dedent(
                    """\
                    [Desktop Entry]
                    Name=gtranslate
                    GenericName=Translator
                    GenericName[de]=Übersetzer
                    Exec=gedit %U
                    Categories=GNOME;GTK;Utility;TextEditor;
                    """
                )
            )
            desktop_file.flush()

            self.report["DesktopFile"] = desktop_file.name
            ui.report = self.report
            info = ui.get_desktop_entry()

            self.assertEqual(
                info,
                {
                    "genericname": "Translator",
                    "categories": "GNOME;GTK;Utility;TextEditor;",
                    "name": "gtranslate",
                    "genericname[de]": "Übersetzer",
                    "exec": "gedit %U",
                },
            )

    def test_get_desktop_entry_broken(self) -> None:
        """Parse broken .desktop files."""
        ui = UserInterfaceMock()
        # duplicate key
        with tempfile.NamedTemporaryFile(mode="w+") as desktop_file:
            desktop_file.write(
                textwrap.dedent(
                    """\
                    [Desktop Entry]
                    Name=gtranslate
                    GenericName=Translator
                    GenericName[de]=Übersetzer
                    Exec=gedit %U
                    Keywords=foo;bar;
                    Categories=GNOME;GTK;Utility;TextEditor;
                    Keywords=baz
                    """
                )
            )
            desktop_file.flush()

            self.report["DesktopFile"] = desktop_file.name
            ui.report = self.report
            info = ui.get_desktop_entry()
            self.assertEqual(
                info,
                {
                    "genericname": "Translator",
                    "categories": "GNOME;GTK;Utility;TextEditor;",
                    "name": "gtranslate",
                    "genericname[de]": "Übersetzer",
                    "keywords": "baz",
                    "exec": "gedit %U",
                },
            )

            # no header
            desktop_file.seek(0)
            desktop_file.write(
                textwrap.dedent(
                    """\
                    Name=gtranslate
                    GenericName=Translator
                    Exec=gedit %U
                    """
                )
            )
            desktop_file.flush()

            self.assertIsNone(ui.get_desktop_entry())

            # syntax error
            desktop_file.seek(0)
            desktop_file.write(
                textwrap.dedent(
                    """\
                    [Desktop Entry]
                    Name gtranslate
                    GenericName=Translator
                    Exec=gedit %U
                    """
                )
            )
            desktop_file.flush()

            self.assertIsNone(ui.get_desktop_entry())

    # pylint: disable-next=no-self-use
    def test_wait_for_pid(self) -> None:
        ui = UserInterfaceMock()
        # fork a test process
        with run_test_executable() as pid:
            pass
        ui.wait_for_pid(pid)

    @unittest.mock.patch("os.getgid", MagicMock(return_value=0))
    @unittest.mock.patch("os.getuid", MagicMock(return_value=0))
    @unittest.mock.patch.dict("os.environ", {"SUDO_UID": str(os.getuid())}, clear=True)
    def test_run_as_real_user(self) -> None:
        """Test run_as_real_user() with SUDO_UID set."""
        pwuid = pwd.getpwuid(int(os.environ["SUDO_UID"]))
        with tempfile.TemporaryDirectory() as tmpdir:
            # rename test program to fake gvfsd
            gvfsd_mock = os.path.join(tmpdir, "gvfsd")
            shutil.copy(self.TEST_EXECUTABLE, gvfsd_mock)
            gvfsd_env = {
                "XDG_DATA_DIRS": "mocked XDG data dir",
                "DBUS_SESSION_BUS_ADDRESS": "/fake/dbus/path",
            }
            with run_test_executable([gvfsd_mock] + self.TEST_ARGS, env=gvfsd_env):
                with unittest.mock.patch(
                    "subprocess.run", side_effect=mock_run_calls_except_pgrep
                ) as run_mock:
                    run_as_real_user(["/bin/true"], get_user_env=True)

        run_mock.assert_called_with(
            ["/bin/true"],
            check=False,
            env={
                "DBUS_SESSION_BUS_ADDRESS": "/fake/dbus/path",
                "XDG_DATA_DIRS": "mocked XDG data dir",
                "HOME": pwuid.pw_dir,
            },
            user=int(os.environ["SUDO_UID"]),
            group=pwuid.pw_gid,
            extra_groups=os.getgrouplist(pwuid.pw_name, pwuid.pw_gid),
        )
        self.assertEqual(run_mock.call_count, 2)

    @unittest.mock.patch("os.getgid", MagicMock(return_value=0))
    @unittest.mock.patch("os.getuid", MagicMock(return_value=0))
    @unittest.mock.patch.dict("os.environ", {"SUDO_UID": "1337"}, clear=True)
    @unittest.mock.patch("pwd.getpwuid")
    def test_run_as_real_user_no_gvfsd(self, getpwuid_mock: MagicMock) -> None:
        """Test run_as_real_user() without no gvfsd process."""
        getpwuid_mock.return_value = pwd.struct_passwd(
            ("testuser", "x", 1337, 42, "Test user,,,", "/home/testuser", "/bin/bash")
        )
        with unittest.mock.patch(
            "subprocess.run", side_effect=mock_run_calls_except_pgrep
        ) as run_mock:
            run_as_real_user(["/bin/true"], get_user_env=True)

        run_mock.assert_called_with(
            ["/bin/true"],
            check=False,
            env={"HOME": "/home/testuser"},
            user=1337,
            group=42,
            extra_groups=[42],
        )
        self.assertEqual(run_mock.call_count, 2)

    @unittest.mock.patch.dict("os.environ", {}, clear=True)
    def test_run_as_real_user_no_sudo(self) -> None:
        # pylint: disable=no-self-use
        """Test run_as_real_user() without sudo env variables."""
        with unittest.mock.patch(
            "subprocess.run", side_effect=mock_run_calls_except_pgrep
        ) as run_mock:
            run_as_real_user(["/bin/true"])

        run_mock.assert_called_once_with(["/bin/true"], check=False)

    @unittest.mock.patch("os.getgid", MagicMock(return_value=37))
    @unittest.mock.patch("os.getuid", MagicMock(return_value=37))
    @unittest.mock.patch.dict("os.environ", {"SUDO_UID": "0"})
    def test_run_as_real_user_non_root(self) -> None:
        # pylint: disable=no-self-use
        """Test run_as_real_user() as non-root and SUDO_UID set."""
        with unittest.mock.patch(
            "subprocess.run", side_effect=mock_run_calls_except_pgrep
        ) as run_mock:
            run_as_real_user(["/bin/true"])

        run_mock.assert_called_once_with(["/bin/true"], check=False)
