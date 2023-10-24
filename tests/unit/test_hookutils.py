"""Unit tests for the apport.hookutils module."""

import re
import subprocess
import time
import unittest
import unittest.mock

import apport.hookutils


class TestHookutils(unittest.TestCase):
    # pylint: disable=missing-function-docstring
    """Test apport.hookutils module."""

    @unittest.mock.patch("apport.hookutils.root_command_output")
    def test_attach_dmesg(self, root_command_output_mock):
        """attach_dmesg()"""
        root_command_output_mock.return_value = "[30804.972250] CPU0 is up"

        report = {}
        apport.hookutils.attach_dmesg(report)
        self.assertEqual(report, {"CurrentDmesg": "[30804.972250] CPU0 is up"})

        root_command_output_mock.assert_called_once_with(["dmesg"])

    def test_dmesg_overwrite(self):
        """attach_dmesg() does not overwrite already existing data"""
        report = {"CurrentDmesg": "existingcurrent"}

        apport.hookutils.attach_dmesg(report)
        self.assertEqual(report["CurrentDmesg"], "existingcurrent")

    @unittest.mock.patch("subprocess.run")
    @unittest.mock.patch("os.path.exists", unittest.mock.MagicMock(return_value=True))
    def test_attach_journal_errors_with_date(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=None, returncode=0, stdout=b"journalctl output", stderr=b""
        )

        report = apport.Report(date="Wed May 18 18:31:08 2022")
        apport.hookutils.attach_journal_errors(report)

        self.assertEqual(run_mock.call_count, 1)
        self.assertEqual(report.get("JournalErrors"), "journalctl output")
        self.assertEqual(
            run_mock.call_args[0][0],
            [
                "journalctl",
                "--priority=warning",
                f"--since=@{1652898658 + time.altzone}",
                f"--until=@{1652898678 + time.altzone}",
            ],
        )

    @unittest.mock.patch("subprocess.run")
    @unittest.mock.patch("os.path.exists", unittest.mock.MagicMock(return_value=True))
    def test_attach_journal_errors_without_date(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=None, returncode=0, stdout=b"journalctl output", stderr=b""
        )

        report = apport.Report()
        del report["Date"]
        apport.hookutils.attach_journal_errors(report)

        self.assertEqual(run_mock.call_count, 1)
        self.assertEqual(report.get("JournalErrors"), "journalctl output")
        self.assertEqual(
            run_mock.call_args[0][0],
            ["journalctl", "--priority=warning", "-b", "--lines=1000"],
        )

    def test_path_to_key(self):
        """Transform a file path to a valid report key."""
        self.assertEqual(apport.hookutils.path_to_key("simple.txt"), "simple.txt")
        self.assertEqual(
            apport.hookutils.path_to_key("path/with/dirs.txt"), "path.with.dirs.txt"
        )
        self.assertEqual(
            apport.hookutils.path_to_key('/funny:characters!& ".txt'),
            ".funny.characters.._..txt",
        )

    @unittest.mock.patch("subprocess.Popen")
    @unittest.mock.patch("os.path.exists", unittest.mock.MagicMock(return_value=True))
    def test_recent_syslog_journald_cmd(self, popen_mock):
        class _SkipPopen(Exception):
            pass

        popen_mock.side_effect = _SkipPopen

        cmd = ["journalctl", "--quiet", "-b", "-a"]
        cmd_system_only = cmd + ["--system"]

        with self.assertRaises(_SkipPopen):
            apport.hookutils.recent_syslog(re.compile("."))
        popen_mock.assert_called_once_with(cmd_system_only, stdout=unittest.mock.ANY)

        popen_mock.reset_mock()
        with self.assertRaises(_SkipPopen):
            apport.hookutils.recent_syslog(re.compile("."), journald_only_system=True)
        popen_mock.assert_called_once_with(cmd_system_only, stdout=unittest.mock.ANY)

        popen_mock.reset_mock()
        with self.assertRaises(_SkipPopen):
            apport.hookutils.recent_syslog(re.compile("."), journald_only_system=False)
        popen_mock.assert_called_once_with(cmd, stdout=unittest.mock.ANY)

    def test_deprecated_upstart_functions(self) -> None:
        """attach_upstart_*() throw deprecation warnings."""
        with self.assertWarns(PendingDeprecationWarning):
            apport.hookutils.attach_upstart_logs({}, "apport")
        with self.assertWarns(PendingDeprecationWarning):
            apport.hookutils.attach_upstart_overrides({}, "nonexisting")
