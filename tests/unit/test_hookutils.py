"""Unit tests for the apport.hookutils module."""

import datetime
import os
import re
import subprocess
import unittest
import unittest.mock
from unittest.mock import MagicMock, Mock

import apport.hookutils


class TestHookutils(unittest.TestCase):
    # pylint: disable=missing-function-docstring
    """Test apport.hookutils module."""

    maxDiff = None

    @unittest.mock.patch("os.path.isdir", MagicMock(return_value=True))
    @unittest.mock.patch("os.listdir")
    @unittest.mock.patch("os.stat")
    @unittest.mock.patch("apport.hookutils.read_file")
    def test_attach_dmi(
        self, read_file_mock: MagicMock, stat_mock: MagicMock, listdir_mock: MagicMock
    ) -> None:
        """attach_dmi()"""

        def stat(
            content: str = "private\n",
            st_mode: int = 0o100444,
            st_nlink: int = 1,
            st_size: int = 4096,
        ) -> tuple[str, os.stat_result]:
            st_time = 1698056204.0
            stat = os.stat_result(
                (st_mode, 1337, 22, st_nlink, 0, 0, st_size, st_time, st_time, st_time)
            )
            return (content, stat)

        dmi_files = {
            "bios_date": stat("07/20/2022\n"),
            "board_serial": stat(st_mode=0o100400),
            "uevent": stat("MODALIAS=dmi:[...]\n", st_mode=0o100644),
            "product_serial": stat(st_mode=0o100400),
            "product_name": stat("B550I AORUS PRO AX\n"),
            "sys_vendor": stat("Gigabyte Technology Co., Ltd.\n"),
            "power": stat(st_mode=0o40755, st_nlink=2, st_size=0),
            "bios_version": stat("F16e\n"),
            "bios_release": stat("5.17\n"),
            "board_vendor": stat("Gigabyte Technology Co., Ltd.\n"),
            "subsystem": stat(st_mode=0o40755, st_nlink=2, st_size=0),
            "product_family": stat("B550 MB\n"),
            "product_uuid": stat(
                "2cf4a3c2-8f76-4f38-95b5-77c8a9f6ec4f\n", st_mode=0o100400
            ),
            "bios_vendor": stat("American Megatrends International, LLC.\n"),
            "board_name": stat("B550I AORUS PRO AX\n"),
        }

        def mock_os_stat(path: str) -> os.stat_result:
            return dmi_files[os.path.basename(path)][1]

        def mock_read_file(path: str) -> str:
            return dmi_files[os.path.basename(path)][0].strip()

        listdir_mock.return_value = list(dmi_files.keys())
        stat_mock.side_effect = mock_os_stat
        read_file_mock.side_effect = mock_read_file
        report: dict[str, str] = {}
        apport.hookutils.attach_dmi(report)
        self.assertEqual(
            report,
            {
                "dmi.bios.date": "07/20/2022",
                "dmi.bios.release": "5.17",
                "dmi.bios.vendor": "American Megatrends International, LLC.",
                "dmi.bios.version": "F16e",
                "dmi.board.name": "B550I AORUS PRO AX",
                "dmi.board.vendor": "Gigabyte Technology Co., Ltd.",
                "dmi.product.family": "B550 MB",
                "dmi.product.name": "B550I AORUS PRO AX",
                "dmi.sys.vendor": "Gigabyte Technology Co., Ltd.",
                "MachineType": "Gigabyte Technology Co., Ltd. B550I AORUS PRO AX",
            },
        )

    @unittest.mock.patch("apport.hookutils.root_command_output")
    def test_attach_dmesg(self, root_command_output_mock: MagicMock) -> None:
        """attach_dmesg()"""
        root_command_output_mock.return_value = "[30804.972250] CPU0 is up"

        report: dict[str, str] = {}
        apport.hookutils.attach_dmesg(report)
        self.assertEqual(report, {"CurrentDmesg": "[30804.972250] CPU0 is up"})

        root_command_output_mock.assert_called_once_with(["dmesg"])

    def test_dmesg_overwrite(self) -> None:
        """attach_dmesg() does not overwrite already existing data"""
        report = {"CurrentDmesg": "existingcurrent"}

        apport.hookutils.attach_dmesg(report)
        self.assertEqual(report["CurrentDmesg"], "existingcurrent")

    @unittest.mock.patch("subprocess.run")
    @unittest.mock.patch("os.path.exists", MagicMock(return_value=True))
    def test_attach_journal_errors_with_date(self, run_mock: MagicMock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=MagicMock(), returncode=0, stdout=b"journalctl output", stderr=b""
        )
        now = datetime.datetime.now()

        report = apport.Report(date=now.strftime("%a %b %d %H:%M:%S %Y"))
        apport.hookutils.attach_journal_errors(report)

        self.assertEqual(run_mock.call_count, 1)
        self.assertEqual(report.get("JournalErrors"), "journalctl output")
        self.assertEqual(
            run_mock.call_args[0][0],
            [
                "journalctl",
                "--priority=warning",
                f"--since=@{int(now.timestamp()) - 10}",
                f"--until=@{int(now.timestamp()) + 10}",
            ],
        )

    @unittest.mock.patch("subprocess.run")
    @unittest.mock.patch("os.path.exists", MagicMock(return_value=True))
    def test_attach_journal_errors_without_date(self, run_mock: MagicMock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=MagicMock(), returncode=0, stdout=b"journalctl output", stderr=b""
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

    def test_path_to_key(self) -> None:
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
    @unittest.mock.patch("os.path.exists", MagicMock(return_value=True))
    def test_recent_syslog_journald_cmd(self, popen_mock: MagicMock) -> None:
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

    def test_recent_syslog_race_condition(self) -> None:
        """Test recent_syslog reads stdout buffer after process completion.

        LP: #2073935
        """
        with unittest.mock.patch("apport.hookutils.subprocess.Popen") as popen_mock:
            process = unittest.mock.Mock()
            popen_mock.return_value.__enter__.return_value = process
            process.returncode = 0

            process.poll = Mock(return_value=0)
            process.stdout = MagicMock()
            process.stdout.__iter__.side_effect = [iter([b"content"])]

            match_content = apport.hookutils.recent_syslog(
                re.compile("."), path="/nonexisting"
            )
            self.assertEqual(match_content, "content")

    def test_recent_syslog_long_process(self) -> None:
        """Test recent_syslog retrieves entire stdout."""
        with unittest.mock.patch("apport.hookutils.subprocess.Popen") as popen_mock:
            process = unittest.mock.Mock()
            popen_mock.return_value.__enter__.return_value = process
            process.returncode = 0

            process.poll = Mock(side_effect=[None, 0])
            process.stdout = MagicMock()
            process.stdout.__iter__.side_effect = [
                iter([b"test\n"]),
                iter([b"content\n"]),
            ]

            match_content = apport.hookutils.recent_syslog(
                re.compile("."), path="/nonexisting"
            )

            self.assertEqual(match_content, "test\ncontent\n")
