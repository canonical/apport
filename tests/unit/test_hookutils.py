"""Unit tests for the apport.hookutils module."""

import datetime
import os
import re
import subprocess
import unittest
import unittest.mock
from unittest.mock import MagicMock, Mock

import apport.hookutils
from problem_report import ProblemReport

IW_REG_LIST_DE = b"""\
global
country 00: DFS-UNSET
	(755 - 928 @ 2), (N/A, 20), (N/A), PASSIVE-SCAN
	(2402 - 2472 @ 40), (N/A, 20), (N/A)
	(2457 - 2482 @ 20), (N/A, 20), (N/A), AUTO-BW, PASSIVE-SCAN
	(2474 - 2494 @ 20), (N/A, 20), (N/A), NO-OFDM, PASSIVE-SCAN
	(5170 - 5250 @ 80), (N/A, 20), (N/A), AUTO-BW, PASSIVE-SCAN
	(5250 - 5330 @ 80), (N/A, 20), (0 ms), DFS, AUTO-BW, PASSIVE-SCAN
	(5490 - 5730 @ 160), (N/A, 20), (0 ms), DFS, PASSIVE-SCAN
	(5735 - 5835 @ 80), (N/A, 20), (N/A), PASSIVE-SCAN
	(57240 - 63720 @ 2160), (N/A, 0), (N/A)

phy#0 (self-managed)
country DE: DFS-UNSET
	(2402 - 2437 @ 40), (6, 22), (N/A), AUTO-BW, NO-HT40MINUS, NO-80MHZ, NO-160MHZ
	(2422 - 2462 @ 40), (6, 22), (N/A), AUTO-BW, NO-80MHZ, NO-160MHZ
	(2447 - 2482 @ 40), (6, 22), (N/A), AUTO-BW, NO-HT40PLUS, NO-80MHZ, NO-160MHZ
	(5170 - 5190 @ 160), (6, 22), (N/A), NO-OUTDOOR, AUTO-BW, IR-CONCURRENT, NO-HT40MINUS, NO-320MHZ, PASSIVE-SCAN
	(5190 - 5210 @ 160), (6, 22), (N/A), NO-OUTDOOR, AUTO-BW, IR-CONCURRENT, NO-HT40PLUS, NO-320MHZ, PASSIVE-SCAN
	(5210 - 5230 @ 160), (6, 22), (N/A), NO-OUTDOOR, AUTO-BW, IR-CONCURRENT, NO-HT40MINUS, NO-320MHZ, PASSIVE-SCAN
	(5230 - 5250 @ 160), (6, 22), (N/A), NO-OUTDOOR, AUTO-BW, IR-CONCURRENT, NO-HT40PLUS, NO-320MHZ, PASSIVE-SCAN
	(5250 - 5270 @ 160), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40MINUS, NO-320MHZ, PASSIVE-SCAN
	(5270 - 5290 @ 160), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40PLUS, NO-320MHZ, PASSIVE-SCAN
	(5290 - 5310 @ 160), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40MINUS, NO-320MHZ, PASSIVE-SCAN
	(5310 - 5330 @ 160), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40PLUS, NO-320MHZ, PASSIVE-SCAN
	(5490 - 5510 @ 160), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40MINUS, NO-320MHZ, PASSIVE-SCAN
	(5510 - 5530 @ 160), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40PLUS, NO-320MHZ, PASSIVE-SCAN
	(5530 - 5550 @ 160), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40MINUS, NO-320MHZ, PASSIVE-SCAN
	(5550 - 5570 @ 160), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40PLUS, NO-320MHZ, PASSIVE-SCAN
	(5570 - 5590 @ 160), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40MINUS, NO-320MHZ, PASSIVE-SCAN
	(5590 - 5610 @ 160), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40PLUS, NO-320MHZ, PASSIVE-SCAN
	(5610 - 5630 @ 160), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40MINUS, NO-320MHZ, PASSIVE-SCAN
	(5630 - 5650 @ 160), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40PLUS, NO-320MHZ, PASSIVE-SCAN
	(5650 - 5670 @ 80), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40MINUS, NO-160MHZ, NO-320MHZ, PASSIVE-SCAN
	(5670 - 5690 @ 80), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40PLUS, NO-160MHZ, NO-320MHZ, PASSIVE-SCAN
	(5690 - 5710 @ 80), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40MINUS, NO-160MHZ, NO-320MHZ, PASSIVE-SCAN
	(5710 - 5730 @ 80), (6, 22), (0 ms), DFS, AUTO-BW, NO-HT40PLUS, NO-160MHZ, NO-320MHZ, PASSIVE-SCAN
	(5735 - 5755 @ 80), (6, 22), (N/A), AUTO-BW, NO-HT40MINUS, NO-160MHZ, NO-320MHZ
	(5755 - 5775 @ 80), (6, 22), (N/A), AUTO-BW, NO-HT40PLUS, NO-160MHZ, NO-320MHZ
	(5775 - 5795 @ 80), (6, 22), (N/A), AUTO-BW, NO-HT40MINUS, NO-160MHZ, NO-320MHZ
	(5795 - 5815 @ 80), (6, 22), (N/A), AUTO-BW, NO-HT40PLUS, NO-160MHZ, NO-320MHZ
	(5815 - 5835 @ 20), (6, 22), (N/A), AUTO-BW, NO-HT40MINUS, NO-HT40PLUS, NO-80MHZ, NO-160MHZ, NO-320MHZ

"""  # noqa


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

    @unittest.mock.patch("apport.hookutils.execute_multiple_root_commands")
    def test_attach_mac_events_apparmor(
        self, execute_multiple_root_commands_mock: MagicMock
    ) -> None:
        # TODO: Split into separate test cases
        # pylint: disable=too-many-statements
        """Test apparmor tag calculation of attach_mac_events()"""
        execute_multiple_root_commands_mock.return_value = {}
        denied_log = (
            "[  351.624338] type=1400 audit(1343775571.688:27):"
            ' apparmor="DENIED" operation="capable" parent=1'
            ' profile="/usr/sbin/cupsd" pid=1361 comm="cupsd" pid=1361'
            ' comm="cupsd" capability=36  capname="block_suspend"\n'
        )

        denied_hex = (
            "[  351.624338] type=1400 audit(1343775571.688:27):"
            ' apparmor="DENIED" operation="capable" parent=1'
            ' profile=2F7573722F7362696E2F6375707364 pid=1361 comm="cupsd"'
            ' pid=1361 comm="cupsd" capability=36  capname="block_suspend"\n'
        )

        # No AppArmor messages
        report = ProblemReport()
        report["AuditLog"] = "some audit log"
        report["KernLog"] = (
            "[    2.997534] i915 0000:00:02.0:"
            " power state changed by ACPI to D0\n"
            "[    2.997541] i915 0000:00:02.0:"
            " PCI INT A -> GSI 16 (level, low)\n"
            "[    2.997544] i915 0000:00:02.0: setting latency timer to 64\n"
            "[    3.061584] i915 0000:00:02.0: irq 42 for MSI/MSI-X\n"
        )

        apport.hookutils.attach_mac_events(report)
        self.assertNotIn("Tags", report)
        execute_multiple_root_commands_mock.assert_called_with({})

        # AppArmor message, but not a denial
        report = ProblemReport()
        report["AuditLog"] = "some audit log"
        report["KernLog"] = (
            "[   32.420248] type=1400 audit(1344562672.449:2):"
            ' apparmor="STATUS" operation="profile_load" name="/sbin/dhclient"'
            ' pid=894 comm="apparmor_parser"\n'
        )

        apport.hookutils.attach_mac_events(report)
        self.assertNotIn("Tags", report)
        execute_multiple_root_commands_mock.assert_called_with({})

        # AppArmor denial, empty tags, no profile specified
        report = ProblemReport()
        report["AuditLog"] = "some audit log"
        report["KernLog"] = denied_log

        apport.hookutils.attach_mac_events(report)
        self.assertEqual(report["Tags"], "apparmor")
        execute_multiple_root_commands_mock.assert_called_with({})

        # AppArmor hex-encoded denial, no profile specified
        report = ProblemReport()
        report["AuditLog"] = "some audit log"
        report["KernLog"] = denied_hex

        apport.hookutils.attach_mac_events(report)
        self.assertEqual(report["Tags"], "apparmor")
        execute_multiple_root_commands_mock.assert_called_with({})

        # AppArmor denial in AuditLog
        report = ProblemReport()
        report["AuditLog"] = denied_log
        report["KernLog"] = "some dmesg log"

        apport.hookutils.attach_mac_events(report)
        self.assertEqual(report["Tags"], "apparmor")
        execute_multiple_root_commands_mock.assert_called_with({})

        # AppArmor denial, pre-existing tags, no profile specified
        report = ProblemReport()
        report["AuditLog"] = "some audit log"
        report["KernLog"] = denied_log
        report["Tags"] = "bogustag"

        apport.hookutils.attach_mac_events(report)
        self.assertEqual(report["Tags"], "apparmor bogustag")
        execute_multiple_root_commands_mock.assert_called_with({})

        # AppArmor denial, single profile specified
        report = ProblemReport()
        report["AuditLog"] = "some audit log"
        report["KernLog"] = denied_log

        apport.hookutils.attach_mac_events(report, "/usr/sbin/cupsd")
        self.assertEqual(report["Tags"], "apparmor")
        execute_multiple_root_commands_mock.assert_called_with({})

        # AppArmor denial, regex profile specified
        report = ProblemReport()
        report["AuditLog"] = "some audit log"
        report["KernLog"] = denied_log

        apport.hookutils.attach_mac_events(report, "/usr/sbin/cups.*")
        self.assertEqual(report["Tags"], "apparmor")
        execute_multiple_root_commands_mock.assert_called_with({})

        # AppArmor denial, subset profile specified
        report = ProblemReport()
        report["AuditLog"] = "some audit log"
        report["KernLog"] = denied_log

        apport.hookutils.attach_mac_events(report, "/usr/sbin/cup")
        self.assertNotIn("Tags", report)
        execute_multiple_root_commands_mock.assert_called_with({})

        # AppArmor hex-encoded denial, single profile specified
        report = ProblemReport()
        report["AuditLog"] = "some audit log"
        report["KernLog"] = denied_hex

        apport.hookutils.attach_mac_events(report, "/usr/sbin/cupsd")
        self.assertEqual(report["Tags"], "apparmor")
        execute_multiple_root_commands_mock.assert_called_with({})

        # AppArmor denial, single different profile specified
        report = ProblemReport()
        report["AuditLog"] = "some audit log"
        report["KernLog"] = denied_log

        apport.hookutils.attach_mac_events(report, "/usr/sbin/nonexistent")
        self.assertNotIn("Tags", report)
        execute_multiple_root_commands_mock.assert_called_with({})

        # AppArmor denial, multiple profiles specified
        report = ProblemReport()
        report["AuditLog"] = "some audit log"
        report["KernLog"] = denied_log
        profiles = ["/usr/bin/nonexistent", "/usr/sbin/cupsd"]

        apport.hookutils.attach_mac_events(report, profiles)
        self.assertEqual(report["Tags"], "apparmor")
        execute_multiple_root_commands_mock.assert_called_with({})

        # AppArmor denial, multiple different profiles
        report = ProblemReport()
        report["AuditLog"] = "some audit log"
        report["KernLog"] = denied_log
        profiles = ["/usr/bin/nonexistent", "/usr/sbin/anotherone"]

        apport.hookutils.attach_mac_events(report, profiles)
        self.assertNotIn("Tags", report)
        execute_multiple_root_commands_mock.assert_called_with({})

        # Multiple AppArmor denials, second match
        report = ProblemReport()
        report["KernLog"] = (
            "[  351.624338] type=1400 audit(1343775571.688:27):"
            ' apparmor="DENIED" operation="capable" parent=1'
            ' profile="/usr/sbin/blah" pid=1361 comm="cupsd" pid=1361'
            ' comm="cupsd" capability=36  capname="block_suspend"\n'
            "[  351.624338] type=1400 audit(1343775571.688:27):"
            ' apparmor="DENIED" operation="capable" parent=1'
            ' profile="/usr/sbin/cupsd" pid=1361 comm="cupsd" pid=1361'
            ' comm="cupsd" capability=36  capname="block_suspend"\n'
        )

        apport.hookutils.attach_mac_events(report, "/usr/sbin/cupsd")
        self.assertEqual(report["Tags"], "apparmor")
        execute_multiple_root_commands_mock.assert_called_with({})

    @unittest.mock.patch("glob.glob")
    @unittest.mock.patch("os.path.exists")
    @unittest.mock.patch("subprocess.run")
    @unittest.mock.patch(
        "apport.hookutils.recent_syslog", MagicMock(return_value="some recent logs")
    )
    def test_attach_wifi(
        self, run_mock: MagicMock, exists_mock: MagicMock, glob_mock: MagicMock
    ) -> None:
        """Test attach_wifi() with some real world data from Ubuntu 25.04.

        This test case does not test the recent_syslog() call."""
        glob_mock.return_value = ["/sys/class/net/wlp3s0/wireless"]
        exists_mock.side_effect = [True, False]
        rfkill_list = (
            b"0: hci0: Bluetooth\n	Soft blocked: no\n	Hard blocked: no\n"
            b"1: phy0: Wireless LAN\n	Soft blocked: no\n	Hard blocked: no\n"
        )
        iw_dev_wlp3s0_link_params = (
            b"	freq: 2437.0\n"
            b"	RX: 2363829 bytes (3994 packets)\n"
            b"	TX: 303619 bytes (1560 packets)\n"
            b"	signal: -43 dBm\n"
            b"	rx bitrate: 286.7 MBit/s HE-MCS 11 HE-NSS 2 HE-GI 0 HE-DCM 0\n"
            b"	tx bitrate: 286.7 MBit/s HE-MCS 11 HE-NSS 2 HE-GI 0 HE-DCM 0\n"
            b"	bss flags: CTS-protection short-preamble short-slot-time\n"
            b"	dtim period: 2\n"
            b"	beacon int: 100\n"
        )
        iw_dev_wlp3s0_link = (
            b"Connected to 00:53:e9:15:6c:33 (on wlp3s0)\n	SSID: MyWifiNetwork\n"
            + iw_dev_wlp3s0_link_params
        )
        run_mock.side_effect = [
            subprocess.CompletedProcess(
                args=MagicMock(), returncode=0, stdout=rfkill_list, stderr=b""
            ),
            subprocess.CompletedProcess(
                args=MagicMock(), returncode=0, stdout=iw_dev_wlp3s0_link, stderr=b""
            ),
            subprocess.CompletedProcess(
                args=MagicMock(), returncode=0, stdout=IW_REG_LIST_DE, stderr=b""
            ),
        ]

        report = apport.Report()
        apport.hookutils.attach_wifi(report)

        self.assertEqual(report["WifiSyslog"], "some recent logs")
        self.assertEqual(report["RfKill"], rfkill_list.decode("utf-8").rstrip())
        self.assertEqual(
            report["IwDevWlp3s0Link"],
            "Connected to <hidden-mac> (on wlp3s0)\n	SSID: <hidden>\n"
            + iw_dev_wlp3s0_link_params.decode("utf-8").rstrip(),
        )
        self.assertEqual(report["CRDA"], IW_REG_LIST_DE.decode("utf-8").rstrip())
        self.assertEqual(
            set(report.keys()),
            {"CRDA", "Date", "IwDevWlp3s0Link", "ProblemType", "RfKill", "WifiSyslog"},
        )
        glob_mock.assert_called_once_with("/sys/class/net/*/wireless")
        self.assertEqual(
            [call.args[0] for call in exists_mock.call_args_list],
            ["/sbin/iw", "/var/log/wpa_supplicant.log"],
        )
        self.assertEqual(
            [call.args[0] for call in run_mock.call_args_list],
            [["rfkill", "list"], ["iw", "dev", "wlp3s0", "link"], ["iw", "reg", "get"]],
        )

    @unittest.mock.patch("os.path.exists")
    @unittest.mock.patch("subprocess.run")
    @unittest.mock.patch(
        "apport.hookutils.recent_syslog", MagicMock(return_value="some recent logs")
    )
    def test_attach_wifi_without_iw(
        self, run_mock: MagicMock, exists_mock: MagicMock
    ) -> None:
        """Test attach_wifi() with no iw command installed.

        This test case does not test the recent_syslog() call and rfkill command."""
        exists_mock.return_value = False
        run_mock.return_value = subprocess.CompletedProcess(
            args=MagicMock(), returncode=0, stdout=b"rfkill output", stderr=b""
        )

        report = apport.Report()
        apport.hookutils.attach_wifi(report)

        self.assertEqual(report["WifiSyslog"], "some recent logs")
        self.assertEqual(report["RfKill"], "rfkill output")
        self.assertEqual(report["CRDA"], "N/A")
        self.assertEqual(
            set(report.keys()), {"CRDA", "Date", "ProblemType", "RfKill", "WifiSyslog"}
        )
        exists_mock.assert_called()
        self.assertEqual(
            [call.args[0] for call in exists_mock.call_args_list],
            ["/sbin/iw", "/var/log/wpa_supplicant.log"],
        )
        run_mock.assert_called_once()
        self.assertEqual(run_mock.call_args_list[0].args[0], ["rfkill", "list"])

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

    @staticmethod
    @unittest.mock.patch("subprocess.run")
    def test_execute_multiple_root_commands_no_commands(run_mock: MagicMock) -> None:
        outputs = apport.hookutils.execute_multiple_root_commands({})
        assert not outputs
        assert not run_mock.called
