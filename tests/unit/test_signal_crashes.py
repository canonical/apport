# Copyright (C) 2022 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for data/apport."""

import datetime
import errno
import io
import os
import pathlib
import shutil
import signal
import sys
import tempfile
import time
import unittest
import unittest.mock
from unittest.mock import MagicMock

import apport.fileutils
import apport.user_group
from tests.helper import import_module_from_file
from tests.paths import get_data_directory

apport_binary = import_module_from_file(get_data_directory() / "apport")


class TestApport(unittest.TestCase):
    # pylint: disable=too-many-public-methods
    """Unit tests for data/apport."""

    orig_report_dir: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.orig_report_dir = apport.fileutils.report_dir

    @classmethod
    def tearDownClass(cls) -> None:
        apport.fileutils.report_dir = cls.orig_report_dir

    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.workdir)
        apport.fileutils.report_dir = os.path.join(self.workdir, "crash")
        self.report_dir = pathlib.Path(apport.fileutils.report_dir)

    @unittest.mock.patch("subprocess.run")
    def test_check_kernel_crash(self, run_mock: MagicMock) -> None:
        """Test found kernel crash dump."""
        self.report_dir.mkdir()
        vmcore = self.report_dir / "vmcore"
        vmcore.touch()
        apport_binary.check_kernel_crash()
        run_mock.assert_called_once_with(
            ["/usr/share/apport/kernel_crashdump"], check=False
        )

    def test_check_lock_not_writable(self) -> None:
        """Test check_lock() with not writable lock file."""
        os.environ["APPORT_LOCK_FILE"] = "/non-existing/apport.lock"
        try:
            with self.assertRaisesRegex(SystemExit, "^1$"):
                apport_binary.check_lock()
        finally:
            del os.environ["APPORT_LOCK_FILE"]

    @unittest.mock.patch("fcntl.lockf")
    def test_check_lock_taken(self, lockf_mock: MagicMock) -> None:
        """Test check_lock() with lock file taken by other process."""
        # Since this is a unit test, let the mock raise an exception instead
        # of letting the fcntl.lockf call run into the timeout signal.
        lockf_mock.side_effect = TimeoutError()
        with tempfile.NamedTemporaryFile("w") as lockfile:
            os.environ["APPORT_LOCK_FILE"] = lockfile.name
            try:
                with self.assertRaisesRegex(SystemExit, "^1$"):
                    apport_binary.check_lock()
            finally:
                del os.environ["APPORT_LOCK_FILE"]

    def test_refine_core_ulimit_huge(self) -> None:
        """Test refine_core_ulimit() with huge limit."""
        options = apport_binary.parse_arguments(
            ["-p", str(os.getpid()), "-d", "1", "-c", str(pow(2, 64))]
        )
        self.assertEqual(apport_binary.refine_core_ulimit(options), -1)

    @unittest.mock.patch("os.isatty")
    def test_init_error_log_is_tty(self, isatty_mock: MagicMock) -> None:
        """Test init_error_log() doing nothing on a TTY."""
        isatty_mock.return_value = True
        stderr = sys.stderr
        apport_binary.init_error_log()
        # Check sys.stderr to be unchanged
        self.assertEqual(sys.stderr, stderr)
        isatty_mock.assert_called_once_with(2)

    def test_proc_pid_not_exist(self) -> None:
        """Test ProcPid().exits() returning False."""
        with apport_binary.ProcPid(os.getpid()) as proc_pid:
            self.assertFalse(proc_pid.exists("nonexistent"))

    def test_receive_arguments_via_socket_import_error(self) -> None:
        """Test receive_arguments_via_socket() fail to import systemd."""
        with (
            self.assertLogs(level="ERROR") as error_logs,
            unittest.mock.patch("builtins.__import__") as import_mock,
            self.assertRaisesRegex(SystemExit, "^0$"),
        ):
            import_mock.side_effect = ModuleNotFoundError("No module named 'systemd'")
            apport_binary.receive_arguments_via_socket()

        import_mock.assert_called_once()
        self.assertRegex(
            error_logs.output[0], "apport-forward.socket.*systemd python module"
        )

    def test_receive_arguments_via_socket_invalid_socket(self) -> None:
        """Test receive_arguments_via_socket with invalid socket."""
        try:
            # pylint: disable=import-outside-toplevel
            from systemd.daemon import listen_fds
        except ImportError:
            self.skipTest("systemd Python module not available")
        assert listen_fds
        self.assertNotIn("LISTEN_FDS", os.environ)
        with self.assertRaisesRegex(SystemExit, "^1$"):
            apport_binary.receive_arguments_via_socket()

    @unittest.mock.patch.object(apport_binary, "check_lock", MagicMock())
    @unittest.mock.patch.object(
        apport_binary, "is_same_ns", MagicMock(return_value=False)
    )
    @unittest.mock.patch.object(apport_binary, "forward_crash_to_container")
    def test_forward_crash_to_container(self, forward_mock: MagicMock) -> None:
        """process_crash_from_kernel_with_proc_pid() to forward crash to container."""
        fake_pid = 67890
        yesterday = int(time.clock_gettime(time.CLOCK_BOOTTIME) * 100) - 86400
        options = apport_binary.parse_arguments(
            ["-p", "12345", "-d", "1", "-P", str(fake_pid)]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            stat = pathlib.Path(tmpdir) / "stat"
            stat.write_text(f"{fake_pid} (name) ?{' x' * 18} {yesterday} ...\n")
            status = pathlib.Path(tmpdir) / "status"
            status.write_text("Name:\tname\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
            exe = pathlib.Path(tmpdir) / "exe"
            os.symlink(sys.executable, exe)
            cmdline = pathlib.Path(tmpdir) / "cmdline"
            cmdline.write_text("name\0")
            with apport_binary.ProcPid(fake_pid, tmpdir) as proc_pid:
                exit_code = apport_binary.process_crash_from_kernel_with_proc_pid(
                    options, proc_pid
                )

        self.assertEqual(exit_code, 0)
        forward_mock.assert_called_once()

    @unittest.mock.patch.object(apport_binary, "init_error_log", MagicMock())
    @unittest.mock.patch.object(apport_binary, "start_apport")
    def test_main_start(self, start_mock: MagicMock) -> None:
        """Test calling apport with --start."""
        self.assertEqual(apport_binary.main(["--start"]), 0)
        start_mock.assert_called_once_with()

    @unittest.mock.patch.object(apport_binary, "init_error_log", MagicMock())
    @unittest.mock.patch.object(apport_binary, "stop_apport")
    def test_main_stop(self, stop_mock: MagicMock) -> None:
        """Test calling apport with --stop."""
        self.assertEqual(apport_binary.main(["--stop"]), 0)
        stop_mock.assert_called_once_with()

    def test_start(self) -> None:
        """Test starting Apport crash handler."""
        open_mock = unittest.mock.mock_open()
        with unittest.mock.patch("builtins.open", open_mock):
            apport_binary.start_apport()
        open_mock.assert_called_with(
            "/proc/sys/kernel/core_pipe_limit", "w", encoding="utf-8"
        )
        self.assertEqual(open_mock.call_count, 3)

    def test_consistency_checks_replaced_process(self) -> None:
        """Test consistency_checks() for a replaced crash process ID."""
        pid = os.getpid()
        options = apport_binary.parse_arguments(["-p", str(pid), "-d", "1"])
        now = int(time.clock_gettime(time.CLOCK_BOOTTIME) * 100)
        crash_user = apport.user_group.get_process_user_and_group()
        with apport_binary.ProcPid(pid) as proc_pid:
            self.assertFalse(
                apport_binary.consistency_checks(options, now, proc_pid, crash_user)
            )

    @unittest.mock.patch.object(apport_binary, "check_lock", MagicMock())
    def test_consistency_checks_before_forwarding(self) -> None:
        """Test that consistency checks are done before forwarding to container."""
        fake_pid = 67890
        future = int(time.clock_gettime(time.CLOCK_BOOTTIME) * 100) + 3600
        options = apport_binary.parse_arguments(
            ["-p", "12345", "-d", "1", "-P", str(fake_pid)]
        )
        with (
            self.assertLogs(level="ERROR") as info_logs,
            tempfile.TemporaryDirectory() as tmpdir,
        ):
            stat = pathlib.Path(tmpdir) / "stat"
            stat.write_text(f"{fake_pid} (name) ?{' x' * 18} {future} ...\n")
            status = pathlib.Path(tmpdir) / "status"
            status.write_text("Name:\tname\nUid:\t42\t42\t42\t42\nGid:\t7\t7\t7\t7\n")
            with apport_binary.ProcPid(fake_pid, tmpdir) as proc_pid:
                exit_code = apport_binary.process_crash_from_kernel_with_proc_pid(
                    options, proc_pid
                )

        self.assertEqual(exit_code, 0)
        self.assertIn(
            "process was replaced after Apport started, ignoring", info_logs.output[0]
        )

    def test_consistency_checks_mismatching_uid(self) -> None:
        """Test consistency_checks() for a mitmatching UID."""
        pid = os.getpid()
        crash_user = apport.user_group.get_process_user_and_group()
        options = apport_binary.parse_arguments(
            [
                "-p",
                str(pid),
                "-d",
                "1",
                "-u",
                str(crash_user.uid + 1),
                "-g",
                str(crash_user.gid + 1),
            ]
        )
        with apport_binary.ProcPid(pid) as proc_pid:
            self.assertFalse(
                apport_binary.consistency_checks(options, 1, proc_pid, crash_user)
            )

    def test_stop(self) -> None:
        """Test stopping Apport crash handler."""
        open_mock = unittest.mock.mock_open()
        with unittest.mock.patch("builtins.open", open_mock):
            apport_binary.stop_apport()
        open_mock.assert_called_with(
            "/proc/sys/kernel/core_pattern", "w", encoding="utf-8"
        )
        self.assertEqual(open_mock.call_count, 3)

    @unittest.mock.patch("os.setresgid", MagicMock())
    @unittest.mock.patch("os.setresuid", MagicMock())
    @unittest.mock.patch.object(apport_binary, "_run_with_output_limit_and_timeout")
    @unittest.mock.patch("os.path.exists")
    def test_is_closing_session(
        self, path_exist_mock: MagicMock, run_mock: MagicMock
    ) -> None:
        """Test is_closing_session()."""
        path_exist_mock.return_value = True
        run_mock.return_value = (b"(false,)\n", b"some stderr output\n")
        crash_user = apport.user_group.UserGroupID(1337, 1337)
        with tempfile.TemporaryDirectory() as tmpdir:
            env = pathlib.Path(tmpdir) / "environ"
            env.write_text("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1337/bus\0")
            with apport_binary.ProcPid(12345, tmpdir) as proc_pid:
                self.assertEqual(
                    apport_binary.is_closing_session(proc_pid, crash_user), True
                )
        path_exist_mock.assert_called_once_with("/run/user/1337/bus")
        run_mock.assert_called_once()

    def test_is_closing_session_no_environ(self) -> None:
        """Test is_closing_session() with no DBUS_SESSION_BUS_ADDRESS."""
        crash_user = apport.user_group.UserGroupID(1337, 1337)
        with tempfile.TemporaryDirectory() as tmpdir:
            env = pathlib.Path(tmpdir) / "environ"
            env.write_text("DISPLAY=:0\0")
            with apport_binary.ProcPid(12345, tmpdir) as proc_pid:
                self.assertEqual(
                    apport_binary.is_closing_session(proc_pid, crash_user), False
                )

    def test_is_closing_session_no_determine_socket(self) -> None:
        """Test is_closing_session() cannot determine D-Bus socket."""
        crash_user = apport.user_group.UserGroupID(42, 42)
        with tempfile.TemporaryDirectory() as tmpdir:
            env = pathlib.Path(tmpdir) / "environ"
            env.write_text("DBUS_SESSION_BUS_ADDRESS=unix:/run/user/42/bus\0")
            with apport_binary.ProcPid(12345, tmpdir) as proc_pid:
                self.assertEqual(
                    apport_binary.is_closing_session(proc_pid, crash_user), False
                )

    def test_is_closing_session_socket_not_exists(self) -> None:
        """Test is_closing_session() where D-Bus socket does not exist."""
        assert not os.path.exists("/run/user/1337/bus")
        crash_user = apport.user_group.UserGroupID(1337, 1337)
        with tempfile.TemporaryDirectory() as tmpdir:
            env = pathlib.Path(tmpdir) / "environ"
            env.write_text("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1337/bus\0")
            with apport_binary.ProcPid(12345, tmpdir) as proc_pid:
                self.assertEqual(
                    apport_binary.is_closing_session(proc_pid, crash_user), False
                )

    @unittest.mock.patch("os.setresgid", MagicMock())
    @unittest.mock.patch("os.setresuid", MagicMock())
    @unittest.mock.patch.object(apport_binary, "_run_with_output_limit_and_timeout")
    @unittest.mock.patch("os.path.exists")
    def test_is_closing_session_gdbus_failure(
        self, path_exist_mock: MagicMock, run_mock: MagicMock
    ) -> None:
        """Test is_closing_session() with OSError from gdbus."""
        path_exist_mock.return_value = True
        run_mock.side_effect = OSError(
            errno.ENOENT, "No such file or directory: 'gdbus'"
        )
        crash_user = apport.user_group.UserGroupID(1337, 1337)
        with tempfile.TemporaryDirectory() as tmpdir:
            env = pathlib.Path(tmpdir) / "environ"
            env.write_text("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1337/bus\0")
            with apport_binary.ProcPid(12345, tmpdir) as proc_pid:
                self.assertEqual(
                    apport_binary.is_closing_session(proc_pid, crash_user), False
                )
        path_exist_mock.assert_called_once_with("/run/user/1337/bus")
        run_mock.assert_called_once()

    @unittest.mock.patch.object(apport_binary, "check_lock", MagicMock())
    @unittest.mock.patch.object(apport_binary, "init_error_log", MagicMock())
    def test_missing_proc_pid(self) -> None:
        """Test /proc/<pid> is already gone."""
        fake_pid = 2147483647
        assert not os.path.exists(f"/proc/{fake_pid}")
        with self.assertLogs(level="ERROR") as error_logs:
            with tempfile.NamedTemporaryFile() as stdin:
                stdin_mock = io.FileIO(stdin.name)
                with unittest.mock.patch("sys.stdin", return_value=stdin_mock):
                    exit_code = apport_binary.main(["-p", str(fake_pid), "-d", "1"])
                    self.assertEqual(exit_code, 1)
        self.assertIn("/proc/2147483647 not found", error_logs.output[0])

    @unittest.mock.patch.object(apport_binary, "check_lock", MagicMock())
    @unittest.mock.patch.object(apport_binary, "consistency_checks", MagicMock())
    @unittest.mock.patch.object(apport_binary, "init_error_log", MagicMock())
    @unittest.mock.patch.object(
        apport_binary, "is_closing_session", MagicMock(return_value=False)
    )
    @unittest.mock.patch.object(apport_binary, "is_systemd_watchdog_restart")
    def test_main_ignore_watchdog_restart(
        self, is_systemd_watchdog_restart_mock: MagicMock
    ) -> None:
        """Test main() to ignore watchdog restarts.

        The underlying is_systemd_watchdog_restart() function is mocked,
        which should be tested in a separate unit test.
        """
        is_systemd_watchdog_restart_mock.return_value = True
        args = [
            "-p",
            str(os.getpid()),
            "-d",
            "1",
            "-s",
            str(int(signal.SIGABRT)),
            "-c",
            "-1",
        ]
        with self.assertLogs(level="ERROR") as error_logs:
            with tempfile.NamedTemporaryFile() as stdin:
                stdin_mock = io.TextIOWrapper(io.FileIO(stdin.name))
                with unittest.mock.patch("sys.stdin", stdin_mock):
                    exit_code = apport_binary.main(args)

        self.assertEqual(exit_code, 0)
        is_systemd_watchdog_restart_mock.assert_called_once()
        self.assertIn("Ignoring systemd watchdog restart", error_logs.output[0])

    @unittest.mock.patch.object(apport_binary, "init_error_log", MagicMock())
    def test_non_existing_systemd_coredump(self) -> None:
        """Test main() to print error if systemd-coredump cannot be found."""
        try:
            # pylint: disable-next=import-outside-toplevel
            import systemd.journal
        except ImportError as error:
            self.skipTest(f"{error.name} Python module not available")
        assert systemd.journal

        with self.assertLogs(level="ERROR") as error_logs:
            exit_code = apport_binary.main(["--from-systemd-coredump", "42-5846584-0"])

        self.assertEqual(exit_code, 1)
        self.assertIn(
            "No journal log for systemd unit"
            " systemd-coredump@42-5846584-0.service found.",
            error_logs.output[0],
        )

    def test_systemd_journal_import_error(self) -> None:
        """Test handling missing systemd.journal library correctly."""
        with (
            self.assertLogs(level="ERROR") as error_logs,
            unittest.mock.patch("builtins.__import__") as import_mock,
            self.assertRaisesRegex(SystemExit, "^1$"),
        ):
            import_mock.side_effect = ModuleNotFoundError(
                "No module named 'systemd.journal'"
            )
            apport_binary.process_crash_from_systemd_coredump("0-383264-0")

        import_mock.assert_called_once()
        self.assertRegex(error_logs.output[0], "Please install python3-systemd")

    @unittest.mock.patch.object(apport_binary, "process_crash")
    @unittest.mock.patch.object(apport_binary, "get_systemd_coredump")
    def test_reading_core_from_journal_log(
        self, get_systemd_coredump_mock: MagicMock, process_crash_mock: MagicMock
    ) -> None:
        """Test _user_can_read_coredump via process_crash_from_systemd_coredump

        The core dump can be provided via the journal log. In this case
        _user_can_read_coredump should behave correctly.
        """
        get_systemd_coredump_mock.return_value = {
            "COREDUMP": b"(\xb5/\xfd$\x0ca\x00\x00mocked core\nG\xfe\xe0\x10",
            "COREDUMP_CMDLINE": "python3",
            "COREDUMP_CWD": "/",
            "COREDUMP_ENVIRON": "SHELL=/bin/bash\n",
            "COREDUMP_EXE": sys.executable,
            "COREDUMP_GID": 0,
            "COREDUMP_PID": 123456789,
            "COREDUMP_PROC_MAPS": "mocked /proc/<pid>/maps",
            "COREDUMP_PROC_STATUS": "mocked /proc/<pid>/status",
            "COREDUMP_SIGNAL": 11,
            "COREDUMP_SIGNAL_NAME": "SIGSEGV",
            "COREDUMP_TIMESTAMP": datetime.datetime(
                2024, 2, 19, 12, 10, 42, tzinfo=datetime.timezone.utc
            ),
            "COREDUMP_UID": 0,
        }
        process_crash_mock.side_effect = lambda report, *_args: report

        report = apport_binary.process_crash_from_systemd_coredump("3-12345-7")

        get_systemd_coredump_mock.assert_called_once_with("3-12345-7")
        process_crash_mock.assert_called_once()
        self.assertEqual(report.pid, 123456789)
        self.assertEqual(
            dict(report),
            {
                "Date": "Mon Feb 19 12:10:42 2024",
                "CoreDump": b"(\xb5/\xfd$\x0ca\x00\x00mocked core\nG\xfe\xe0\x10",
                "ExecutablePath": sys.executable,
                "ExecutableTimestamp": str(int(os.stat(sys.executable).st_mtime)),
                "ProblemType": "Crash",
                "ProcCmdline": "python3",
                "ProcCwd": "/",
                "ProcEnviron": "SHELL=/bin/bash",
                "ProcMaps": "mocked /proc/<pid>/maps",
                "ProcStatus": "mocked /proc/<pid>/status",
                "Signal": "11",
                "SignalName": "SIGSEGV",
            },
        )

    @unittest.mock.patch.object(apport_binary, "process_crash")
    @unittest.mock.patch.object(apport_binary, "get_systemd_coredump")
    def test_process_crash_from_systemd_coredump_container(
        self, get_systemd_coredump_mock: MagicMock, process_crash_mock: MagicMock
    ) -> None:
        """Test process_crash_from_systemd_coredump with container crash"""
        get_systemd_coredump_mock.return_value = {
            "COREDUMP_CMDLINE": "divide-by-zero",
            "COREDUMP_CONTAINER_CMDLINE": "/usr/lib/systemd/systemd",
            "COREDUMP_CWD": "/root",
            "COREDUMP_ENVIRON": "SHELL=/bin/bash\n",
            "COREDUMP_EXE": "/usr/bin/divide-by-zero",
            "COREDUMP_GID": 297664512,
            "COREDUMP_PID": 523536,
            "COREDUMP_PROC_MAPS": "mocked /proc/<pid>/maps",
            "COREDUMP_PROC_STATUS": "mocked /proc/<pid>/status",
            "COREDUMP_SIGNAL": 4,
            "COREDUMP_SIGNAL_NAME": "SIGILL",
            "COREDUMP_TIMESTAMP": datetime.datetime(
                2024, 4, 25, 10, 52, 42, tzinfo=datetime.timezone.utc
            ),
            "COREDUMP_UID": 297664512,
        }

        with self.assertLogs(level="INFO") as info_logs:
            result = apport_binary.process_crash_from_systemd_coredump("0-523537-0")

        get_systemd_coredump_mock.assert_called_once_with("0-523537-0")
        process_crash_mock.assert_not_called()
        self.assertEqual(result, 0)
        self.assertIn(
            "Ignoring /usr/bin/divide-by-zero crash because it happened"
            " inside a container.",
            info_logs.output[0],
        )
