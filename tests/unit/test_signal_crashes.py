# Copyright (C) 2022 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for data/apport."""

import contextlib
import errno
import io
import os
import pathlib
import shutil
import sys
import tempfile
import time
import typing
import unittest

import apport.fileutils
from tests.helper import import_module_from_file
from tests.paths import get_data_directory

apport_binary = import_module_from_file(get_data_directory() / "apport")


class TestApport(unittest.TestCase):
    """Unit tests for data/apport."""

    @classmethod
    def setUpClass(cls):
        cls.orig_report_dir = apport.fileutils.report_dir

    @classmethod
    def tearDownClass(cls):
        apport.fileutils.report_dir = cls.orig_report_dir

    def setUp(self):
        self.workdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.workdir)
        apport.fileutils.report_dir = os.path.join(self.workdir, "crash")
        self.report_dir = pathlib.Path(apport.fileutils.report_dir)

    @staticmethod
    @contextlib.contextmanager
    def _open_dir(path: str) -> typing.Generator[int, None, None]:
        dir_fd = os.open(path, os.O_RDONLY | os.O_PATH | os.O_DIRECTORY)
        yield dir_fd
        os.close(dir_fd)

    @unittest.mock.patch("subprocess.run")
    def test_check_kernel_crash(self, run_mock):
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
    def test_check_lock_taken(
        self, lockf_mock: unittest.mock.MagicMock
    ) -> None:
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

    @unittest.mock.patch("os.isatty")
    def test_init_error_log_is_tty(
        self, isatty_mock: unittest.mock.MagicMock
    ) -> None:
        """Test init_error_log() doing nothing on a TTY."""
        isatty_mock.return_value = True
        stderr = sys.stderr
        apport_binary.init_error_log()
        # Check sys.stderr to be unchanged
        self.assertEqual(sys.stderr, stderr)
        isatty_mock.assert_called_once_with(2)

    @unittest.mock.patch("builtins.__import__")
    def test_receive_arguments_via_socket_import_error(self, import_mock):
        """Test receive_arguments_via_socket() fail to import systemd."""
        import_mock.side_effect = ModuleNotFoundError(
            "No module named 'systemd'"
        )
        with self.assertRaisesRegex(SystemExit, "^0$"):
            apport_binary.receive_arguments_via_socket()

    def test_receive_arguments_via_socket_invalid_socket(self):
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

    @unittest.mock.patch.object(
        apport_binary, "init_error_log", unittest.mock.MagicMock()
    )
    @unittest.mock.patch.object(
        apport_binary,
        "is_same_ns",
        unittest.mock.MagicMock(return_value=False),
    )
    @unittest.mock.patch.object(apport_binary, "forward_crash_to_container")
    def test_main_forward_crash_to_container(self, forward_mock):
        """Test main() to forward crash to container."""
        args = ["-p", "12345", "-P", "67890"]
        self.assertEqual(apport_binary.main(args), 0)
        forward_mock.assert_called_once()

    @unittest.mock.patch.object(
        apport_binary, "init_error_log", unittest.mock.MagicMock()
    )
    @unittest.mock.patch.object(apport_binary, "start_apport")
    def test_main_start(self, start_mock):
        """Test calling apport with --start."""
        self.assertEqual(apport_binary.main(["--start"]), 0)
        start_mock.assert_called_once_with()

    @unittest.mock.patch.object(
        apport_binary, "init_error_log", unittest.mock.MagicMock()
    )
    @unittest.mock.patch.object(apport_binary, "stop_apport")
    def test_main_stop(self, stop_mock):
        """Test calling apport with --stop."""
        self.assertEqual(apport_binary.main(["--stop"]), 0)
        stop_mock.assert_called_once_with()

    def test_start(self):
        """Test starting Apport crash handler."""
        open_mock = unittest.mock.mock_open()
        with unittest.mock.patch("builtins.open", open_mock):
            apport_binary.start_apport()
        open_mock.assert_called_with(
            "/proc/sys/kernel/core_pipe_limit", "w", encoding="utf-8"
        )
        self.assertEqual(open_mock.call_count, 3)

    def test_consistency_checks_replaced_process(self):
        """Test consistency_checks() for a replaced crash process ID."""
        options = apport_binary.parse_arguments(["-p", str(os.getpid())])
        now = int(time.clock_gettime(time.CLOCK_BOOTTIME) * 100)
        self.assertFalse(apport_binary.consistency_checks(options, now))

    def test_consistency_checks_mismatching_uid(self):
        """Test consistency_checks() for a mitmatching UID."""
        pid = os.getpid()
        options = apport_binary.parse_arguments(
            [
                "-p",
                str(pid),
                "-u",
                str(os.getuid() + 1),
                "-g",
                str(os.getgid() + 1),
            ]
        )
        # TODO: Get rid of global variables from get_pid_info
        apport_binary.get_pid_info(pid)
        self.assertFalse(apport_binary.consistency_checks(options, 1))

    def test_stop(self):
        """Test stopping Apport crash handler."""
        open_mock = unittest.mock.mock_open()
        with unittest.mock.patch("builtins.open", open_mock):
            apport_binary.stop_apport()
        open_mock.assert_called_with(
            "/proc/sys/kernel/core_pattern", "w", encoding="utf-8"
        )
        self.assertEqual(open_mock.call_count, 3)

    @unittest.mock.patch("os.setresgid", unittest.mock.MagicMock())
    @unittest.mock.patch("os.setresuid", unittest.mock.MagicMock())
    @unittest.mock.patch.object(
        apport_binary, "_run_with_output_limit_and_timeout"
    )
    @unittest.mock.patch("os.path.exists")
    def test_is_closing_session(
        self,
        path_exist_mock: unittest.mock.MagicMock,
        run_mock: unittest.mock.MagicMock,
    ) -> None:
        """Test is_closing_session()."""
        path_exist_mock.return_value = True
        run_mock.return_value = (b"(false,)\n", b"some stderr output\n")
        with tempfile.TemporaryDirectory() as tmpdir:
            env = pathlib.Path(tmpdir) / "environ"
            env.write_text(
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1337/bus\0"
            )
            with self._open_dir(tmpdir) as proc_pid_fd:
                # TODO: Get rid of global variables from get_pid_info
                apport_binary.proc_pid_fd = proc_pid_fd
                self.assertEqual(apport_binary.is_closing_session(), True)
        path_exist_mock.assert_called_once_with("/run/user/1337/bus")
        run_mock.assert_called_once()

    def test_is_closing_session_no_environ(self) -> None:
        """Test is_closing_session() with no DBUS_SESSION_BUS_ADDRESS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = pathlib.Path(tmpdir) / "environ"
            env.write_text("DISPLAY=:0\0")
            with self._open_dir(tmpdir) as proc_pid_fd:
                # TODO: Get rid of global variables from get_pid_info
                apport_binary.proc_pid_fd = proc_pid_fd
                self.assertEqual(apport_binary.is_closing_session(), False)

    def test_is_closing_session_no_determine_socket(self) -> None:
        """Test is_closing_session() cannot determine D-Bus socket."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = pathlib.Path(tmpdir) / "environ"
            env.write_text("DBUS_SESSION_BUS_ADDRESS=unix:/run/user/42/bus\0")
            with self._open_dir(tmpdir) as proc_pid_fd:
                # TODO: Get rid of global variables from get_pid_info
                apport_binary.proc_pid_fd = proc_pid_fd
                self.assertEqual(apport_binary.is_closing_session(), False)

    def test_is_closing_session_socket_not_exists(self) -> None:
        """Test is_closing_session() where D-Bus socket does not exist."""
        assert not os.path.exists("/run/user/1337/bus")
        with tempfile.TemporaryDirectory() as tmpdir:
            env = pathlib.Path(tmpdir) / "environ"
            env.write_text(
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1337/bus\0"
            )
            with self._open_dir(tmpdir) as proc_pid_fd:
                # TODO: Get rid of global variables from get_pid_info
                apport_binary.proc_pid_fd = proc_pid_fd
                self.assertEqual(apport_binary.is_closing_session(), False)

    @unittest.mock.patch("os.setresgid", unittest.mock.MagicMock())
    @unittest.mock.patch("os.setresuid", unittest.mock.MagicMock())
    @unittest.mock.patch.object(
        apport_binary, "_run_with_output_limit_and_timeout"
    )
    @unittest.mock.patch("os.path.exists")
    def test_is_closing_session_gdbus_failure(
        self,
        path_exist_mock: unittest.mock.MagicMock,
        run_mock: unittest.mock.MagicMock,
    ) -> None:
        """Test is_closing_session() with OSError from gdbus."""
        path_exist_mock.return_value = True
        run_mock.side_effect = OSError(
            errno.ENOENT, "No such file or directory: 'gdbus'"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            env = pathlib.Path(tmpdir) / "environ"
            env.write_text(
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1337/bus\0"
            )
            with self._open_dir(tmpdir) as proc_pid_fd:
                # TODO: Get rid of global variables from get_pid_info
                apport_binary.proc_pid_fd = proc_pid_fd
                self.assertEqual(apport_binary.is_closing_session(), False)
        path_exist_mock.assert_called_once_with("/run/user/1337/bus")
        run_mock.assert_called_once()

    @unittest.mock.patch.object(
        apport_binary, "check_lock", unittest.mock.MagicMock()
    )
    @unittest.mock.patch.object(
        apport_binary, "init_error_log", unittest.mock.MagicMock()
    )
    def test_missing_proc_pid(self) -> None:
        """Test /proc/<pid> is already gone."""
        fake_pid = 2147483647
        assert not os.path.exists(f"/proc/{fake_pid}")
        with self.assertLogs(level="ERROR") as error_logs:
            with tempfile.NamedTemporaryFile() as stdin:
                stdin_mock = io.FileIO(stdin.name)
                with unittest.mock.patch("sys.stdin", return_value=stdin_mock):
                    self.assertEqual(
                        apport_binary.main(["-p", str(fake_pid)]), 1
                    )
        self.assertIn("/proc/2147483647 not found", error_logs.output[0])
