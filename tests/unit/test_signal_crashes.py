# Copyright (C) 2022 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for data/apport."""

import os
import pathlib
import shutil
import tempfile
import time
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

    def test_sanity_checks_replaced_process(self):
        """Test sanity_checks() for a replaced crash process ID."""
        options = apport_binary.parse_arguments(["-p", str(os.getpid())])
        now = int(time.clock_gettime(time.CLOCK_BOOTTIME) * 100)
        self.assertFalse(apport_binary.sanity_checks(options, now))

    def test_sanity_checks_mismatching_uid(self):
        """Test sanity_checks() for a mitmatching UID."""
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
        self.assertFalse(apport_binary.sanity_checks(options, 1))

    def test_stop(self):
        """Test stopping Apport crash handler."""
        open_mock = unittest.mock.mock_open()
        with unittest.mock.patch("builtins.open", open_mock):
            apport_binary.stop_apport()
        open_mock.assert_called_with(
            "/proc/sys/kernel/core_pattern", "w", encoding="utf-8"
        )
        self.assertEqual(open_mock.call_count, 3)
