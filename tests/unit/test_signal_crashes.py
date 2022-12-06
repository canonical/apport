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
import unittest

import apport.fileutils
from tests.helper import import_module_from_file
from tests.paths import get_data_directory

apport_binary = import_module_from_file(
    os.path.join(get_data_directory(), "apport")
)


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

    @unittest.mock.patch.object(apport_binary, "start_apport")
    def test_main_start(self, start_mock):
        """Test calling apport with --start."""
        self.assertEqual(apport_binary.main(["--start"]), 0)
        start_mock.assert_called_once_with()

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

    def test_stop(self):
        """Test stopping Apport crash handler."""
        open_mock = unittest.mock.mock_open()
        with unittest.mock.patch("builtins.open", open_mock):
            apport_binary.stop_apport()
        open_mock.assert_called_with(
            "/proc/sys/kernel/core_pattern", "w", encoding="utf-8"
        )
        self.assertEqual(open_mock.call_count, 3)
