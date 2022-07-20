"""Test unkillable_shutdown"""

# Copyright (C) 2022 Canonical Ltd.
# Author: Benjamin Drung <bdrung@ubuntu.com>
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
import typing
import unittest

from tests.paths import get_data_directory, local_test_environment


class TestUnkillableShutdown(unittest.TestCase):
    """Test unkillable_shutdown"""

    maxDiff = None
    TEST_EXECUTABLE = os.path.realpath("/bin/sleep")
    TEST_ARGS = ["86400"]

    def setUp(self):
        self.data_dir = get_data_directory()
        self.env = os.environ | local_test_environment()

        self.report_dir = tempfile.mkdtemp()
        self.env["APPORT_REPORT_DIR"] = self.report_dir

    def tearDown(self):
        shutil.rmtree(self.report_dir)

    def _call(
        self,
        omit: typing.Optional[list] = None,
        expected_stderr: typing.Optional[str] = None,
    ) -> None:
        cmd = [f"{self.data_dir}/unkillable_shutdown"]
        if omit:
            cmd += [arg for pid in omit for arg in ["-o", str(pid)]]
        process = subprocess.run(
            cmd,
            check=False,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout, "")
        if expected_stderr:
            self.assertEqual(process.stderr, expected_stderr)

    @staticmethod
    def _get_all_pids():
        return [int(pid) for pid in os.listdir("/proc") if pid.isdigit()]

    def test_omit_all_processes(self):
        """unkillable_shutdown will write no reports."""
        self._call(omit=self._get_all_pids(), expected_stderr="")
        self.assertEqual(os.listdir(self.report_dir), [])
