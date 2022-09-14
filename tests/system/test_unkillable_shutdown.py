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
import signal
import subprocess
import tempfile
import typing
import unittest

from tests.helper import get_init_system, pidof
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

    @unittest.skipIf(
        get_init_system() != "systemd", "running init system is not systemd"
    )
    def _launch_process_with_different_session_id(self) -> int:
        """Launch test executable with different session ID.

        getsid() will return a different ID than the current process.
        """
        service_manager = "--system" if os.geteuid() == 0 else "--user"
        existing_pids = self._get_all_pids()
        try:
            subprocess.run(
                ["systemd-run", service_manager, self.TEST_EXECUTABLE]
                + self.TEST_ARGS,
                check=True,
            )
        except FileNotFoundError as error:  # pragma: no cover
            self.skipTest(f"{error.filename} not available")
        test_executable_pids = {
            pid
            for pid in pidof(self.TEST_EXECUTABLE)
            if pid not in existing_pids
        }
        self.assertEqual(len(test_executable_pids), 1, test_executable_pids)
        return test_executable_pids.pop()

    def test_omit_all_processes_except_one(self):
        """unkillable_shutdown will write exactly one report."""
        existing_pids = self._get_all_pids()
        pid = self._launch_process_with_different_session_id()
        try:
            self._call(omit=existing_pids, expected_stderr="")
        finally:
            os.kill(pid, signal.SIGHUP)
        self.assertEqual(
            os.listdir(self.report_dir),
            [f"{self.TEST_EXECUTABLE.replace('/', '_')}.{os.geteuid()}.crash"],
        )

    def test_write_reports(self):
        """unkillable_shutdown will write reports."""
        # Ensure that at least one process is honoured by unkillable_shutdown.
        pid = self._launch_process_with_different_session_id()
        try:
            self._call()
        finally:
            os.kill(pid, signal.SIGHUP)
        reports = os.listdir(self.report_dir)
        self.assertGreater(len(reports), 0, reports)
