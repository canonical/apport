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
import time
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
        return self._wait_for_process(self.TEST_EXECUTABLE, existing_pids)

    def _wait_for_process(
        self,
        program: str,
        existing_pids: typing.Container[int],
        timeout_sec=5.0,
    ) -> int:
        """Wait until one process with the given name is running."""
        timeout = 0.0
        while timeout < timeout_sec:
            pids = {pid for pid in pidof(program) if pid not in existing_pids}
            if pids:
                self.assertEqual(len(pids), 1, pids)
                return pids.pop()

            time.sleep(0.1)
            timeout += 0.1

        self.fail(
            f"Process {program} not started within {int(timeout)} seconds."
        )

    @unittest.mock.patch("tests.system.test_unkillable_shutdown.pidof")
    @unittest.mock.patch("time.sleep")
    def test_wait_for_process_timeout(self, sleep_mock, pidof_mock):
        """Test wait_for_gdb_child_process() helper runs into timeout."""
        pidof_mock.return_value = []
        with unittest.mock.patch.object(self, "fail") as fail_mock:
            self._wait_for_process(self.TEST_EXECUTABLE, [])
        fail_mock.assert_called_once()
        sleep_mock.assert_called_with(0.1)
        self.assertEqual(sleep_mock.call_count, 51)

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
