"""Test unkillable_shutdown"""

# Copyright (C) 2022 Canonical Ltd.
# Author: Benjamin Drung <bdrung@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import contextlib
import multiprocessing
import os
import shutil
import signal
import subprocess
import tempfile
import unittest
from collections.abc import Generator

from tests.paths import get_data_directory, local_test_environment


class TestUnkillableShutdown(unittest.TestCase):
    """Test unkillable_shutdown"""

    maxDiff = None
    TEST_EXECUTABLE = os.path.realpath("/bin/sleep")
    TEST_ARGS = ["86400"]

    def setUp(self) -> None:
        self.data_dir = get_data_directory()
        self.env = os.environ | local_test_environment()

        self.report_dir = tempfile.mkdtemp()
        self.env["APPORT_REPORT_DIR"] = self.report_dir

    def tearDown(self) -> None:
        shutil.rmtree(self.report_dir)

    def _call(self, omit: list | None = None) -> None:
        cmd = [str(self.data_dir / "unkillable_shutdown")]
        if omit:
            cmd += [arg for pid in omit for arg in ("-o", str(pid))]
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

    @staticmethod
    def _get_all_pids() -> list[int]:
        return [int(pid) for pid in os.listdir("/proc") if pid.isdigit()]

    @contextlib.contextmanager
    def _launch_process_with_different_session_id(
        self,
    ) -> Generator[multiprocessing.Process, None, None]:
        """Launch test executable with different session ID.

        getsid() will return a different ID than the current process.
        """

        def _run_test_executable(queue: multiprocessing.Queue) -> None:
            os.setsid()
            cmd = [self.TEST_EXECUTABLE] + self.TEST_ARGS
            with subprocess.Popen(cmd) as test_process:
                queue.put(test_process.pid)

        queue: multiprocessing.Queue = multiprocessing.Queue()
        runner = multiprocessing.Process(target=_run_test_executable, args=(queue,))
        runner.start()
        try:
            pid = queue.get(timeout=60)
            try:
                yield runner
            finally:
                os.kill(pid, signal.SIGHUP)
            runner.join(60)
        finally:
            runner.kill()

    def test_omit_all_processes(self) -> None:
        """unkillable_shutdown will write no reports."""
        self._call(omit=self._get_all_pids())
        self.assertEqual(os.listdir(self.report_dir), [])

    def test_omit_all_processes_except_one(self) -> None:
        """unkillable_shutdown will write exactly one report."""
        existing_pids = self._get_all_pids()
        with self._launch_process_with_different_session_id() as runner:
            self._call(omit=existing_pids + [runner.pid])
        self.assertEqual(
            os.listdir(self.report_dir),
            [f"{self.TEST_EXECUTABLE.replace('/', '_')}.{os.geteuid()}.crash"],
        )

    def test_write_reports(self) -> None:
        """unkillable_shutdown will write reports."""
        # Ensure that at least one process is honoured by unkillable_shutdown.
        with self._launch_process_with_different_session_id():
            self._call()
        reports = os.listdir(self.report_dir)
        self.assertGreater(len(reports), 0, reports)
