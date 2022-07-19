"""Test apport-checkreports"""

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

import apport.report
from tests.paths import get_data_directory, local_test_environment


class TestApportCheckreports(unittest.TestCase):
    """Test apport-checkreports"""

    def setUp(self):
        self.data_dir = get_data_directory()
        self.env = os.environ | local_test_environment()

        self.report_dir = tempfile.mkdtemp()
        self.env["APPORT_REPORT_DIR"] = self.report_dir

    def tearDown(self):
        shutil.rmtree(self.report_dir)

    def _call(
        self,
        args: typing.Optional[list] = None,
        expected_returncode: int = 0,
        expected_stdout: str = "",
    ) -> None:
        cmd = [f"{self.data_dir}/apport-checkreports"]
        if args:
            cmd += args
        process = subprocess.run(
            cmd,
            check=False,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(process.returncode, expected_returncode)
        self.assertEqual(process.stdout, expected_stdout)
        self.assertEqual(process.stderr, "")

    def _write_report(self, filename: str, user: bool = True) -> None:
        path = f"{self.report_dir}/{filename}"
        report = apport.report.Report()
        with open(path, "wb") as report_file:
            report.write(report_file)

        if user and os.geteuid() == 0:
            os.chown(path, 1000, -1)

    def test_has_no_system_report(self):
        self._write_report("_bin_sleep.1000.crash")
        self._call(args=["--system"], expected_returncode=1)

    @unittest.skipIf(os.geteuid() != 0, "this test needs to be run as root")
    def test_has_system_report(self):
        self._write_report("_usr_bin_yes.0.crash", user=False)
        self._call(args=["-s"], expected_returncode=0, expected_stdout="yes\n")

    def test_has_user_report(self):
        self._write_report("_bin_sleep.1000.crash")
        self._call(expected_returncode=0, expected_stdout="sleep\n")

    def test_no_report(self):
        self._call(expected_returncode=1)
