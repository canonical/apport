"""Test recoverable_problem"""

# Copyright (C) 2012 Canonical Ltd.
# Author: Evan Dandrea <ev@ubuntu.com>
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
import time
import unittest

import apport.report
from tests.paths import get_data_directory, local_test_environment


class T(unittest.TestCase):
    def setUp(self):
        self.env = os.environ | local_test_environment()
        self.report_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.report_dir)
        self.env["APPORT_REPORT_DIR"] = self.report_dir
        self.datadir = get_data_directory()

    def wait_for_report(self):
        seconds = 0
        while seconds < 10:
            crashes = os.listdir(self.report_dir)
            if crashes:
                assert len(crashes) == 1
                return os.path.join(self.report_dir, crashes[0])

            time.sleep(0.1)
            seconds += 0.1
        self.fail(
            f"timeout while waiting for .crash file to be created"
            f" in {self.report_dir}."
        )

    def call_recoverable_problem(self, data):
        cmd = ["%s/recoverable_problem" % self.datadir]
        proc = subprocess.run(
            cmd,
            check=False,
            env=self.env,
            input=data,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            # we expect some error message
            self.assertNotEqual(proc.stderr, "")
            raise subprocess.CalledProcessError(proc.returncode, cmd[0])
        self.assertEqual(proc.stderr, "")

    def test_recoverable_problem(self):
        """recoverable_problem with valid data"""
        self.call_recoverable_problem("hello\0there")
        path = self.wait_for_report()
        with open(path, "rb") as report_path:
            report = apport.report.Report()
            report.load(report_path)
            self.assertEqual(report["hello"], "there")
            self.assertIn("Pid:\t%d" % os.getpid(), report["ProcStatus"])

    def test_recoverable_problem_dupe_sig(self):
        """recoverable_problem duplicate signature includes ExecutablePath"""
        self.call_recoverable_problem("Package\0test\0DuplicateSignature\0ds")
        path = self.wait_for_report()
        with open(path, "rb") as report_path:
            report = apport.report.Report()
            report.load(report_path)
            exec_path = report.get("ExecutablePath")
            self.assertEqual(
                report["DuplicateSignature"], "%s:ds" % (exec_path)
            )
            self.assertIn("Pid:\t%d" % os.getpid(), report["ProcStatus"])

    def test_invalid_data(self):
        """recoverable_problem with invalid data"""
        self.assertRaises(
            subprocess.CalledProcessError,
            self.call_recoverable_problem,
            "hello",
        )

        self.assertRaises(
            subprocess.CalledProcessError,
            self.call_recoverable_problem,
            "hello\0there\0extraneous",
        )

        self.assertRaises(
            subprocess.CalledProcessError,
            self.call_recoverable_problem,
            "hello\0\0there",
        )
