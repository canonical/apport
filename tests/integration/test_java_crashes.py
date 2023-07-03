# Copyright (C) 2010 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
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
import unittest

import apport.fileutils
import apport.report
from tests.helper import skip_if_command_is_missing
from tests.paths import get_data_directory, local_test_environment


@skip_if_command_is_missing("java")
class TestJavaCrashes(unittest.TestCase):
    def setUp(self):
        self.env = os.environ | local_test_environment()
        datadir = get_data_directory()
        self.orig_report_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = tempfile.mkdtemp()
        self.env["APPORT_REPORT_DIR"] = apport.fileutils.report_dir
        self.env["APPORT_JAVA_EXCEPTION_HANDLER"] = str(
            datadir / "java_uncaught_exception"
        )
        java_dir = get_data_directory("java")
        self.apport_jar_path = java_dir / "apport.jar"
        self.crash_jar_path = java_dir / "testsuite" / "crash.jar"
        if not self.apport_jar_path.exists():
            self.skipTest(f"{self.apport_jar_path} missing")

    def tearDown(self):
        shutil.rmtree(apport.fileutils.report_dir)
        apport.fileutils.report_dir = self.orig_report_dir

    def test_crash_class(self):
        """Crash in a .class file."""
        crash_class = self.crash_jar_path.with_suffix(".class")
        self.assertTrue(crash_class.exists(), f"{crash_class} missing")
        java = subprocess.run(
            [
                "java",
                "-classpath",
                f"{self.apport_jar_path}:{self.crash_jar_path.parent}",
                "crash",
            ],
            check=False,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(
            java.returncode, 0, "crash must exit with nonzero code"
        )
        self.assertIn("Can't catch this", java.stderr.decode())

        self._check_crash_report(str(crash_class))

    def test_crash_jar(self):
        """Crash in a .jar file."""
        self.assertTrue(
            self.crash_jar_path.exists(), f"{self.crash_jar_path} missing"
        )
        java = subprocess.run(
            [
                "java",
                "-classpath",
                f"{self.apport_jar_path}:{self.crash_jar_path}",
                "crash",
            ],
            check=False,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(
            java.returncode, 0, "crash must exit with nonzero code"
        )
        self.assertIn("Can't catch this", java.stderr.decode())

        self._check_crash_report(f"{self.crash_jar_path}!/crash.class")

    def _check_crash_report(self, main_file):
        """Check that we have one crash report, and verify its contents."""
        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 1, "did not create a crash report")
        report = apport.report.Report()
        with open(reports[0], "rb") as report_file:
            report.load(report_file)
        self.assertEqual(report["ProblemType"], "Crash")
        self.assertTrue(
            report["ProcCmdline"].startswith("java -classpath"), report
        )
        self.assertTrue(
            report["StackTrace"].startswith(
                "java.lang.RuntimeException: Can't catch this"
            )
        )
        if ".jar!" in main_file:
            self.assertEqual(report["MainClassUrl"], f"jar:file:{main_file}")
        else:
            self.assertEqual(report["MainClassUrl"], f"file:{main_file}")
        self.assertIn("DistroRelease", report)
        self.assertIn("ProcCwd", report)
