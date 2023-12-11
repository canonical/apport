"""Test apport-unpack"""

# Copyright (C) 2012 Canonical Ltd.
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

import problem_report
from tests.paths import local_test_environment


class TestApportUnpack(unittest.TestCase):
    # pylint: disable=missing-class-docstring,missing-function-docstring
    UTF8_STR = b"a\xe2\x99\xa5b"
    BINDATA = b"\x00\x01\xFF\x40"
    env: dict[str, str]

    @classmethod
    def setUpClass(cls):
        cls.env = os.environ | local_test_environment() | {"LANGUAGE": "C.UTF-8"}
        cls.workdir = tempfile.mkdtemp()

        # create problem report file with all possible data types
        report = problem_report.ProblemReport()
        report["utf8"] = cls.UTF8_STR
        report["unicode"] = cls.UTF8_STR.decode("UTF-8")
        report["binary"] = cls.BINDATA
        report["compressed"] = problem_report.CompressedValue(b"FooFoo!")
        report["separator"] = ""

        cls.report_file = os.path.join(cls.workdir, "test.apport")
        with open(cls.report_file, "wb") as report_file:
            report.write(report_file)

        cls.unpack_dir = os.path.join(cls.workdir, "un pack")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.workdir)

    def tearDown(self):
        if os.path.isdir(self.unpack_dir):
            shutil.rmtree(self.unpack_dir)

    def test_unpack(self):
        """apport-unpack for all possible data types"""
        process = self._call_apport_unpack([self.report_file, self.unpack_dir])
        self.assertEqual(process.returncode, 0)
        self.assertEqual(process.stderr, "")
        self.assertEqual(process.stdout, "")

        self.assertEqual(self._get_unpack("utf8"), self.UTF8_STR)
        self.assertEqual(self._get_unpack("unicode"), self.UTF8_STR)
        self.assertEqual(self._get_unpack("binary"), self.BINDATA)
        self.assertEqual(self._get_unpack("compressed"), b"FooFoo!")

    def test_unpack_stdin(self):
        """apport-unpack unpacks report from stdin"""
        with open(self.report_file, "rb") as report_file:
            process = subprocess.run(
                ["apport-unpack", "-", self.unpack_dir],
                check=False,
                env=self.env,
                stdin=report_file,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        self.assertEqual(process.stderr, b"", process.stderr.decode())
        self.assertEqual(process.stdout, b"", process.stdout.decode())
        self.assertEqual(process.returncode, 0)

        self.assertEqual(self._get_unpack("utf8"), self.UTF8_STR)
        self.assertEqual(self._get_unpack("unicode"), self.UTF8_STR)
        self.assertEqual(self._get_unpack("binary"), self.BINDATA)
        self.assertEqual(self._get_unpack("compressed"), b"FooFoo!")

    def test_help(self):
        """Call apport-unpack with --help."""
        process = self._call_apport_unpack(["--help"])
        self.assertEqual(process.returncode, 0)
        self.assertEqual(process.stderr, "")
        self.assertTrue(process.stdout.startswith("usage:"), process.stdout)

    def test_error(self):
        """Call apport-unpack with wrong arguments."""
        process = self._call_apport_unpack([])
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, "")
        self.assertTrue(process.stderr.startswith("usage:"), process.stderr)

        process = self._call_apport_unpack([self.report_file])
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, "")
        self.assertTrue(process.stderr.startswith("usage:"), process.stderr)

        process = self._call_apport_unpack(["/nonexisting.crash", self.unpack_dir])
        self.assertEqual(process.returncode, 1)
        self.assertIn("/nonexisting.crash", process.stderr)
        self.assertEqual(process.stdout, "")

    def test_broken_report(self):
        with tempfile.NamedTemporaryFile("wb") as report_file:
            report_file.write(b"AB\xfc:CD\n")
            report_file.flush()
            process = self._call_apport_unpack([report_file.name, self.unpack_dir])

        self.assertEqual(process.returncode, 1)
        self.assertEqual(
            process.stderr,
            "ERROR: Malformed problem report: 'ascii' codec can't decode "
            "byte 0xfc in position 2: ordinal not in range(128). "
            "Is this a proper .crash text file?\n",
        )
        self.assertEqual(process.stdout, "")

    def test_broken_core_dump(self):
        """Test unpacking a report file that has a malformed CoreDump entry."""
        with tempfile.NamedTemporaryFile("wb") as report_file:
            report_file.write(
                b"CoreDump: base64\n H4sICAAAAAAC/0NvcmVEdW1wAA==\n"
                b" 7Z0LYFPV/cdP0rQ\n"
            )
            report_file.flush()
            process = self._call_apport_unpack([report_file.name, self.unpack_dir])

        self.assertEqual(process.returncode, 1)
        self.assertEqual(
            process.stderr,
            "ERROR: Malformed problem report: Incorrect padding. "
            "Is this a proper .crash text file?\n",
        )
        self.assertEqual(process.stdout, "")

    def _call_apport_unpack(self, argv: list) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["apport-unpack"] + argv,
            check=False,
            encoding="UTF-8",
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def _get_unpack(self, fname):
        with open(os.path.join(self.unpack_dir, fname), "rb") as file_:
            return file_.read()
