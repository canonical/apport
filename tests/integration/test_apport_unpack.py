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


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = (
            os.environ | local_test_environment() | {"LANGUAGE": "C.UTF-8"}
        )
        cls.workdir = tempfile.mkdtemp()

        # create problem report file with all possible data types
        r = problem_report.ProblemReport()
        cls.utf8_str = b"a\xe2\x99\xa5b"
        cls.bindata = b"\x00\x01\xFF\x40"
        r["utf8"] = cls.utf8_str
        r["unicode"] = cls.utf8_str.decode("UTF-8")
        r["binary"] = cls.bindata
        r["compressed"] = problem_report.CompressedValue(b"FooFoo!")
        r["separator"] = ""

        cls.report_file = os.path.join(cls.workdir, "test.apport")
        with open(cls.report_file, "wb") as f:
            r.write(f)

        cls.unpack_dir = os.path.join(cls.workdir, "un pack")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.workdir)

    def tearDown(self):
        if os.path.isdir(self.unpack_dir):
            shutil.rmtree(self.unpack_dir)

    def test_unpack(self):
        """apport-unpack for all possible data types"""

        self.assertEqual(
            self._call(["apport-unpack", self.report_file, self.unpack_dir]),
            (0, "", ""),
        )

        self.assertEqual(self._get_unpack("utf8"), self.utf8_str)
        self.assertEqual(self._get_unpack("unicode"), self.utf8_str)
        self.assertEqual(self._get_unpack("binary"), self.bindata)
        self.assertEqual(self._get_unpack("compressed"), b"FooFoo!")

    def test_help(self):
        """calling apport-unpack with help"""

        (ret, out, err) = self._call(["apport-unpack", "--help"])
        self.assertEqual(ret, 0)
        self.assertEqual(err, "")
        self.assertTrue(out.startswith("usage:"), out)

    def test_error(self):
        """calling apport-unpack with wrong arguments"""

        (ret, out, err) = self._call(["apport-unpack"])
        self.assertEqual(ret, 2)
        self.assertEqual(out, "")
        self.assertTrue(err.startswith("usage:"), out)

        (ret, out, err) = self._call(["apport-unpack", self.report_file])
        self.assertEqual(ret, 2)
        self.assertEqual(out, "")
        self.assertTrue(err.startswith("usage:"), out)

        (ret, out, err) = self._call(
            ["apport-unpack", "/nonexisting.crash", self.unpack_dir]
        )
        self.assertEqual(ret, 1)
        self.assertIn("/nonexisting.crash", err)
        self.assertEqual(out, "")

    def _call(self, argv):
        process = subprocess.run(
            argv,
            check=False,
            encoding="UTF-8",
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return (process.returncode, process.stdout, process.stderr)

    def _get_unpack(self, fname):
        with open(os.path.join(self.unpack_dir, fname), "rb") as f:
            return f.read()
