"""Test dupdb-admin"""

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
import unittest

from apport.crashdb_impl.memory import CrashDatabase
from tests.paths import local_test_environment


class TestDupdbAdmin(unittest.TestCase):
    # pylint: disable=missing-function-docstring
    """Test dupdb-admin"""

    env: dict[str, str]
    db_file: str
    workdir: str

    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp()
        self.db_file = os.path.join(self.workdir, "apport_duplicates.db")
        self.env = os.environ | local_test_environment()

        self.crashes = CrashDatabase(
            None, {"sample_data": "1", "dupdb_url": f"file://{self.db_file}"}
        )
        self.crashes.init_duplicate_db(self.db_file)

    def tearDown(self) -> None:
        shutil.rmtree(self.workdir)

    def _call(
        self, args: list, expected_returncode: int = 0, expected_stdout: str | None = ""
    ) -> tuple[str, str]:
        cmd = ["dupdb-admin", "-f", self.db_file] + args
        process = subprocess.run(
            cmd,
            check=False,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(process.returncode, expected_returncode, process.stderr)
        if process.returncode == 0:
            self.assertEqual(process.stderr, "")
        if expected_stdout is not None:
            self.assertEqual(process.stdout, expected_stdout)
        return (process.stdout, process.stderr)

    @staticmethod
    def _find_files_and_directories(base_dir: str) -> tuple[list[str], list[str]]:
        found_directories = []
        found_files = []
        for root, dirs, files in os.walk(base_dir):
            found_directories += [
                os.path.relpath(f"{root}/{d}", start=base_dir) for d in dirs
            ]
            found_files += [
                os.path.relpath(f"{root}/{f}", start=base_dir) for f in files
            ]
        return sorted(found_directories), sorted(found_files)

    def test_dump_empty_database(self) -> None:
        self._call(["dump"])

    def test_dump_database(self) -> None:
        self.assertIsNone(self.crashes.check_duplicate(0))
        self.assertIsNone(self.crashes.check_duplicate(2))
        self.crashes.duplicate_db_fixed(2, "42")
        stdout = self._call(["dump"], expected_stdout=None)[0]

        lines = stdout.rstrip().split("\n")
        self.assertEqual(len(lines), 2, lines)
        self.assertIn(
            "0: /bin/crash:11:foo_bar:d01:raise:<signal handler called>:__frob"
            " [open]",
            lines[0],
        )
        self.assertIn("2: /usr/bin/broken:11:h:g:f:e:d [fixed in: 42]", lines[1])

    def test_changeid(self) -> None:
        self.assertIsNone(self.crashes.check_duplicate(2))
        self._call(["changeid", "2", "1"])
        stdout = self._call(["dump"], expected_stdout=None)[0]
        self.assertIn("1: /usr/bin/broken:11:h:g:f:e:d [open]", stdout)

    def test_changeid_missing_argument(self) -> None:
        self.assertIsNone(self.crashes.check_duplicate(2))
        stderr = self._call(["changeid", "2"], expected_returncode=2)[1]
        self.assertIn("the following arguments are required: new_id", stderr)

    def test_missing_db_file(self) -> None:
        os.remove(self.db_file)
        stderr = self._call(["dump"], expected_returncode=1)[1]
        self.assertIn("file does not exist", stderr)

    def test_no_command(self) -> None:
        stderr = self._call([], expected_returncode=2)[1]
        self.assertIn("the following arguments are required: command", stderr)

    def test_publish(self) -> None:
        self.assertIsNone(self.crashes.check_duplicate(1))
        pub_path = f"{self.workdir}/www"
        self._call(["publish", pub_path])
        directories, files = self._find_files_and_directories(pub_path)
        self.assertEqual(directories, ["address", "sig"])
        self.assertEqual(files, ["sig/_bin_crash_11"])

    def test_publish_missing_argument(self) -> None:
        stderr = self._call(["publish"], expected_returncode=2)[1]
        self.assertIn("the following arguments are required: path", stderr)

    def test_removeid(self) -> None:
        self.assertIsNone(self.crashes.check_duplicate(1))
        self._call(["removeid", "1"])
        self._call(["dump"])

    def test_removeid_missing_argument(self) -> None:
        self.assertIsNone(self.crashes.check_duplicate(1))
        stderr = self._call(["removeid"], expected_returncode=2)[1]
        self.assertIn("the following arguments are required: id", stderr)

    def test_unknown_command(self) -> None:
        stderr = self._call(["nonexisting"], expected_returncode=2)[1]
        self.assertIn("invalid choice: 'nonexisting'", stderr)
