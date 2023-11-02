# Copyright (C) 2022 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Integration tests for whoopsie-upload-all."""

import io
import os
import shutil
import tempfile
import unittest
import unittest.mock

from tests.helper import import_module_from_file
from tests.paths import get_data_directory

whoopsie_upload_all = import_module_from_file(
    get_data_directory() / "whoopsie-upload-all"
)


class TestWhoopsieUploadAll(unittest.TestCase):
    """Integration tests for whoopsie-upload-all."""

    def setUp(self):
        self.report_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.report_dir)

    def _write_report(self, content: bytes) -> str:
        report = os.path.join(self.report_dir, "testcase.crash")
        with open(report, "wb") as report_file:
            report_file.write(content)
        return report

    @unittest.mock.patch("sys.stderr", new_callable=io.StringIO)
    def test_process_report_malformed_report(self, stderr_mock):
        """Test process_report() raises MalformedProblemReport."""
        report = self._write_report(b"AB\xfc:CD\n")
        self.assertIsNone(whoopsie_upload_all.process_report(report))
        self.assertIn(
            "Malformed problem report: 'ascii' codec can't decode byte 0xfc"
            " in position 2: ordinal not in range(128).",
            stderr_mock.getvalue(),
        )
