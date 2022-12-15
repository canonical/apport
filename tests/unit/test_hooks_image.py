# Copyright (C) 2022 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for data/general-hooks/image.py."""

import os
import unittest

import problem_report
from tests.helper import import_module_from_file
from tests.paths import get_data_directory

image = import_module_from_file(
    os.path.join(get_data_directory(), "general-hooks", "image.py")
)


class TestGeneralHookImage(unittest.TestCase):
    """Unit tests for data/general-hooks/image.py."""

    @unittest.mock.patch(
        "os.path.isfile", unittest.mock.MagicMock(return_value=True)
    )
    def test_add_info(self):
        """Test add_info() for Ubuntu 22.04 server cloud image."""
        report = problem_report.ProblemReport()
        open_mock = unittest.mock.mock_open(
            read_data="build_name: server\nserial: 20221214\n"
        )
        with unittest.mock.patch("builtins.open", open_mock):
            image.add_info(report, None)
        self.assertEqual(
            set(report.keys()),
            {"CloudBuildName", "CloudSerial", "Date", "ProblemType", "Tags"},
        )
        self.assertEqual(report["CloudBuildName"], "server")
        self.assertEqual(report["CloudSerial"], "20221214")
        self.assertEqual(report["Tags"], "cloud-image")
        open_mock.assert_called_with("/etc/cloud/build.info", encoding="utf-8")

    @unittest.mock.patch(
        "os.path.isfile", unittest.mock.MagicMock(return_value=True)
    )
    def test_add_info_empty_build_info(self):
        """Test add_info() with empty /etc/cloud/build.info."""
        report = problem_report.ProblemReport()
        open_mock = unittest.mock.mock_open(read_data="\n")
        with unittest.mock.patch("builtins.open", open_mock):
            image.add_info(report, None)
        self.assertEqual(set(report.keys()), {"Date", "ProblemType", "Tags"})
        self.assertEqual(report["Tags"], "cloud-image")
        open_mock.assert_called_with("/etc/cloud/build.info", encoding="utf-8")

    @unittest.mock.patch(
        "os.path.isfile", unittest.mock.MagicMock(return_value=True)
    )
    def test_add_info_unknown_field(self):
        """Test add_info() with unknown field in /etc/cloud/build.info."""
        report = problem_report.ProblemReport()
        open_mock = unittest.mock.mock_open(
            read_data="unknown: value\nserial: 20221214\n"
        )
        with unittest.mock.patch("builtins.open", open_mock):
            image.add_info(report, None)
        self.assertEqual(
            set(report.keys()), {"CloudSerial", "Date", "ProblemType", "Tags"}
        )
        self.assertEqual(report["CloudSerial"], "20221214")
        self.assertEqual(report["Tags"], "cloud-image")
        open_mock.assert_called_with("/etc/cloud/build.info", encoding="utf-8")

    @unittest.mock.patch("os.path.isfile")
    def test_no_cloud_build_info(self, isfile_mock):
        """Test add_info() with no /etc/cloud/build.info."""
        isfile_mock.return_value = False
        report = problem_report.ProblemReport()
        image.add_info(report, None)
        self.assertEqual(set(report.keys()), {"Date", "ProblemType"})
        isfile_mock.assert_called_once_with("/etc/cloud/build.info")
