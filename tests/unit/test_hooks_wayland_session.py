# Copyright (C) 2023 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for data/general-hooks/wayland_session.py."""

import unittest
import unittest.mock

import problem_report
from tests.helper import import_module_from_file
from tests.paths import get_data_directory

wayland_session = import_module_from_file(
    get_data_directory() / "general-hooks" / "wayland_session.py"
)


class TestGeneralHookWaylandSession(unittest.TestCase):
    """Unit tests for data/general-hooks/wayland_session.py."""

    @unittest.mock.patch.dict("os.environ", {"WAYLAND_DISPLAY": "wayland-0"})
    def test_is_wayland_session(self) -> None:
        """Test add_info() for a Wayland session."""
        report = problem_report.ProblemReport()
        wayland_session.add_info(report, None)
        self.assertEqual(set(report.keys()), {"Date", "ProblemType", "Tags"})
        self.assertEqual(report["Tags"], "wayland-session")

    @unittest.mock.patch.dict("os.environ", {}, clear=True)
    def test_is_no_wayland_session(self) -> None:
        """Test add_info() for a session that isn't using Wayland."""
        report = problem_report.ProblemReport()
        wayland_session.add_info(report, None)
        self.assertEqual(set(report.keys()), {"Date", "ProblemType"})
