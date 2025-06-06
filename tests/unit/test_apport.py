# Copyright (C) 2025 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for functions in the base apport module."""

from apport import Report, packaging


def test_report() -> None:
    """Test using Report imported from the base apport module."""
    report = Report()
    assert report["ProblemType"] == "Crash"


def test_packaging() -> None:
    """Test using packaging imported from the base apport module."""
    assert packaging.get_source("gzip") == "gzip"
