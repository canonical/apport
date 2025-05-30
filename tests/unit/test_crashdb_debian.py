# Copyright (C) 2025 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for apport.crash_impl.debian"""

from apport.crashdb_impl.debian import CrashDatabase
from apport.report import Report


def test_missing_sender() -> None:
    """Test missing sender in CrashDB configuration."""
    crashdb = CrashDatabase(None, {})
    report = Report()
    assert crashdb.accepts(report)
    assert report["UnreportableReason"] == (
        "Please configure sender settings in /etc/apport/crashdb.conf"
    )
