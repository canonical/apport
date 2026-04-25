# Copyright (C) 2026 Canonical Ltd.
# Author: Benjamin Drung <bdrung@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for the apport.procutils module."""

from unittest.mock import mock_open, patch

import pytest

from apport.procutils import parse_meminfo


def test_parse_meminfo() -> None:
    """Test parse_meminfo() reading all values successfully."""
    open_mock = mock_open(
        read_data=(
            "MemTotal:       128887668 kB\n"
            "MemFree:        81203612 kB\n"
            "HugePages_Total:       0\n"
            "DirectMap1G:    127926272 kB\n"
        )
    )
    with patch("builtins.open", open_mock):
        meminfo = parse_meminfo({"MemTotal", "MemFree", "HugePages_Total"})
    assert meminfo["MemTotal"] == 128887668
    assert meminfo["MemFree"] == 81203612
    assert meminfo["HugePages_Total"] == 0
    assert len(meminfo) == 3


def test_parse_meminfo_missing_key() -> None:
    """Test parse_meminfo() failing to read the requested keys."""
    open_mock = mock_open(
        read_data=("MemTotal:       128887668 kB\nMemFree:        81203612 kB\n")
    )
    with patch("builtins.open", open_mock):
        with pytest.raises(KeyError) as exc_info:
            parse_meminfo({"MemTotal", "MemAvailable"})
    exc_info.match("MemAvailable not found in /proc/meminfo")
