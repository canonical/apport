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

from apport.procutils import Meminfo, parse_meminfo


def test_parse_meminfo() -> None:
    """Test parse_meminfo() reading all values successfully."""
    open_mock = mock_open(
        read_data=(
            "MemTotal:       64249228 kB\n"
            "MemFree:        25066812 kB\n"
            "MemAvailable:   40437820 kB\n"
            "Buffers:          587236 kB\n"
            "Cached:         19694816 kB\n"
            "Writeback:             0 kB\n"
        )
    )
    with patch("builtins.open", open_mock):
        meminfo = parse_meminfo()
    assert meminfo == Meminfo(64249228, 25066812, 40437820, 19694816, 0)


def test_parse_meminfo_missing_key() -> None:
    """Test parse_meminfo() failing to read the requested keys."""
    open_mock = mock_open(
        read_data=(
            "MemTotal:       64249228 kB\n"
            "MemFree:        23434628 kB\n"
            "MemAvailable:   38809072 kB\n"
            "Buffers:          589372 kB\n"
            "Cached:         20099444 kB\n"
        )
    )
    with patch("builtins.open", open_mock):
        with pytest.raises(KeyError) as exc_info:
            parse_meminfo()
    exc_info.match("Writeback not found in /proc/meminfo")
