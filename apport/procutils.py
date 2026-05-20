# Copyright (C) 2026 Canonical Ltd.
# Author: Benjamin Drung <bdrung@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Functions to operate on files in /proc."""

import dataclasses


@dataclasses.dataclass
class Meminfo:
    """Data from /proc/meminfo. Values are in KiB.

    Only the needed values from /proc/meminfo are provided.
    This dataclass can be extended when needed.
    """

    mem_total: int
    mem_free: int
    mem_available: int
    cached: int
    writeback: int


def parse_meminfo() -> Meminfo:
    """Parse /proc/meminfo and return a dictionary for the requested keys."""
    remaining_keys = {"MemTotal", "MemFree", "MemAvailable", "Cached", "Writeback"}
    meminfo = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as meminfo_file:
        for line in meminfo_file:
            key, remaining = line.split(":", maxsplit=1)
            if key not in remaining_keys:
                continue
            value, unit = remaining.strip().split(maxsplit=2)
            assert unit == "kB" or value == "0"
            meminfo[key] = int(value)
            remaining_keys.remove(key)
            if not remaining_keys:
                return Meminfo(
                    meminfo["MemTotal"],
                    meminfo["MemFree"],
                    meminfo["MemAvailable"],
                    meminfo["Cached"],
                    meminfo["Writeback"],
                )
    raise KeyError(f"{', '.join(sorted(remaining_keys))} not found in /proc/meminfo")
