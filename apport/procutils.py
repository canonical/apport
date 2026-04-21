# Copyright (C) 2026 Canonical Ltd.
# Author: Benjamin Drung <bdrung@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Functions to operate on files in /proc."""

from collections.abc import Iterable


def parse_meminfo(keys: Iterable[str]) -> dict[str, int]:
    """Parse /proc/meminfo and return a dictionary for the requested keys."""
    remaining_keys = set(keys)
    meminfo = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as meminfo_file:
        for line in meminfo_file:
            key, remaining = line.split(":", maxsplit=1)
            if key not in remaining_keys:
                continue
            value = remaining.strip().split(maxsplit=1)[0]
            meminfo[key] = int(value)
            remaining_keys.remove(key)
            if not remaining_keys:
                return meminfo
    raise KeyError(f"{' '.join(sorted(remaining_keys))} not found in /proc/meminfo")
