# Copyright (C) 2026 Canonical Ltd.
# Author: Benjamin Drung <bdrung@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Path and directory name manipulation utilities for Apport."""

import re


def format_dir_name(name: str, default: str = "unnamed", max_length: int = 255) -> str:
    """Format a string for use as a single directory name.

    Replaces path separators (/) and non-basic ASCII characters (like null byte,
    control characters, dollar sign) with underscores. Also remove leading dots.
    """
    name = re.sub(r"[^- +.0-9A-Z_a-z]+", "_", name).lstrip(" _.")
    name_bytes = name.encode("utf-8")[:max_length]
    name = name_bytes.decode("utf-8", errors="ignore").rstrip(" _")
    if not name:
        return default
    return name
