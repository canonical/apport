# Copyright (C) 2024 Canonical Ltd.
# Author: Benjamin Drung <bdrung@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Validate XML files."""

import subprocess

import pytest

from tests.paths import is_local_source_directory


def get_policy_xml() -> str:
    """Determine path to Apport PolicyKit XML."""
    if not is_local_source_directory():
        return "/usr/share/polkit-1/actions/com.ubuntu.apport.policy"
    policy_xml = "build/share/polkit-1/actions/com.ubuntu.apport.policy"
    return policy_xml


def test_validate_xml() -> None:
    """Validate Apport PolicyKit XML."""
    cmd = [
        "xmllint",
        "--noout",
        "--nonet",
        "--dtdvalid",
        "/usr/share/polkit-1/policyconfig-1.dtd",
        get_policy_xml(),
    ]
    try:
        subprocess.check_call(cmd)
    except FileNotFoundError as error:
        pytest.skip(f"{error.filename} not available")
