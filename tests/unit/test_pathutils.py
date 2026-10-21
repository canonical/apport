# Copyright (C) 2026 Canonical Ltd.
# Author: Benjamin Drung <bdrung@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for the apport.pathutils module."""

from apport.pathutils import format_dir_name


def test_format_dir_name_control_characters() -> None:
    """format_dir_name() on control characters."""
    assert format_dir_name(" some\x00input/\npath ") == "some_input_path"


def test_format_dir_name_debian_distro_release() -> None:
    """format_dir_name() on correct Debian release."""
    assert format_dir_name("Debian GNU/Linux 13") == "Debian GNU_Linux 13"


def test_format_dir_name_empty() -> None:
    """format_dir_name() on empty string."""
    assert format_dir_name(" .. \n ", default="empty") == "empty"


def test_format_dir_name_path_traversal() -> None:
    """format_dir_name() on path traversal."""
    assert format_dir_name("../../etc/passwd") == "etc_passwd"


def test_format_dir_name_ubuntu_distro_release() -> None:
    """format_dir_name() on correct Ubuntu release."""
    assert format_dir_name("Ubuntu 26.04") == "Ubuntu 26.04"
