"""Integration tests for the GTK Apport user interface."""

# Copyright (C) 2025 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
# SPDX-License-Identifier: GPL-2.0-or-later

import io
import os
import unittest.mock

import pytest

from tests.helper import import_module_from_file, restore_os_environ
from tests.paths import get_data_directory


@restore_os_environ()
def test_unusable_display() -> None:
    """Test apport-gtk to not crash if no usable display is found (LP: #2006981)."""
    os.environ |= {"DISPLAY": ":42", "WAYLAND_DISPLAY": "bogus"}
    apport_gtk_path = get_data_directory("gtk") / "apport-gtk"
    with unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
        try:
            apport_gtk = import_module_from_file(apport_gtk_path)
        except SystemExit:
            pytest.skip(stderr.getvalue().strip())
    with unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
        with pytest.raises(SystemExit) as error:
            apport_gtk.main([str(apport_gtk_path)])

    assert (
        stderr.getvalue() == "ERROR: This program needs a running display server"
        ' session. Please see "man apport-cli" for a command line version of Apport.\n'
    )
    assert error.value.code == 1
