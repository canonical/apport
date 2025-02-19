"""Integration tests for the Qt Apport user interface."""

# Copyright (C) 2025 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
# SPDX-License-Identifier: GPL-2.0-or-later

import io
from unittest.mock import patch

import pytest

from tests.helper import import_module_from_file
from tests.paths import get_data_directory


def test_no_environment_variables() -> None:
    """Test launching apport-kde without any environment variables set."""
    apport_kde_path = get_data_directory("kde") / "apport-kde"
    with patch("sys.stderr", new_callable=io.StringIO) as stderr:
        try:
            apport_kde = import_module_from_file(apport_kde_path)
        except SystemExit:
            pytest.skip(stderr.getvalue().strip())
    with (
        patch.dict("os.environ", {}, clear=True),
        patch("sys.stderr", new_callable=io.StringIO) as stderr,
        pytest.raises(SystemExit) as error,
    ):
        apport_kde.main([str(apport_kde_path)])

    assert (
        stderr.getvalue() == "ERROR: This program needs a running X"
        ' session. Please see "man apport-cli" for a command line version of Apport.\n'
    )
    assert error.value.code == 1
