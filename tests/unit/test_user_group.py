# Copyright (C) 2023 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
# SPDX-License-Identifier: GPL-2.0-or-later

"""Unit tests for apport.user_group."""

import unittest
from unittest.mock import MagicMock, patch

from apport.user_group import get_process_user_and_group


class TestUserGroup(unittest.TestCase):
    # pylint: disable=missing-function-docstring
    """Unit tests for apport.user_group."""

    @patch("os.getgid", MagicMock(return_value=0))
    @patch("os.getuid", MagicMock(return_value=0))
    def test_get_process_user_and_group_is_root(self) -> None:
        self.assertTrue(get_process_user_and_group().is_root())

    @patch("os.getgid", MagicMock(return_value=2000))
    @patch("os.getuid", MagicMock(return_value=3000))
    def test_get_process_user_and_group_is_not_root(self) -> None:
        self.assertFalse(get_process_user_and_group().is_root())
