# Copyright (C) 2023 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for apport.unicode_gettext."""

import unittest
import unittest.mock

from apport import unicode_gettext


class TestDeprecation(unittest.TestCase):
    """Unit tests for apport.unicode_gettext."""

    def test_unicode_gettext(self) -> None:
        """unicode_gettext() throws a deprecation warning."""
        with self.assertWarns(PendingDeprecationWarning):
            self.assertEqual(unicode_gettext("untranslated"), "untranslated")
