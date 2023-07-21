# Copyright (C) 2022 Canonical Ltd.
# Author: Nathan Pratta Teodosio
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Integration tests for the apport.crashdb_impl.github module."""

import unittest
from unittest.mock import ANY, Mock, patch

try:
    import apport.crashdb_impl.github

    IMPORT_ERROR = None
except ImportError as error:
    IMPORT_ERROR = error


@unittest.skipIf(IMPORT_ERROR, f"module not available: {IMPORT_ERROR}")
class TestGitHub(unittest.TestCase):
    # pylint: disable=missing-class-docstring,missing-function-docstring
    # pylint: disable=protected-access

    def setUp(self):
        self.crashdb = self._get_gh_database("Lorem", "Ipsum")
        self.crashdb_barren = self._get_gh_database(None, None)

        self.message_cb = Mock()
        self.github = apport.crashdb_impl.github.Github(
            self.crashdb.app_id, self.message_cb
        )

        self.api_auth_return_value = {
            "verification_uri": None,
            "user_code": 123,
            "device_code": "d123",
            "interval": 1,
            "expires_in": 20,
        }

    def test__format_report(self):
        data = {"bold1": "normal1", "bold2": "normal2"}
        expected_body = "**bold1**\nnormal1\n\n**bold2**\nnormal2\n\n"

        result = self.crashdb._format_report(data)
        self.assertTrue("body" in result and result["body"] == expected_body)
        self.assertTrue("title" in result)
        self.assertTrue(self.crashdb.labels == set(result["labels"]))

    @patch("apport.crashdb_impl.github.Github.api_authentication")
    @patch("apport.crashdb_impl.github.Github.api_open_issue")
    @patch("apport.crashdb_impl.github.Github.authentication_complete")
    def test_upload(self, mock_auth, mock_api, mock_api_auth):
        mock_api.return_value = {"html_url": "doesntmatterhere"}
        mock_auth.return_value = True
        mock_api_auth.return_value = self.api_auth_return_value
        nodata = {}
        snapdata = {"SnapGitOwner": "gimli", "SnapGitName": "axe"}

        with self.github as github:
            self.crashdb.github = github
            self.crashdb_barren.github = github

            # Snap fields are not set and the database specifies no
            # norepository_{owner,name}
            self.assertRaises(
                RuntimeError, self.crashdb_barren.upload, nodata, None, self.message_cb
            )

            # Snap fields are not set and the database specifies
            # norepository_{owner,name}
            self.crashdb.upload(nodata, None, self.message_cb)
            mock_api.assert_called_with(
                self.crashdb.repository_owner, self.crashdb.repository_name, ANY
            )

            # Snap fields are set and the database specifies
            # norepository_{owner,name}
            self.crashdb_barren.upload(snapdata, None, self.message_cb)
            mock_api.assert_called_with(
                snapdata["SnapGitOwner"], snapdata["SnapGitName"], ANY
            )

            # Snap fields are set and the database specifies
            # repository_{owner,name}: The database specs takes precedence.
            self.crashdb.upload(snapdata, None, self.message_cb)
            mock_api.assert_called_with(
                self.crashdb.repository_owner, self.crashdb.repository_name, ANY
            )

    @patch("apport.crashdb_impl.github.Github.api_authentication")
    def test_authentication_complete(self, mock_api):
        base_response = self.api_auth_return_value
        mocked = [base_response.copy() for i in range(7)]
        mocked[2]["error"] = "foo"
        mocked[3]["error"] = "authorization_pending"
        mocked[4]["error"] = "slow_down"
        mocked[5]["access_token"] = "token"
        mocked[6]["expires_in"] = -100
        mock_api.side_effect = mocked

        # No __enter__, no authentication data
        self.assertRaises(RuntimeError, self.github.authentication_complete)
        self.message_cb.assert_not_called()
        with self.github as github:
            # Error message missing
            self.assertRaises(RuntimeError, github.authentication_complete)
            self.message_cb.assert_called_with("Login required", ANY)
            # Error message awry
            self.assertRaises(RuntimeError, github.authentication_complete)
            # Still not authorized
            self.assertFalse(github.authentication_complete())
            # Slow down!
            self.assertFalse(github.authentication_complete())
            # Access token OK
            self.assertTrue(github.authentication_complete())
        with self.github as github:
            # Expired (requires __enter__ again to update __expiry).
            self.assertRaises(RuntimeError, github.authentication_complete)
            self.message_cb.assert_called_with(
                "Failed login", "Github authentication expired. Please try again."
            )

    def test_not_implemented_methods(self):
        ni = NotImplementedError
        self.assertRaises(ni, self.crashdb._mark_dup_checked, None, None)
        self.assertRaises(ni, self.crashdb.can_update, None)
        self.assertRaises(ni, self.crashdb.close_duplicate, None, None, None)
        self.assertRaises(ni, self.crashdb.download, None)
        self.assertRaises(ni, self.crashdb.duplicate_of, None)
        self.assertRaises(ni, self.crashdb.get_affected_packages, None)
        self.assertRaises(ni, self.crashdb.get_distro_release, None)
        self.assertRaises(ni, self.crashdb.get_dup_unchecked)
        self.assertRaises(ni, self.crashdb.get_fixed_version, None)
        self.assertRaises(ni, self.crashdb.get_id_url, None, None)
        self.assertRaises(ni, self.crashdb.get_unfixed)
        self.assertRaises(ni, self.crashdb.get_unretraced)
        self.assertRaises(ni, self.crashdb.is_reporter, None)
        self.assertRaises(ni, self.crashdb.mark_regression, None, None)
        self.assertRaises(ni, self.crashdb.mark_retrace_failed, None, None)
        self.assertRaises(ni, self.crashdb.mark_retraced, None)
        self.assertRaises(ni, self.crashdb.update, None, None, None, None)

    @staticmethod
    def _get_gh_database(repository_owner, repository_name):
        return apport.crashdb_impl.github.CrashDatabase(
            None,
            {
                "impl": "github",
                "repository_owner": repository_owner,
                "repository_name": repository_name,
                "github_app_id": "a654870577ad2a2ab5b1",
                "labels": ["apport"],
            },
        )
