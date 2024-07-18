"""System tests for the apport.crashdb_impl.github module."""

import unittest
from unittest.mock import Mock

import apport.crashdb_impl.github

SOME_ID = "a654870577ad2a2ab5b1"


class TestGitHubQuery(unittest.TestCase):
    """System tests for the apport.crashdb_impl.github module."""

    def setUp(self) -> None:
        self.crashdb = self._get_gh_database("Lorem", "Ipsum")
        self.message_cb = Mock()
        self.github = apport.crashdb_impl.github.Github(
            self.crashdb.app_id, self.message_cb
        )

    def test_api_authentication(self) -> None:
        """Test if we can contact Github authentication service."""
        with self.github as github:
            data = {"client_id": SOME_ID, "scope": "public_repo"}
            url = "https://github.com/login/device/code"
            response = github.api_authentication(url, data)
            # Sample response:
            # {
            #     'device_code': '35fe1f072913d46c00ad3e4a83e57facfb758f67',
            #     'user_code': '5A5D-7210',
            #     'verification_uri': 'https://github.com/login/device',
            #     'expires_in': 899,
            #     'interval': 5
            # }
            self.assertIsInstance(response["device_code"], str)
            self.assertIsInstance(response["user_code"], str)
            self.assertIsInstance(response["device_code"], str)
            self.assertIsInstance(response["expires_in"], int)
            self.assertIsInstance(response["interval"], int)

    @staticmethod
    def _get_gh_database(
        repository_owner: str, repository_name: str
    ) -> apport.crashdb_impl.github.CrashDatabase:
        return apport.crashdb_impl.github.CrashDatabase(
            None,
            {
                "impl": "github",
                "repository_owner": repository_owner,
                "repository_name": repository_name,
                "github_app_id": SOME_ID,
                "labels": ["apport"],
            },
        )
