import unittest
from unittest.mock import Mock

try:
    import apport.crashdb_impl.github

    IMPORT_ERROR = None
except ImportError as error:
    IMPORT_ERROR = error


some_id = "a654870577ad2a2ab5b1"


@unittest.skipIf(IMPORT_ERROR, f"module not available: {IMPORT_ERROR}")
class T(unittest.TestCase):
    def setUp(self):
        self.crashdb = self._get_gh_database("Lorem", "Ipsum")
        self.message_cb = Mock()
        self.github = apport.crashdb_impl.github.Github(
            self.crashdb.app_id, self.message_cb
        )

    def test_api_authentication(self):
        """Test if we can contact Github authentication service."""
        with self.github as g:
            data = {"client_id": some_id, "scope": "public_repo"}
            url = "https://github.com/login/device/code"
            response = g.api_authentication(url, data)
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
    def _get_gh_database(repository_owner, repository_name):
        return apport.crashdb_impl.github.CrashDatabase(
            None,
            {
                "impl": "github",
                "repository_owner": repository_owner,
                "repository_name": repository_name,
                "github_app_id": some_id,
                "labels": ["apport"],
            },
        )
