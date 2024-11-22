"""Unit tests for the apport.ui module."""

import os
import tempfile
import textwrap
import unittest
import unittest.mock
from gettext import gettext as _
from unittest.mock import MagicMock

import apport.ui


class TestUI(unittest.TestCase):
    """Unit tests for apport.ui."""

    crashdb_conf: str

    @classmethod
    def setUpClass(cls) -> None:
        # pylint: disable-next=consider-using-with
        crashdb_conf_file = tempfile.NamedTemporaryFile("w+")
        cls.addClassCleanup(crashdb_conf_file.close)
        crashdb_conf_file.write(
            textwrap.dedent(
                """\
            default = 'testsuite'
            databases = {
                'testsuite': {
                    'impl': 'memory',
                    'bug_pattern_url': None,
                },
                'debug': {
                    'impl': 'memory',
                    'distro': 'debug',
                },
            }
            """
            )
        )
        crashdb_conf_file.flush()
        cls.crashdb_conf = crashdb_conf_file.name

    def setUp(self) -> None:
        self.orig_environ = os.environ.copy()
        os.environ["APPORT_CRASHDB_CONF"] = self.crashdb_conf
        self.ui = apport.ui.UserInterface([])

        # Mock environment for run_as_real_user() to not being called via sudo/pkexec
        os.environ.pop("SUDO_UID", None)
        os.environ.pop("PKEXEC_UID", None)

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self.orig_environ)

    @unittest.mock.patch("subprocess.run")
    @unittest.mock.patch("webbrowser.open")
    def test_open_url(self, open_mock: MagicMock, run_mock: MagicMock) -> None:
        """Test successful UserInterface.open_url() without pkexec/sudo."""
        self.ui.open_url("https://example.com")

        run_mock.assert_called_once_with(
            ["xdg-open", "https://example.com"], check=False
        )
        open_mock.assert_not_called()

    @unittest.mock.patch("subprocess.run")
    @unittest.mock.patch("webbrowser.open")
    def test_open_url_webbrowser_fallback(
        self, open_mock: MagicMock, run_mock: MagicMock
    ) -> None:
        """Test UserInterface.open_url() to fall back to webbrowser.open()."""
        run_mock.side_effect = FileNotFoundError
        open_mock.return_value = True

        self.ui.open_url("https://example.net")

        run_mock.assert_called_once_with(
            ["xdg-open", "https://example.net"], check=False
        )
        open_mock.assert_called_once_with("https://example.net", new=1, autoraise=True)

    @unittest.mock.patch("subprocess.run")
    @unittest.mock.patch("webbrowser.open")
    @unittest.mock.patch("apport.ui.UserInterface.ui_error_message")
    def test_open_url_webbrowser_fails(
        self, error_message_mock: MagicMock, open_mock: MagicMock, run_mock: MagicMock
    ) -> None:
        """Test UserInterface.open_url() with webbrowser.open() returning False."""
        run_mock.side_effect = FileNotFoundError
        open_mock.return_value = False

        self.ui.open_url("https://example.org")

        run_mock.assert_called_once_with(
            ["xdg-open", "https://example.org"], check=False
        )
        open_mock.assert_called_once_with("https://example.org", new=1, autoraise=True)
        error_message_mock.assert_called_once_with(
            _("Unable to start web browser"),
            _("Unable to start web browser to open %s.") % ("https://example.org"),
        )
