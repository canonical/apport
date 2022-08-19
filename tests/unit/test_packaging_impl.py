"""Test functions in apport/packaging_impl/__init__.py."""

import unittest
import unittest.mock

from apport.packaging_impl import determine_packaging_implementation


class T(unittest.TestCase):
    @unittest.mock.patch("apport.packaging_impl.freedesktop_os_release")
    def test_determine_ubuntu(self, os_release_mock):
        os_release_mock.return_value = {
            "PRETTY_NAME": "Ubuntu 22.04.1 LTS",
            "NAME": "Ubuntu",
            "VERSION_ID": "22.04",
            "VERSION": "22.04.1 LTS (Jammy Jellyfish)",
            "VERSION_CODENAME": "jammy",
            "ID": "ubuntu",
            "ID_LIKE": "debian",
        }
        self.assertEqual(determine_packaging_implementation(), "apt_dpkg")
        os_release_mock.assert_called_once_with()

    @unittest.mock.patch("apport.packaging_impl.freedesktop_os_release")
    def test_determine_debian_unstable(self, os_release_mock):
        os_release_mock.return_value = {
            "PRETTY_NAME": "Debian GNU/Linux bookworm/sid",
            "NAME": "Debian GNU/Linux",
            "ID": "debian",
        }
        self.assertEqual(determine_packaging_implementation(), "apt_dpkg")
        os_release_mock.assert_called_once_with()
