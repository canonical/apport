import unittest

from tests.helper import skip_if_command_is_missing

try:
    from apport.packaging_impl.rpm import impl

    HAS_RPM = True
except ImportError:
    HAS_RPM = False


@unittest.skipUnless(HAS_RPM, "rpm module not available")
@skip_if_command_is_missing("rpm")
class T(unittest.TestCase):
    def test_get_dependencies(self):
        """get_dependencies()."""
        deps = impl.get_dependencies("bash")
        self.assertNotEqual(deps, [])

    def test_get_header(self):
        """_get_header()."""
        # pylint: disable=protected-access
        hdr = impl._get_header("alsa-utils")
        self.assertEqual(hdr["n"], "alsa-utils")

    def test_get_headers_by_tag(self):
        """_get_headers_by_tag()."""
        # pylint: disable=protected-access
        headersByTag = impl._get_headers_by_tag("basenames", "/bin/bash")
        self.assertEqual(len(headersByTag), 1)
        self.assertTrue(headersByTag[0]["n"].startswith("bash"))

    def test_get_system_architecture(self):
        """get_system_architecture()."""
        arch = impl.get_system_architecture()
        # must be nonempty without line breaks
        self.assertNotEqual(arch, "")
        self.assertNotIn("\n", arch)

    def test_get_version(self):
        """get_version()."""
        ver = impl.get_version("bash")
        self.assertNotEqual(ver, None)
        ver = impl.get_version("alsa-utils")
        self.assertNotEqual(ver, None)
