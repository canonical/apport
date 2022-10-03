import unittest

import apport.packaging


class T(unittest.TestCase):
    def test_get_uninstalled_package(self):
        """get_uninstalled_package()"""
        p = apport.packaging.get_uninstalled_package()
        self.assertNotEqual(p, None)
        self.assertNotEqual(apport.packaging.get_available_version(p), "")
        self.assertRaises(ValueError, apport.packaging.get_version, p)
        self.assertTrue(apport.packaging.is_distro_package(p))

    def test_get_os_version(self):
        """get_os_version()"""
        (n, v) = apport.packaging.get_os_version()
        self.assertEqual(type(n), str)
        self.assertEqual(type(v), str)
        self.assertGreater(len(n), 1)
        self.assertGreater(len(v), 0)

        # second one uses caching, should be identical
        (n2, v2) = apport.packaging.get_os_version()
        self.assertEqual((n, v), (n2, v2))
