import unittest

import apport


class T(unittest.TestCase):
    def test_get_uninstalled_package(self):
        '''get_uninstalled_package()'''

        p = apport.packaging.get_uninstalled_package()
        self.assertNotEqual(p, None)
        self.assertNotEqual(apport.packaging.get_available_version(p), '')
        self.assertRaises(ValueError, apport.packaging.get_version, p)
        self.assertTrue(apport.packaging.is_distro_package(p))

unittest.main()
