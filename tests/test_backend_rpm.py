import unittest, imp
import shutil

from tests.paths import is_local_source_directory

try:
    if is_local_source_directory():
        impl = imp.load_source('', 'backends/packaging_rpm.py').impl
    else:
        from apport.packaging_impl import impl
    HAS_RPM = True
except ImportError:
    HAS_RPM = False


@unittest.skipUnless(HAS_RPM, 'rpm module not available')
@unittest.skipIf(shutil.which('rpm') is None, 'rpm not available')
class T(unittest.TestCase):

    def test_get_dependencies(self):
        '''get_dependencies().'''

        deps = impl.get_dependencies('bash')
        self.assertNotEqual(deps, [])

    def test_get_header(self):
        '''_get_header().'''

        hdr = impl._get_header('alsa-utils')
        self.assertEqual(hdr['n'], 'alsa-utils')

    def test_get_headers_by_tag(self):
        '''_get_headers_by_tag().'''

        headersByTag = impl._get_headers_by_tag('basenames', '/bin/bash')
        self.assertEqual(len(headersByTag), 1)
        self.assertTrue(headersByTag[0]['n'].startswith('bash'))

    def test_get_system_architecture(self):
        '''get_system_architecture().'''

        arch = impl.get_system_architecture()
        # must be nonempty without line breaks
        self.assertNotEqual(arch, '')
        self.assertTrue('\n' not in arch)

    def test_get_version(self):
        '''get_version().'''

        ver = impl.get_version('bash')
        self.assertNotEqual(ver, None)
        ver = impl.get_version('alsa-utils')
        self.assertNotEqual(ver, None)


if __name__ == "__main__":
    unittest.main()
