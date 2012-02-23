import unittest, imp, subprocess, sys

try:
    impl = imp.load_source('', 'backends/packaging_rpm.py').impl
except ImportError:
    print('%s: Skipping, rpm module not available' % sys.argv[0])
    sys.exit(0)

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
        
        headersByTag = impl._get_headers_by_tag('basenames','/bin/bash')
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


# only execute if rpm is available
try:
    if subprocess.call(['rpm', '--help'], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE) == 0:
        unittest.main()
except OSError:
    print('%s: Skipping, rpm not available' % sys.argv[0])
