'''A concrete apport.PackageInfo class implementation for openSUSE.

Copyright (C) 2008 Nikolay Derkach
Author: Nikolay Derkach <nderkach@gmail.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import rpm
from packaging_rpm import RPMPackageInfo

class __SUSEPackageInfo(RPMPackageInfo):
    '''Concrete apport.PackageInfo class implementation for openSUSE.'''
    
    # some helper functions from rpmUtils.miscutils (yum)
    
    def compareEVR(self, (e1, v1, r1), (e2, v2, r2)):
        # return 1: a is newer than b
        # 0: a and b are the same version
        # -1: b is newer than a
        e1 = str(e1)
        v1 = str(v1)
        r1 = str(r1)
        e2 = str(e2)
        v2 = str(v2)
        r2 = str(r2)
        rc = rpm.labelCompare((e1, v1, r1), (e2, v2, r2))
        return rc
    
    def stringToVersion(self, verstring):
        if verstring in [None, '']:
            return (None, None, None)
        i = verstring.find(':')
        if i != -1:
            try:
                epoch = str(long(verstring[:i]))
            except ValueError:
                # look, garbage in the epoch field, how fun, kill it
                epoch = '0' # this is our fallback, deal
        else:
            epoch = '0'
        j = verstring.find('-')
        if j != -1:
            if verstring[i + 1:j] == '':
                version = None
            else:
                version = verstring[i + 1:j]
            release = verstring[j + 1:]
        else:
            if verstring[i + 1:] == '':
                version = None
            else:
                version = verstring[i + 1:]
            release = None
        return (epoch, version, release)
        

    # A list of ids of official keys used by the openSUSE
    official_keylist = ('9c800aca') # SUSE LINUX Products GmbH

    def is_distro_package(self, package):
        '''Check if a package is a genuine distro package (True) or comes from
        a third-party source.'''
        if self.get_vendor(package) == 'SUSE LINUX Products GmbH, Nuernberg, Germany':
            if RPMPackageInfo.is_distro_package(self, package):
                # GPG key id checks out OK. Yay!
                return True
        else:
            return False

    def get_available_version(self, package):
        '''Return the latest available version of a package.'''
        # used in report.py, which is used by the frontends
        # Epoch tag is not used in SUSE
        (epoch, name, ver, rel, arch) = self._split_envra(package)
        package_ver = '%s-%s' % (ver,rel)
        return package_ver

    def get_source_tree(self, srcpackage, dir, version=None):
        '''Download given source package and unpack it into dir (which should
        be empty).

        This also has to care about applying patches etc., so that dir will
        eventually contain the actually compiled source.

        If version is given, this particular version will be retrieved.
        Otherwise this will fetch the latest available version.

        Return the directory that contains the actual source root directory
        (which might be a subdirectory of dir). Return None if the source is
        not available.'''
        # Used only by apport-retrace.
        # FIXME STUB
        return None
         
    def compare_versions(self, ver1, ver2):
        '''Compare two package versions.

        Return -1 for ver < ver2, 0 for ver1 == ver2, and 1 for ver1 > ver2.'''
        # Used by crashdb.py (i.e. the frontends)
        return self.compareEVR(self.stringToVersion(ver1), self.stringToVersion(ver2))
        
    def get_file_package(self, file):
        '''Return the package a file belongs to, or None if the file is not
        shipped by any package.
        
        Under normal use, the 'file' argument will always be the executable
        that crashed.
        '''  
        
        hdrs = self._get_headers_by_tag('basenames',file)
        h = None
        if len(hdrs) == 1: # If the file belongs to multiple packages
        # there is some --force package installation
        # FIXME: implement some more smart hadling 
            h = hdrs[0]
        return self._make_envra_from_header(h)  

impl = __SUSEPackageInfo()

#
# Unit test
#

if __name__ == '__main__':
    import unittest

    class __SUSEPackageInfoTest(unittest.TestCase):

        def test_is_distro_package(self):
            '''Test is_distro_package().'''

            self.assert_(impl.is_distro_package('bash'))
            self.assert_(not impl.is_distro_package('libxine1'))
            self.assertRaises(ValueError, impl.is_distro_package, 'nonexistant_package')
            
        def test_get_available_version(self):
            '''Test get_available version().'''
            
#            print impl.get_available_version('bash-3.2-112.x86_64')  
            
        def test_compare_versions(self):
            '''Test is_distro_package().'''
            
            self.assertEqual(impl.compare_versions('1', '2'), -1)
            
        def test_get_file_package(self):
            '''Test get_file_package().'''
            
            package = impl.get_file_package('/bin/bash') 
 #           print package              
            
    unittest.main()
         
            
