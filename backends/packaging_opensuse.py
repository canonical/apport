'''A concrete apport.PackageInfo class implementation for openSUSE.

Copyright (C) 2008 Nikolay Derkach
Author: Nikolay Derkach <nderkach@gmail.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

from packaging_rpm import RPMPackageInfo
from rpmUtils.miscutils import compareEVR, stringToVersion

class __SUSEPackageInfo(RPMPackageInfo):
    '''Concrete apport.PackageInfo class implementation for openSUSE.'''

    # A list of ids of official keys used by the openSUSE
    official_keylist = ('9c800aca') # SUSE LINUX Products GmbH

    def is_distro_package(self, package):
        '''Check if a package is a genuine distro package (True) or comes from
        a third-party source.'''
        if RPMPackageInfo.is_distro_package(self,package):
            # GPG key id checks out OK. Yay!
            return True
        else:
            # GPG key check failed.
            return False

    def get_available_version(self, package):
        '''Return the latest available version of a package.'''
        # used in report.py, which is used by the frontends
        (epoch, name, ver, rel, arch) = self._split_envra(package)
        package_ver = '%s-%s' % (ver,rel)
        if epoch: 
            package_ver = "%s:%s" % (epoch, package_ver)
        # FIXME STUB
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
        return compareEVR(stringToVersion(ver1),stringToVersion(ver2))
        
    def get_file_package(self, file):
        '''Return the package a file belongs to, or None if the file is not
        shipped by any package.
        
        Under normal use, the 'file' argument will always be the executable
        that crashed.
        '''  
        
        hdrs = self._get_headers_by_tag('basenames',file)
        h = None
        if len(hdrs) > 1: # The file belongs to multiple packages,
        # not possible unless there is some --force package installation
        # FIXME: implement some more smart hadling 
            break              
        else:
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

            self.assert_(impl.is_distro_package('bash-3.2-112.x86_64'))
            # no False test here, hard to come up with a generic one
            
    unittest.main()
         
            
