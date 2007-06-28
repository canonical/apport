'''A concrete apport.PackageInfo class implementation for Fedora.

Copyright (C) 2007 Red Hat Inc.
Author: Will Woods <wwoods@redhat.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

from packaging_rpm import RPMPackageInfo

class __FedoraPackageInfo(RPMPackageInfo):
    '''Concrete apport.PackageInfo class implementation for Fedora.'''

    # A list of ids of official keys used by the Fedora project
    official_keylist = ('30c9ecf8','4f2a6fd2','897da07a','1ac70ce6')

    def __distro_is_rawhide(self):
        '''Check to see if we're running rawhide, so we know that it's OK if
        a package is unsigned.'''
        f = open("/etc/fedora-release")
        line = f.readline()
        f.close()
        if "Rawhide" in line:
            return True
        else:
            return False

    def is_distro_package(self, package):
        '''Check if a package is a genuine distro package (True) or comes from
        a third-party source.'''
        if RPMPackageInfo.is_distro_package(self,package):
            # GPG key id checks out OK. Yay!
            return True
        else:
            # GPG key check failed.
            # In Fedora, rawhide packages aren't signed - even official ones.
            # So check to see if we're running rawhide, and if so, fall back
            # to something stupid, like checking for "Red Hat" in distribution
            # and vendor tags.

            # NOTE the superclass method also does _get_header and then
            # throws it away. This is somewhat wasteful.
            hdr = RPMPackageInfo._get_header(self,package)

            if self.__distro_is_rawhide() and \
               hdr['vendor'] == "Red Hat, Inc." and \
               hdr['distribution'].startswith("Red Hat"):
                return True
        return False

impl = __FedoraPackageInfo()
