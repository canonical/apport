'''Class that abstracts and encapsulates all packaging system queries that the
various parts of apport need.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

class PackageInfo:
    def get_version(self, package):
        '''Return the installed version of a package.'''

        raise Exception, 'this method must be implemented by a concrete subclass'

    def get_dependencies(self, package):
        '''Return a list of packages a package depends on.'''

        raise Exception, 'this method must be implemented by a concrete subclass'

    def get_source(self, package):
        '''Return the source package name for a package.'''

        raise Exception, 'this method must be implemented by a concrete subclass'

    def get_architecture(self, package):
        '''Return the architecture of a package.
        
        This might differ on multiarch architectures (e. g.  an i386 Firefox
        package on a x86_64 system)'''

        raise Exception, 'this method must be implemented by a concrete subclass'

    def get_files(self, package):
        '''Return list of files shipped by a package.'''

        raise Exception, 'this method must be implemented by a concrete subclass'

    def get_modified_files(self, package):
        '''Return list of all modified files of a package.'''

        raise Exception, 'this method must be implemented by a concrete subclass'

    def get_file_package(self, file):
        '''Return the package a file belongs to, or None if the file is not
        shipped by any package.'''

        raise Exception, 'this method must be implemented by a concrete subclass'

    def get_system_architecture(self):
        '''Return the architecture of the system, in the notation used by the
        particular distribution.'''

        raise Exception, 'this method must be implemented by a concrete subclass'

import packaging_impl
