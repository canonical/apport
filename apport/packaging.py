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
        '''Return the installed version of a package.
        
        Throw ValueError if package does not exist.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_available_version(self, package):
        '''Return the latest available version of a package.
        
        Throw ValueError if package does not exist.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_dependencies(self, package):
        '''Return a list of packages a package depends on.'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_source(self, package):
        '''Return the source package name for a package.
        
        Throw ValueError if package does not exist.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def is_distro_package(self, package):
        '''Check package origin.

        Return True if the package is a genuine distro package, or False if it
        comes from a third-party source.

        Throw ValueError if package does not exist.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_architecture(self, package):
        '''Return the architecture of a package.

        This might differ on multiarch architectures (e. g.  an i386 Firefox
        package on a x86_64 system)
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_files(self, package):
        '''Return list of files shipped by a package.

        Throw ValueError if package does not exist.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_modified_files(self, package):
        '''Return list of all modified files of a package.'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_file_package(self, file, uninstalled=False, map_cachedir=None):
        '''Return the package a file belongs to.
        
        Return None if the file is not shipped by any package.
        
        If uninstalled is True, this will also find files of uninstalled
        packages; this is very expensive, though, and needs network access and
        lots of CPU and I/O resources. In this case, map_cachedir can be set to
        an existing directory which will be used to permanently store the
        downloaded maps. If it is not set, a temporary directory will be used.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_system_architecture(self):
        '''Return the architecture of the system.
        
        This should use the notation of the particular distribution.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def set_mirror(self, url):
        '''Explicitly set a distribution mirror URL.
        
        This might be called for operations that need to fetch distribution
        files/packages from the network.

        By default, the mirror will be read from the system configuration
        files.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_source_tree(self, srcpackage, dir, version=None):
        '''Download a source package and unpack it into dir..
        
        dir should exist and be empty.

        This also has to care about applying patches etc., so that dir will
        eventually contain the actually compiled source.

        If version is given, this particular version will be retrieved.
        Otherwise this will fetch the latest available version.

        Return the directory that contains the actual source root directory
        (which might be a subdirectory of dir). Return None if the source is
        not available.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def compare_versions(self, ver1, ver2):
        '''Compare two package versions.

        Return -1 for ver < ver2, 0 for ver1 == ver2, and 1 for ver1 > ver2.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def enabled(self):
        '''Return whether Apport should generate crash reports.

        Signal crashes are controlled by /proc/sys/kernel/core_pattern, but
        some init script needs to set that value based on a configuration file.
        This also determines whether Apport generates reports for Python,
        package, or kernel crashes.
        
        Implementations should parse the configuration file which controls
        Apport (such as /etc/default/apport in Debian/Ubuntu).
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_kernel_package(self):
        '''Return the actual Linux kernel package name.

        This is used when the user reports a bug against the "linux" package.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def install_retracing_packages(self, report, verbosity=0,
            unpack_only=False, no_pkg=False, extra_packages=[]):
        '''Install packages which are required to retrace a report.
        
        If package installation fails (e. g. because the user does not have root
        privileges), the list of required packages is printed out instead.

        If unpack_only is True, packages are only temporarily unpacked and
        purged again after retrace, instead of permanently and fully installed.
        If no_pkg is True, the package manager is not used at all, but the
        binary packages are just unpacked with low-level tools; this speeds up
        operations in fakechroots, but makes it impossible to cleanly remove
        the package, so only use that in apport-chroot.
        
        Return a tuple (list of installed packages, string with outdated packages).
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def remove_packages(self, packages, verbosity=0):
        '''Remove packages.

        This is called after install_retracing_packages() to clean up again
        afterwards. packages is a list of package names.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def package_name_glob(self, glob):
        '''Return known package names which match given glob.'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

import packaging_impl
