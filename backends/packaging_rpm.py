'''A partial apport.PackageInfo class implementation for RPM, as found in 
Fedora, RHEL, openSUSE, SUSE Linux, and many other distributions.

Copyright (C) 2007 Red Hat Inc.
Copyright (C) 2008 Nikolay Derkach
Author: Will Woods <wwoods@redhat.com>, Nikolay Derkach <nderkach@gmail.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

# N.B. There's some distro-specific bits in here (e.g. is_distro_package()).
# So this is actually an abstract base class (or a template, if you like) for
# RPM-based distributions.
# A proper implementation needs to (at least) set official_keylist to a list 
# of GPG keyids used by official packages. You might have to extend
# is_distro_package() as well, if you don't sign all your official packages 
# (cough cough Fedora rawhide cough)

# It'd be convenient to use rpmUtils from yum, but I'm trying to keep this
# class distro-agnostic.
import rpm, hashlib, os, stat, subprocess

class RPMPackageInfo:
    '''Partial apport.PackageInfo class implementation for RPM, as
    found in Fedora, RHEL, CentOS, etc.'''

    # Empty keylist. Should contain a list of key ids (8 lowercase hex digits).
    # e.g. official_keylist = ('30c9ecf8','4f2a6fd2','897da07a','1ac70ce6')
    official_keylist = () 

    def __init__(self):
        self.ts = rpm.TransactionSet() # connect to the rpmdb
        self._mirror = None

    def get_version(self, package):
        '''Return the installed version of a package.'''
        hdr = self._get_header(package)
        if hdr == None:
            raise ValueError
        # Note - "version" here seems to refer to the full EVR, so..
        if not hdr['e']:
            return hdr['v'] + '-' + hdr['r']
        if not hdr['v'] or not hdr['r']:
            return None       
        else:
            return hdr['e'] + ':' + hdr['v'] + '-' + hdr['r']     

    def get_available_version(self, package):
        '''Return the latest available version of a package.'''
        # used in report.py, which is used by the frontends
        raise NotImplementedError, 'method must be implemented by distro-specific RPMPackageInfo subclass'

    def get_dependencies(self, package):
        '''Return a list of packages a package depends on.'''
        hdr = self._get_header(package)
        # parse this package's Requires
        reqs=[]
        for r in hdr['requires']:
            if r.startswith('rpmlib') or r.startswith('uname('):
                continue # we've got rpmlib, thanks
            if r[0] == '/': # file requires
                req_heads = self._get_headers_by_tag('basenames',r)
            else:           # other requires
                req_heads = self._get_headers_by_tag('provides',r)
            for rh in req_heads:
                rh_envra = self._make_envra_from_header(rh)
                if rh_envra not in reqs:
                    reqs.append(rh_envra)
        return reqs

    def get_source(self, package):
        '''Return the source package name for a package.'''
        hdr = self._get_header(package)
        return hdr['sourcerpm']
        
    def get_architecture(self, package):
        '''Return the architecture of a package.

        This might differ on multiarch architectures (e. g.  an i386 Firefox
        package on a x86_64 system)'''
        # Yeah, this is kind of redundant, as package is ENVRA, but I want
        # to do this the right way (in case we change what 'package' is)
        hdr = self._get_header(package)
        return hdr['arch'] 

    def get_files(self, package):
        '''Return list of files shipped by a package.'''
        hdr = self._get_header(package)
        files = []
        for (f, mode) in zip(hdr['filenames'],hdr['filemodes']):
            if not stat.S_ISDIR(mode):
                files.append(f)
        return files

    def get_modified_files(self, package):
        '''Return list of all modified files of a package.'''
        hdr = self._get_header(package)   

        files  = hdr['filenames']
        mtimes = hdr['filemtimes']
        md5s   = hdr['filemd5s']

        modified = []
        for i in xrange(len(files)):
            # Skip files we're not tracking md5s for
            if not md5s[i]: continue
            # Skip files we can't read
            if not os.access(files[i],os.R_OK): continue
            # Skip things that aren't real files
            s = os.stat(files[i])
            if not stat.S_ISREG(s.st_mode): continue
            # Skip things that haven't been modified
            if mtimes[i] == s.st_mtime: continue
            # Oh boy, an actual possibly-modified file. Check the md5sum!
            if not self._checkmd5(files[i],md5s[i]):
                modified.append(files[i])

        return modified

    def get_file_package(self, file):
        '''Return the package a file belongs to, or None if the file is not
        shipped by any package.
        
        Under normal use, the 'file' argument will always be the executable
        that crashed.
        '''  
        # The policy for handling files which belong to multiple packages depends on the distro
        raise NotImplementedError, 'method must be implemented by distro-specific RPMPackageInfo subclass'

    def get_system_architecture(self):
        '''Return the architecture of the system, in the notation used by the
        particular distribution.'''
        rpmarch = subprocess.Popen(['rpm', '--eval', '%_target_cpu'],
                stdout=subprocess.PIPE)
        arch = rpmarch.communicate()[0].strip()
        return arch 

    def is_distro_package(self, package):
        '''Check if a package is a genuine distro package (True) or comes from
        a third-party source.'''
        # This is a list of official keys, set by the concrete subclass
        if not self.official_keylist:
            raise Exception, 'Subclass the RPM implementation for your distro!'
        hdr = self._get_header(package)
        if not hdr:
            return False
        # Check the GPG sig and key ID to see if this package was signed 
        # with an official key.
        if hdr['siggpg']:
            # Package is signed
            keyid = hdr['siggpg'][13:17].encode('hex')
            if keyid in self.official_keylist:
                return True      
        return False

    def set_mirror(self, url):
        '''Explicitly set a distribution mirror URL for operations that need to
        fetch distribution files/packages from the network.

        By default, the mirror will be read from the system configuration
        files.'''
        # FIXME C&P from apt-dpkg implementation, might move to subclass
        self._mirror = url

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
        raise NotImplementedError, 'method must be implemented by distro-specific RPMPackageInfo subclass'

    def compare_versions(self, ver1, ver2):
        '''Compare two package versions.

        Return -1 for ver < ver2, 0 for ver1 == ver2, and 1 for ver1 > ver2.'''
        # Used by crashdb.py (i.e. the frontends)
        # I could duplicate stringToVersion/compareEVR from rpmUtils.misc,
        # but I hate duplicating code. So if you don't want to require rpmUtils
        # you can implement this function yourself. Probably you've got
        # equivalent code in whatever your distro uses instead of yum anyway.
        raise NotImplementedError, 'method must be implemented by distro-specific RPMPackageInfo subclass'

    #
    # Internal helper methods. These are only single-underscore, so you can use
    # use them in extending/overriding the methods above in your subclasses
    #

    def _get_headers_by_tag(self,tag,arg):
        '''Get a list of RPM headers by doing dbMatch on the given tag and
        argument.'''
        matches = self.ts.dbMatch(tag,arg)
        if matches.count() == 0:
            raise ValueError, 'Could not find package with %s: %s' % (tag,arg)
        return [m for m in matches]

    def _get_header(self,envra):
        '''Get the RPM header that matches the given ENVRA.'''

        querystr = envra
        qlen = len(envra) 
        while qlen > 0:
            mi = impl.ts.dbMatch('name', querystr)
            hdrs = [m for m in mi]
            if len(hdrs) > 0:
                # yay! we found something
                # Unless there's some rpmdb breakage, you should have one header
                # here. If you do manage to have two rpms with the same ENVRA,
                # who cares which one you get?
                h = hdrs[0]
                break
                
            # remove the last char of querystr and retry the search
            querystr = querystr[0:len(querystr)-1]
            qlen = qlen - 1

        if qlen == 0:
            raise ValueError, 'No headers found for this envra: %s' % envra
        return h

    def _make_envra_from_header(self,h):
        '''Generate an ENVRA string from an rpm header'''
        nvra="%s-%s-%s.%s" % (h['n'],h['v'],h['r'],h['arch'])
        if h['e']:
            envra = "%s:%s" % (h['e'],nvra)
        else:
            envra = nvra
        return envra
    
    def _checkmd5(self,filename,filemd5):
        '''Internal function to check a file's md5sum'''
        m = hashlib.md5()
        f = open(filename)
        data = f.read() 
        f.close()
        m.update(data)
        return (filemd5 == m.hexdigest())

impl = RPMPackageInfo()

#
# Unit test
#

if __name__ == '__main__':
    import unittest

    class RPMPackageInfoTest(unittest.TestCase):
    
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
            self.assert_(headersByTag[0]['n'].startswith('bash'))      
            
        def test_get_system_architecture(self):
            '''get_system_architecture().'''

            arch = impl.get_system_architecture()
            # must be nonempty without line breaks
            self.assertNotEqual(arch, '')
            self.assert_('\n' not in arch)
            
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
        pass
