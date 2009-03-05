'''An apport.PackageInfo class implementation for python-apt and dpkg, as found
on Debian and derivatives such as Ubuntu.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import subprocess, os, glob, stat, sys, tempfile, glob, re

import warnings
warnings.filterwarnings('ignore', 'apt API not stable yet', FutureWarning)
import apt

from apport.packaging import PackageInfo

class __AptDpkgPackageInfo(PackageInfo):
    '''Concrete apport.PackageInfo class implementation for python-apt and
    dpkg, as found on Debian and derivatives such as Ubuntu.'''

    def __init__(self):
        self._apt_cache = None
        self._contents_dir = None
        self._mirror = None

        self.configuration = '/etc/default/apport'

    def __del__(self):
        try:
            if self._contents_dir:
                import shutil
                shutil.rmtree(self._contents_dir)
        except AttributeError:
            pass

    def _cache(self, package):
        '''Return apt.Cache()[package] (initialized lazily).
        
        Throw a ValueError if the package does not exist.'''

        if not self._apt_cache:
            self._apt_cache = apt.Cache()
        try:
            return self._apt_cache[package]
        except KeyError:
            raise ValueError, 'package does not exist'

    def get_version(self, package):
        '''Return the installed version of a package.'''

        return self._cache(package).installedVersion

    def get_available_version(self, package):
        '''Return the latest available version of a package.'''

        return self._cache(package).candidateVersion

    def get_dependencies(self, package):
        '''Return a list of packages a package depends on.'''

        cur_ver = self._cache(package)._pkg.CurrentVer
        if not cur_ver:
            # happens with virtual packages
            return []
        return [d[0].TargetPkg.Name for d in cur_ver.DependsList.get('Depends', []) +
            cur_ver.DependsList.get('PreDepends', [])]

    def get_source(self, package):
        '''Return the source package name for a package.'''

        return self._cache(package).sourcePackageName

    def is_distro_package(self, package):
        '''Check if a package is a genuine distro package (True) or comes from
        a third-party source.'''

        lsb_release = subprocess.Popen(['lsb_release', '-i', '-s'],
            stdout=subprocess.PIPE)
        this_os = lsb_release.communicate()[0].strip()
        assert lsb_release.returncode == 0

        origins = self._cache(package).candidateOrigin
        if origins: # might be None
            for o in origins:
                # note: checking site for ppa is a hack until LP #140412 gets fixed
                if o.origin == this_os and not o.site.startswith('ppa'):
                    return True
        return False

    def get_architecture(self, package):
        '''Return the architecture of a package.

        This might differ on multiarch architectures (e. g.  an i386 Firefox
        package on a x86_64 system)'''

        return self._cache(package).architecture or 'unknown'

    def get_files(self, package):
        '''Return list of files shipped by a package.'''

        list = self._call_dpkg(['-L', package])
        if list is None:
            return None
        return [f for f in list.splitlines() if not f.startswith('diverted')]

    def get_modified_files(self, package):
        '''Return list of all modified files of a package.'''

        # get the maximum mtime of package files that we consider unmodified
        listfile = '/var/lib/dpkg/info/%s.list' % package
        try:
            s = os.stat(listfile)
            if not stat.S_ISREG(s.st_mode):
                raise OSError
            max_time = max(s.st_mtime, s.st_ctime)
        except OSError:
            return [listfile]

        # create a list of files with a newer timestamp for md5sum'ing
        sums = ''
        sumfile = '/var/lib/dpkg/info/%s.md5sums' % package
        # some packages do not ship md5sums, shrug on them
        if not os.path.exists(sumfile):
            return []

        for line in open(sumfile):
            try:
                # ignore lines with NUL bytes (happens, LP#96050)
                if '\0' in line:
                    print >> sys.stderr, 'WARNING:', sumfile, 'contains NUL character, ignoring line'
                    continue
                words  = line.split()
                if len(line) < 1:
                    print >> sys.stderr, 'WARNING:', sumfile, 'contains empty line, ignoring line'
                    continue
                s = os.stat('/' + words[-1])
                if max(s.st_mtime, s.st_ctime) <= max_time:
                    continue
            except OSError:
                pass

            sums += line

        if sums:
            return self._check_files_md5(sums)
        else:
            return []

    def __fgrep_files(self, pattern, file_list):
        '''Call fgrep for a pattern on given file list and return the first
        matching file, or None if no file matches.'''

        match = None
        slice_size = 100
        i = 0

        while not match and i < len(file_list):
            p = subprocess.Popen(['fgrep', '-lxm', '1', '--', pattern] +
                file_list[i:i+slice_size], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            out = p.communicate()[0]
            if p.returncode == 0:
                match = out
            i += slice_size

        return match

    def get_file_package(self, file, uninstalled=False, map_cachedir=None):
        '''Return the package a file belongs to, or None if the file is not
        shipped by any package.
        
        If uninstalled is True, this will also find files of uninstalled
        packages; this is very expensive, though, and needs network access and
        lots of CPU and I/O resources. In this case, map_cachedir can be set to
        an existing directory which will be used to permanently store the
        downloaded maps. If it is not set, a temporary directory will be used.'''

        # check if the file is a diversion
        dpkg = subprocess.Popen(['/usr/sbin/dpkg-divert', '--list', file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = dpkg.communicate()[0]
        if dpkg.returncode == 0 and out:
            return out.split()[-1]

        fname = os.path.splitext(os.path.basename(file))[0].lower()

        all_lists = []
        likely_lists = []
        for f in glob.glob('/var/lib/dpkg/info/*.list'):
            p = os.path.splitext(os.path.basename(f))[0].lower()
            if p in fname or fname in p:
                likely_lists.append(f)
            else:
                all_lists.append(f)

        # first check the likely packages
        match = self.__fgrep_files(file, likely_lists)
        if not match:
            match = self.__fgrep_files(file, all_lists)

        if match:
            return os.path.splitext(os.path.basename(match))[0]

        if uninstalled:
            return self._search_contents(file, map_cachedir)
        else:
            return None

    def get_system_architecture(self):
        '''Return the architecture of the system, in the notation used by the
        particular distribution.'''

        dpkg = subprocess.Popen(['dpkg', '--print-architecture'],
            stdout=subprocess.PIPE)
        arch = dpkg.communicate()[0].strip()
        assert dpkg.returncode == 0
        assert arch
        return arch

    def set_mirror(self, url):
        '''Explicitly set a distribution mirror URL for operations that need to
        fetch distribution files/packages from the network.

        By default, the mirror will be read from the system configuration
        files.'''

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

        # fetch source tree
        argv = ['apt-get', '--assume-yes', 'source', srcpackage]
        if version:
            argv[-1] += '=' + version
        try:
            if subprocess.call(argv, stdout=subprocess.PIPE,
                cwd=dir) != 0:
                return None
        except OSError:
            return None

        # find top level directory
        root = None
        for d in glob.glob(os.path.join(dir, srcpackage + '-*')):
            if os.path.isdir(d):
                root = d
        assert root, 'could not determine source tree root directory'

        # apply patches on a best-effort basis 
        try:
            subprocess.call('debian/rules setup || debian/rules patch || \
                debian/rules apply-patches ||  debian/rules apply-dpatches || \
                debian/rules unpack || debian/rules patch-stamp', 
                shell=True, cwd=root, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        except OSError:
            pass

        return root

    def get_kernel_package(self):
        '''Return the actual Linux kernel package name.

        This is used when the user reports a bug against the "linux" package.
        '''
        # TODO: Ubuntu specific
        return 'linux-image-' + os.uname()[2]

    #
    # Internal helper methods
    #

    def _call_dpkg(self, args):
        '''Call dpkg with given arguments and return output, or return None on
        error.'''

        dpkg = subprocess.Popen(['dpkg'] + args, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        out = dpkg.communicate(input)[0]
        if dpkg.returncode == 0:
            return out
        else:
            raise ValueError, 'package does not exist'

    def _check_files_md5(self, sumfile):
        '''Internal function for calling md5sum.

        This is separate from get_modified_files so that it is automatically
        testable.'''

        if os.path.exists(sumfile):
            m = subprocess.Popen(['/usr/bin/md5sum', '-c', sumfile],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                cwd='/', env={})
            out = m.communicate()[0]
        else:
            m = subprocess.Popen(['/usr/bin/md5sum', '-c'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, cwd='/', env={})
            out = m.communicate(sumfile)[0]

        # if md5sum succeeded, don't bother parsing the output
        if m.returncode == 0:
            return []

        mismatches = []
        for l in out.splitlines():
            if l.endswith('FAILED'):
                mismatches.append(l.rsplit(':', 1)[0])

        return mismatches

    def _get_mirror(self):
        '''Return the distribution mirror URL.

        If it has not been set yet, it will be read from the system
        configuration.'''

        if not self._mirror:
            for l in open('/etc/apt/sources.list'):
                fields = l.split()
                if len(fields) >= 3 and fields[0] == 'deb':
                    self._mirror = fields[1]
                    break
            else:
                raise SystemError, 'cannot determine default mirror: /etc/apt/sources.list does not contain a valid deb line'

        return self._mirror

    def _search_contents(self, file, map_cachedir):
        '''Internal function for searching file in Contents.gz.'''

        if map_cachedir:
            dir = map_cachedir
        else:
            if not self._contents_dir:
                self._contents_dir = tempfile.mkdtemp()
            dir = self._contents_dir

        arch = self.get_system_architecture()
        map = os.path.join(dir, 'Contents-%s.gz' % arch)

        if not os.path.exists(map):
            import urllib

            # determine distro release code name
            lsb_release = subprocess.Popen(['lsb_release', '-sc'],
                stdout=subprocess.PIPE)
            release_name = lsb_release.communicate()[0].strip()
            assert lsb_release.returncode == 0

            url = '%s/dists/%s/Contents-%s.gz' % (self._get_mirror(), release_name, arch)
            urllib.urlretrieve(url, map)
            assert os.path.exists(map)

        if file.startswith('/'):
            file = file[1:]

        # zgrep is magnitudes faster than a 'gzip.open/split() loop'
        package = None
        zgrep = subprocess.Popen(['zgrep', '-m1', '^%s[[:space:]]' % file, map],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = zgrep.communicate()[0]
        # we do not check the return code, since zgrep -m1 often errors out
        # with 'stdout: broken pipe'
        if out:
            package = out.split()[1].split(',')[0].split('/')[-1]

        return package

    def compare_versions(self, ver1, ver2):
        '''Compare two package versions.

        Return -1 for ver < ver2, 0 for ver1 == ver2, and 1 for ver1 > ver2.'''

        return apt.VersionCompare(ver1, ver2)

    def enabled(self):
        '''Return whether Apport should generate crash reports.

        Signal crashes are controlled by /proc/sys/kernel/core_pattern, but
        some init script needs to set that value based on a configuration file.
        This also determines whether Apport generates reports for Python,
        package, or kernel crashes.
        
        Implementations should parse the configuration file which controls
        Apport (such as /etc/default/apport in Debian/Ubuntu).
        '''

        try:
            conf = open(self.configuration).read()
        except IOError:
            # if the file does not exist, assume it's enabled
            return True

        return re.search('^\s*enabled\s*=\s*0\s*$', conf, re.M) is None

impl = __AptDpkgPackageInfo()

#
# Unit test
#

if __name__ == '__main__':
    import unittest, gzip, shutil

    class _AptDpkgPackageInfoTest(unittest.TestCase):

        def setUp(self):
            # save and restore configuration file
            self.orig_conf = impl.configuration

        def tearDown(self):
            impl.configuration = self.orig_conf

        def test_check_files_md5(self):
            '''_check_files_md5().'''

            td = tempfile.mkdtemp()
            try:
                f1 = os.path.join(td, 'test 1.txt')
                f2 = os.path.join(td, 'test:2.txt')
                sumfile = os.path.join(td, 'sums.txt')
                open(f1, 'w').write('Some stuff')
                open(f2, 'w').write('More stuff')
                # use one relative and one absolute path in checksums file
                open(sumfile, 'w').write('''2e41290da2fa3f68bd3313174467e3b5  %s
        f6423dfbc4faf022e58b4d3f5ff71a70  %s
        ''' % (f1[1:], f2))
                self.assertEqual(impl._check_files_md5(sumfile), [], 'correct md5sums')

                open(f1, 'w').write('Some stuff!')
                self.assertEqual(impl._check_files_md5(sumfile), [f1[1:]], 'file 1 wrong')
                open(f2, 'w').write('More stuff!')
                self.assertEqual(impl._check_files_md5(sumfile), [f1[1:], f2], 'files 1 and 2 wrong')
                open(f1, 'w').write('Some stuff')
                self.assertEqual(impl._check_files_md5(sumfile), [f2], 'file 2 wrong')

                # check using a direct md5 list as argument
                self.assertEqual(impl._check_files_md5(open(sumfile).read()),
                    [f2], 'file 2 wrong')

            finally:
                shutil.rmtree(td)

        def test_get_version(self):
            '''get_version().'''

            self.assert_(impl.get_version('libc6').startswith('2'))
            self.assertRaises(ValueError, impl.get_version, 'nonexisting')

        def test_get_available_version(self):
            '''get_available_version().'''

            self.assert_(impl.get_available_version('libc6').startswith('2'))
            self.assertRaises(ValueError, impl.get_available_version, 'nonexisting')

        def test_get_dependencies(self):
            '''get_dependencies().'''

            # package with both Depends: and Pre-Depends:
            d  = impl.get_dependencies('bash')
            self.assert_(len(d) > 2)
            self.assert_('libc6' in d)
            for dep in d:
                self.assert_(impl.get_version(dep))

            # Pre-Depends: only
            d  = impl.get_dependencies('coreutils')
            self.assert_(len(d) >= 1)
            self.assert_('libc6' in d)
            for dep in d:
                self.assert_(impl.get_version(dep))

            # Depends: only
            d  = impl.get_dependencies('libc6')
            self.assert_(len(d) >= 1)
            for dep in d:
                self.assert_(impl.get_version(dep))

        def test_get_source(self):
            '''get_source().'''

            self.assertRaises(ValueError, impl.get_source, 'nonexisting')
            self.assertEqual(impl.get_source('bash'), 'bash')
            self.assertEqual(impl.get_source('libc6'), 'glibc')

        def test_is_distro_package(self):
            '''is_distro_package().'''

            self.assertRaises(ValueError, impl.is_distro_package, 'nonexisting')
            self.assert_(impl.is_distro_package('bash'))
            # no False test here, hard to come up with a generic one

        def test_get_architecture(self):
            '''get_architecture().'''

            self.assertRaises(ValueError, impl.get_architecture, 'nonexisting')
            # just assume that bash uses the native architecture
            d = subprocess.Popen(['dpkg', '--print-architecture'],
                stdout=subprocess.PIPE)
            system_arch = d.communicate()[0].strip()
            assert d.returncode == 0
            self.assertEqual(impl.get_architecture('bash'), system_arch)

        def test_get_files(self):
            '''get_files().'''

            self.assertRaises(ValueError, impl.get_files, 'nonexisting')
            self.assert_('/bin/bash' in impl.get_files('bash'))

        def test_get_file_package(self):
            '''get_file_package() on installed files.'''

            self.assertEqual(impl.get_file_package('/bin/bash'), 'bash')
            self.assertEqual(impl.get_file_package('/bin/cat'), 'coreutils')
            self.assertEqual(impl.get_file_package('/nonexisting'), None)

        def test_get_file_package_uninstalled(self):
            '''get_file_package() on uninstalled packages.'''

            # determine distro release code name
            lsb_release = subprocess.Popen(['lsb_release', '-sc'],
                stdout=subprocess.PIPE)
            release_name = lsb_release.communicate()[0].strip()
            assert lsb_release.returncode == 0

            # generate a test Contents.gz
            basedir = tempfile.mkdtemp()
            try:
                mapdir = os.path.join(basedir, 'dists', release_name)
                os.makedirs(mapdir)
                print >> gzip.open(os.path.join(mapdir, 'Contents-%s.gz' %
                    impl.get_system_architecture()), 'w'), '''
 foo header
FILE                                                    LOCATION
usr/bin/frobnicate                                      foo/frob
usr/bin/frob                                            foo/frob-utils
bo/gu/s                                                 na/mypackage
'''

                self.assertEqual(impl.get_file_package('usr/bin/frob', False, mapdir), None)
                # must not match frob (same file name prefix)
                self.assertEqual(impl.get_file_package('usr/bin/frob', True, mapdir), 'frob-utils')
                self.assertEqual(impl.get_file_package('/usr/bin/frob', True, mapdir), 'frob-utils')

                # invalid mirror
                impl.set_mirror('file:///foo/nonexisting')
                self.assertRaises(IOError, impl.get_file_package, 'usr/bin/frob', True)

                # valid mirror, no cache directory
                impl.set_mirror('file://' + basedir)
                self.assertEqual(impl.get_file_package('usr/bin/frob', True), 'frob-utils')
                self.assertEqual(impl.get_file_package('/usr/bin/frob', True), 'frob-utils')

                # valid mirror, test caching
                cache_dir = os.path.join(basedir, 'cache')
                os.mkdir(cache_dir)
                self.assertEqual(impl.get_file_package('usr/bin/frob', True, cache_dir), 'frob-utils')
                self.assertEqual(len(os.listdir(cache_dir)), 1)
                self.assert_(os.listdir(cache_dir)[0].startswith('Contents-'))
                self.assertEqual(impl.get_file_package('/bo/gu/s', True, cache_dir), 'mypackage')
            finally:
                shutil.rmtree(basedir)

        def test_get_file_package_diversion(self):
            '''get_file_package() for a diverted file.'''

            # pick first diversion we have
            p = subprocess.Popen('LC_ALL=C dpkg-divert --list | head -n 1',
                shell=True, stdout=subprocess.PIPE)
            out = p.communicate()[0]
            assert p.returncode == 0
            assert out
            fields = out.split()
            file = fields[2]
            pkg = fields[-1]

            self.assertEqual(impl.get_file_package(file), pkg)

        def test_get_system_architecture(self):
            '''get_system_architecture().'''

            arch = impl.get_system_architecture()
            # must be nonempty without line breaks
            self.assertNotEqual(arch, '')
            self.assert_('\n' not in arch)

        def test_compare_versions(self):
            '''compare_versions.'''

            self.assertEqual(impl.compare_versions('1', '2'), -1)
            self.assertEqual(impl.compare_versions('1.0-1ubuntu1', '1.0-1ubuntu2'), -1)
            self.assertEqual(impl.compare_versions('1.0-1ubuntu1', '1.0-1ubuntu1'), 0)
            self.assertEqual(impl.compare_versions('1.0-1ubuntu2', '1.0-1ubuntu1'), 1)
            self.assertEqual(impl.compare_versions('1:1.0-1', '2007-2'), 1)
            self.assertEqual(impl.compare_versions('1:1.0-1~1', '1:1.0-1'), -1)

        def test_enabled(self):
            '''enabled.'''

            impl.configuration = '/nonexisting'
            self.assertEqual(impl.enabled(), True)

            f = tempfile.NamedTemporaryFile()
            impl.configuration = f.name
            f.write('# configuration file\nenabled = 1')
            f.flush()
            self.assertEqual(impl.enabled(), True)
            f.close()

            f = tempfile.NamedTemporaryFile()
            impl.configuration = f.name
            f.write('# configuration file\n  enabled =0  ')
            f.flush()
            self.assertEqual(impl.enabled(), False)
            f.close()

            f = tempfile.NamedTemporaryFile()
            impl.configuration = f.name
            f.write('# configuration file\nnothing here')
            f.flush()
            self.assertEqual(impl.enabled(), True)
            f.close()

        def test_get_kernel_pacakge(self):
            '''get_kernel_package().'''

            self.assert_('linux' in impl.get_kernel_package())

    # only execute if dpkg is available
    try:
        if subprocess.call(['dpkg', '--help'], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE) == 0:
            unittest.main()
    except OSError:
        pass
