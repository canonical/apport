import unittest, gzip, subprocess, tempfile, shutil, os, os.path, time
import glob, sys
from apt import apt_pkg
from importlib.machinery import SourceFileLoader

try:
    from urllib import urlopen
    URLError = IOError
    (urlopen)  # pyflakes
except ImportError:
    # python3
    from urllib.request import urlopen
    from urllib.error import URLError

if os.environ.get('APPORT_TEST_LOCAL'):
    impl = SourceFileLoader('', 'backends/packaging-apt-dpkg.py').load_module().impl
else:
    from apport.packaging_impl import impl


def _has_internet():
    '''Return if there is sufficient network connection for the tests.

    This checks if https://api.launchpad.net/devel/ubuntu/ can be downloaded
    from, to check if we can run the online tests.
    '''
    if os.environ.get('SKIP_ONLINE_TESTS'):
        return False
    if _has_internet.cache is None:
        _has_internet.cache = False
        try:
            if sys.version > '3':
                f = urlopen('https://api.launchpad.net/devel/ubuntu/', timeout=30)
            else:
                f = urlopen('https://api.launchpad.net/devel/ubuntu/')
            if b"web_link" in f.readline():
                _has_internet.cache = True
        except URLError:
            pass
    return _has_internet.cache


_has_internet.cache = None


class T(unittest.TestCase):
    def setUp(self):
        # save and restore configuration file
        self.orig_conf = impl.configuration
        self.workdir = tempfile.mkdtemp()
        # reset internal caches between tests
        impl._apt_cache = None
        impl._sandbox_apt_cache = None

    def tearDown(self):
        impl.configuration = self.orig_conf
        shutil.rmtree(self.workdir)

    def test_check_files_md5(self):
        '''_check_files_md5().'''

        td = tempfile.mkdtemp()
        try:
            f1 = os.path.join(td, 'test 1.txt')
            f2 = os.path.join(td, 'test:2.txt')
            sumfile = os.path.join(td, 'sums.txt')
            with open(f1, 'w') as fd:
                fd.write('Some stuff')
            with open(f2, 'w') as fd:
                fd.write('More stuff')
            # use one relative and one absolute path in checksums file
            with open(sumfile, 'wb') as fd:
                fd.write(b'2e41290da2fa3f68bd3313174467e3b5  ' + f1[1:].encode() + b'\n')
                fd.write(b'f6423dfbc4faf022e58b4d3f5ff71a70  ' + f2.encode() + b'\n')
                fd.write(b'deadbeef000001111110000011110000  /bin/\xc3\xa4')
            self.assertEqual(impl._check_files_md5(sumfile), [], 'correct md5sums')

            with open(f1, 'w') as fd:
                fd.write('Some stuff!')
            self.assertEqual(impl._check_files_md5(sumfile), [f1[1:]], 'file 1 wrong')
            with open(f2, 'w') as fd:
                fd.write('More stuff!')
            self.assertEqual(impl._check_files_md5(sumfile), [f1[1:], f2], 'files 1 and 2 wrong')
            with open(f1, 'w') as fd:
                fd.write('Some stuff')
            self.assertEqual(impl._check_files_md5(sumfile), [f2], 'file 2 wrong')

            # check using a direct md5 list as argument
            with open(sumfile, 'rb') as fd:
                self.assertEqual(impl._check_files_md5(fd.read()),
                                 [f2], 'file 2 wrong')

        finally:
            shutil.rmtree(td)

    def test_get_version(self):
        '''get_version().'''

        self.assertTrue(impl.get_version('libc6').startswith('2'))
        self.assertRaises(ValueError, impl.get_version, 'nonexisting')
        self.assertRaises(ValueError, impl.get_version, 'wukrainian')

    def test_get_available_version(self):
        '''get_available_version().'''

        self.assertTrue(impl.get_available_version('libc6').startswith('2'))
        self.assertRaises(ValueError, impl.get_available_version, 'nonexisting')

    def test_get_dependencies(self):
        '''get_dependencies().'''

        # package with both Depends: and Pre-Depends:
        d = impl.get_dependencies('bash')
        self.assertGreater(len(d), 2)
        self.assertIn('libc6', d)
        for dep in d:
            self.assertTrue(impl.get_version(dep))

        # Pre-Depends: only
        d = impl.get_dependencies('coreutils')
        self.assertGreaterEqual(len(d), 1)
        self.assertIn('libc6', d)
        for dep in d:
            self.assertTrue(impl.get_version(dep))

        # Depends: only
        d = impl.get_dependencies('libc-bin')
        self.assertGreaterEqual(len(d), 1)
        for dep in d:
            self.assertTrue(impl.get_version(dep))

    def test_get_source(self):
        '''get_source().'''

        self.assertRaises(ValueError, impl.get_source, 'nonexisting')
        self.assertEqual(impl.get_source('bash'), 'bash')
        self.assertIn('glibc', impl.get_source('libc6'))

    def test_get_package_origin(self):
        '''get_package_origin().'''

        # determine distro name
        distro = impl.get_os_version()[0]

        self.assertRaises(ValueError, impl.get_package_origin, 'nonexisting')
        # this assumes that this package is not installed
        self.assertRaises(ValueError, impl.get_package_origin, 'robocode-doc')
        # this assumes that bash is native
        self.assertEqual(impl.get_package_origin('bash'), distro)
        # no non-native test here, hard to come up with a generic one

    def test_is_distro_package(self):
        '''is_distro_package().'''

        self.assertRaises(ValueError, impl.is_distro_package, 'nonexisting')
        self.assertTrue(impl.is_distro_package('bash'))
        # no False test here, hard to come up with a generic one

    def test_get_architecture(self):
        '''get_architecture().'''

        self.assertRaises(ValueError, impl.get_architecture, 'nonexisting')
        # just assume that bash uses the native architecture
        d = subprocess.Popen(['dpkg', '--print-architecture'],
                             stdout=subprocess.PIPE)
        system_arch = d.communicate()[0].decode().strip()
        assert d.returncode == 0
        self.assertEqual(impl.get_architecture('bash'), system_arch)

    def test_get_files(self):
        '''get_files().'''

        self.assertRaises(ValueError, impl.get_files, 'nonexisting')
        self.assertIn('/bin/bash', impl.get_files('bash'))

    def test_get_file_package(self):
        '''get_file_package() on installed files.'''

        self.assertEqual(impl.get_file_package('/bin/bash'), 'bash')
        self.assertEqual(impl.get_file_package('/bin/cat'), 'coreutils')
        self.assertEqual(impl.get_file_package('/etc/pam.conf'), 'libpam-runtime')
        self.assertEqual(impl.get_file_package('/nonexisting'), None)

    def test_get_file_package_uninstalled(self):
        '''get_file_package() on uninstalled packages.'''

        # generate a test Contents.gz
        basedir = tempfile.mkdtemp()
        try:
            # test Contents.gz for release pocket
            mapdir = os.path.join(basedir, 'dists', impl.get_distro_codename())
            os.makedirs(mapdir)
            with gzip.open(os.path.join(mapdir, 'Contents-%s.gz' %
                                        impl.get_system_architecture()), 'w') as f:
                f.write(b'''usr/bin/frobnicate                                      foo/frob
usr/bin/frob                                            foo/frob-utils
bo/gu/s                                                 na/mypackage
bin/true                                                admin/superutils
''')

            # test Contents.gz for -updates pocket
            mapdir = os.path.join(basedir, 'dists', impl.get_distro_codename() + '-updates')
            os.makedirs(mapdir)
            with gzip.open(os.path.join(mapdir, 'Contents-%s.gz' %
                                        impl.get_system_architecture()), 'w') as f:
                f.write(b'''lib/libnew.so.5                                         universe/libs/libnew5
''')

            # use this as a mirror
            impl.set_mirror('file://' + basedir)

            self.assertEqual(impl.get_file_package('usr/bin/frob', False), None)
            # must not match frob (same file name prefix)
            self.assertEqual(impl.get_file_package('usr/bin/frob', True), 'frob-utils')
            self.assertEqual(impl.get_file_package('/usr/bin/frob', True), 'frob-utils')
            # find files from -updates pocket
            self.assertEqual(impl.get_file_package('/lib/libnew.so.5', False), None)
            self.assertEqual(impl.get_file_package('/lib/libnew.so.5', True), 'libnew5')

            # invalid mirror
            impl.set_mirror('file:///foo/nonexisting')
            self.assertRaises(IOError, impl.get_file_package, 'usr/bin/frob', True)

            # valid mirror, test cache directory
            impl.set_mirror('file://' + basedir)
            cache_dir = os.path.join(basedir, 'cache')
            os.mkdir(cache_dir)
            self.assertEqual(impl.get_file_package('usr/bin/frob', True, cache_dir), 'frob-utils')
            cache_dir_files = os.listdir(cache_dir)
            self.assertEqual(len(cache_dir_files), 3)
            self.assertEqual(impl.get_file_package('/bo/gu/s', True, cache_dir), None)

            # valid cache, should not need to access the mirror
            impl.set_mirror('file:///foo/nonexisting')
            self.assertEqual(impl.get_file_package('/bin/true', True, cache_dir), 'superutils')
            self.assertEqual(impl.get_file_package('/bo/gu/s', True, cache_dir), None)
            self.assertEqual(impl.get_file_package('/lib/libnew.so.5', True, cache_dir), 'libnew5')

            # outdated cache, must refresh the cache and hit the invalid
            # mirror
            if 'updates' in cache_dir_files[0]:
                cache_file = cache_dir_files[1]
            else:
                cache_file = cache_dir_files[0]
            now = int(time.time())
            os.utime(os.path.join(cache_dir, cache_file), (now, now - 90000))
        finally:
            shutil.rmtree(basedir)

    def test_get_file_package_uninstalled_multiarch(self):
        '''get_file_package() on foreign arches and releases'''

        # map "Foonux 3.14" to "mocky"
        orig_distro_release_to_codename = impl._distro_release_to_codename
        impl._distro_release_to_codename = lambda r: (r == 'Foonux 3.14') and 'mocky' or None

        # generate test Contents.gz for two fantasy architectures
        basedir = tempfile.mkdtemp()
        try:
            mapdir = os.path.join(basedir, 'dists', impl.get_distro_codename())
            os.makedirs(mapdir)
            with gzip.open(os.path.join(mapdir, 'Contents-even.gz'), 'w') as f:
                f.write(b'''usr/lib/even/libfrob.so.1                               foo/libfrob1
usr/bin/frob                                            foo/frob-utils
''')
            with gzip.open(os.path.join(mapdir, 'Contents-odd.gz'), 'w') as f:
                f.write(b'''usr/lib/odd/libfrob.so.1                                foo/libfrob1
usr/bin/frob                                            foo/frob-utils
''')

            # and another one for fantasy release
            os.mkdir(os.path.join(basedir, 'dists', 'mocky'))
            with gzip.open(os.path.join(basedir, 'dists', 'mocky', 'Contents-even.gz'), 'w') as f:
                f.write(b'''usr/lib/even/libfrob.so.0                               foo/libfrob0
usr/bin/frob                                            foo/frob
''')

            # use this as a mirror
            impl.set_mirror('file://' + basedir)

            # must not match system architecture
            self.assertEqual(impl.get_file_package('usr/bin/frob', False), None)
            # must match correct architecture
            self.assertEqual(impl.get_file_package('usr/bin/frob', True, arch='even'),
                             'frob-utils')
            self.assertEqual(impl.get_file_package('usr/bin/frob', True, arch='odd'),
                             'frob-utils')
            self.assertEqual(impl.get_file_package('/usr/lib/even/libfrob.so.1', True, arch='even'),
                             'libfrob1')
            self.assertEqual(impl.get_file_package('/usr/lib/even/libfrob.so.1', True, arch='odd'),
                             None)
            self.assertEqual(impl.get_file_package('/usr/lib/odd/libfrob.so.1', True, arch='odd'),
                             'libfrob1')

            # for mocky release ("Foonux 3.14")
            self.assertEqual(impl.get_file_package('/usr/lib/even/libfrob.so.1',
                                                   True, release='Foonux 3.14', arch='even'),
                             None)
            self.assertEqual(impl.get_file_package('/usr/lib/even/libfrob.so.0',
                                                   True, release='Foonux 3.14', arch='even'),
                             'libfrob0')
            self.assertEqual(impl.get_file_package('/usr/bin/frob',
                                                   True, release='Foonux 3.14', arch='even'),
                             'frob')

            # invalid mirror
            impl.set_mirror('file:///foo/nonexisting')
            self.assertRaises(IOError, impl.get_file_package,
                              '/usr/lib/even/libfrob.so.1', True, arch='even')
            self.assertRaises(IOError, impl.get_file_package,
                              '/usr/lib/even/libfrob.so.0', True, release='Foonux 3.14', arch='even')

            # valid mirror, test caching
            impl.set_mirror('file://' + basedir)
            cache_dir = os.path.join(basedir, 'cache')
            os.mkdir(cache_dir)
            self.assertEqual(impl.get_file_package('/usr/lib/even/libfrob.so.1',
                                                   True, cache_dir, arch='even'),
                             'libfrob1')
            self.assertEqual(len(os.listdir(cache_dir)), 2)

            self.assertEqual(impl.get_file_package('/usr/lib/even/libfrob.so.0',
                                                   True, cache_dir, release='Foonux 3.14', arch='even'),
                             'libfrob0')
            self.assertEqual(len(os.listdir(cache_dir)), 4)

            # valid cache, should not need to access the mirror
            impl.set_mirror('file:///foo/nonexisting')
            self.assertEqual(impl.get_file_package('usr/bin/frob', True, cache_dir, arch='even'),
                             'frob-utils')
            self.assertEqual(impl.get_file_package('usr/bin/frob', True, cache_dir,
                                                   release='Foonux 3.14', arch='even'),
                             'frob')

            # but no cached file for the other arch
            self.assertRaises(IOError, impl.get_file_package, 'usr/bin/frob',
                              True, cache_dir, arch='odd')

            # outdated cache, must refresh the cache and hit the invalid
            # mirror
            now = int(time.time())
            for cache_file in os.listdir(cache_dir):
                os.utime(os.path.join(cache_dir, cache_file), (now, now - 90000))

            self.assertRaises(IOError, impl.get_file_package, 'usr/bin/frob',
                              True, cache_dir, arch='even')
        finally:
            shutil.rmtree(basedir)
            impl._distro_release_to_codename = orig_distro_release_to_codename

    def test_get_file_package_diversion(self):
        '''get_file_package() for a diverted file.'''

        # pick first diversion we have
        p = subprocess.Popen('LC_ALL=C dpkg-divert --list | head -n 1',
                             shell=True, stdout=subprocess.PIPE)
        out = p.communicate()[0].decode('UTF-8')
        assert p.returncode == 0
        assert out
        fields = out.split()
        file = fields[2]
        pkg = fields[-1]

        self.assertEqual(impl.get_file_package(file), pkg)

    def test_mirror_from_apt_sources(self):
        s = os.path.join(self.workdir, 'sources.list')

        # valid file, should grab the first mirror
        with open(s, 'w') as f:
            f.write('''# some comment
deb-src http://source.mirror/foo tuxy main
deb http://binary.mirror/tuxy tuxy main
deb http://secondary.mirror tuxy extra
''')
            f.flush()
            self.assertEqual(impl._get_primary_mirror_from_apt_sources(s),
                             'http://binary.mirror/tuxy')

        # valid file with options
        with open(s, 'w') as f:
            f.write('''# some comment
deb-src http://source.mirror/foo tuxy main
deb [arch=flowerpc,leghf] http://binary.mirror/tuxy tuxy main
deb http://secondary.mirror tuxy extra
''')
            f.flush()
            self.assertEqual(impl._get_primary_mirror_from_apt_sources(s),
                             'http://binary.mirror/tuxy')

        # empty file
        with open(s, 'w') as f:
            f.flush()
        self.assertRaises(SystemError, impl._get_primary_mirror_from_apt_sources, s)

    def test_get_modified_conffiles(self):
        '''get_modified_conffiles()'''

        # very shallow
        self.assertEqual(type(impl.get_modified_conffiles('bash')), type({}))
        self.assertEqual(type(impl.get_modified_conffiles('apport')), type({}))
        self.assertEqual(type(impl.get_modified_conffiles('nonexisting')), type({}))

    def test_get_system_architecture(self):
        '''get_system_architecture().'''

        arch = impl.get_system_architecture()
        # must be nonempty without line breaks
        self.assertNotEqual(arch, '')
        self.assertNotIn('\n', arch)

    def test_get_library_paths(self):
        '''get_library_paths().'''

        paths = impl.get_library_paths()
        # must be nonempty without line breaks
        self.assertNotEqual(paths, '')
        self.assertIn(':', paths)
        self.assertIn('/lib', paths)
        self.assertNotIn('\n', paths)

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
        f.write('# configuration file\nenabled = 1'.encode())
        f.flush()
        self.assertEqual(impl.enabled(), True)
        f.close()

        f = tempfile.NamedTemporaryFile()
        impl.configuration = f.name
        f.write('# configuration file\n  enabled =0  '.encode())
        f.flush()
        self.assertEqual(impl.enabled(), False)
        f.close()

        f = tempfile.NamedTemporaryFile()
        impl.configuration = f.name
        f.write('# configuration file\nnothing here'.encode())
        f.flush()
        self.assertEqual(impl.enabled(), True)
        f.close()

    def test_get_kernel_package(self):
        '''get_kernel_package().'''

        self.assertIn('linux', impl.get_kernel_package())

    def test_package_name_glob(self):
        '''package_name_glob().'''

        self.assertGreater(len(impl.package_name_glob('a*')), 5)
        self.assertIn('bash', impl.package_name_glob('ba*h'))
        self.assertEqual(impl.package_name_glob('bash'), ['bash'])
        self.assertEqual(impl.package_name_glob('xzywef*'), [])

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_install_packages_versioned(self):
        '''install_packages() with versions and with cache'''

        self._setup_foonux_config(release='xenial', updates=True)
        v_coreutils = '8.25-2ubuntu2'
        v_libc = '2.23-0ubuntu3'
        obsolete = impl.install_packages(self.rootdir, self.configdir,
                                         'Foonux 16.04',
                                         [('coreutils', v_coreutils),  # should not come from updates
                                          ('libc6', v_libc),
                                          ('tzdata', None),  # should come from -updates, > 2014b-1
                                         ], False, self.cachedir)

        def sandbox_ver(pkg):
            with gzip.open(os.path.join(self.rootdir, 'usr/share/doc', pkg,
                                        'changelog.Debian.gz')) as f:
                return f.readline().decode().split()[1][1:-1]

        self.assertEqual(obsolete, '')

        # packages get installed
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/bin/stat')))
        self.assert_elf_arch(os.path.join(self.rootdir, 'usr/bin/stat'),
                             impl.get_system_architecture())
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/lib/debug/.build-id')))
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/share/zoneinfo/zone.tab')))
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/share/doc/libc6/copyright')))

        # their versions are as expected
        self.assertEqual(sandbox_ver('coreutils'), v_coreutils)
        self.assertEqual(sandbox_ver('libc6'), v_libc)
        self.assertEqual(sandbox_ver('libc6-dbg'), v_libc)
        self.assertGreater(sandbox_ver('tzdata'), '2016')

        with open(os.path.join(self.rootdir, 'packages.txt')) as f:
            pkglist = f.read().splitlines()
        self.assertIn('coreutils ' + v_coreutils, pkglist)
        self.assertIn('coreutils-dbgsym ' + v_coreutils, pkglist)
        self.assertIn('libc6 ' + v_libc, pkglist)
        self.assertIn('libc6-dbg ' + v_libc, pkglist)
        self.assertIn('tzdata ' + sandbox_ver('tzdata'), pkglist)
        self.assertEqual(len(pkglist), 5, str(pkglist))

        # does not clobber config dir
        self.assertEqual(os.listdir(self.configdir), ['Foonux 16.04'])
        self.assertEqual(sorted(os.listdir(os.path.join(self.configdir, 'Foonux 16.04'))),
                         ['armhf', 'codename', 'sources.list', 'trusted.gpg.d'])
        self.assertEqual(sorted(os.listdir(os.path.join(self.configdir, 'Foonux 16.04', 'armhf'))),
                         ['sources.list', 'trusted.gpg.d'])

        # caches packages, and their versions are as expected
        cache = os.listdir(os.path.join(self.cachedir, 'Foonux 16.04', 'apt',
                                        'var', 'cache', 'apt', 'archives'))
        cache_versions = {}
        for p in cache:
            try:
                (name, ver) = p.split('_')[:2]
                cache_versions[name] = ver
            except ValueError:
                pass  # not a .deb, ignore
        self.assertEqual(cache_versions['coreutils'], v_coreutils)
        self.assertEqual(cache_versions['coreutils-dbgsym'], v_coreutils)
        self.assertIn('tzdata', cache_versions)
        self.assertEqual(cache_versions['libc6'], v_libc)
        self.assertEqual(cache_versions['libc6-dbg'], v_libc)

        # installs cached packages
        os.unlink(os.path.join(self.rootdir, 'usr/bin/stat'))
        os.unlink(os.path.join(self.rootdir, 'packages.txt'))
        obsolete = impl.install_packages(self.rootdir, self.configdir,
                                         'Foonux 16.04',
                                         [('coreutils', v_coreutils),
                                         ], False, self.cachedir)
        self.assertEqual(obsolete, '')
        self.assertTrue(os.path.exists(
            os.path.join(self.rootdir, 'usr/bin/stat')))

        # complains about obsolete packages
        result = impl.install_packages(self.rootdir, self.configdir,
                                       'Foonux 16.04', [('aspell-doc', '1.1')])
        self.assertIn('aspell-doc version 1.1 required, but 0.60.7~20110707-3', result)
        # ... but installs the current version anyway
        self.assertTrue(os.path.exists(
            os.path.join(self.rootdir, 'usr/share/info/aspell.info.gz')))
        self.assertGreaterEqual(sandbox_ver('aspell-doc'), '0.60.7~2011')

        # does not crash on nonexisting packages
        result = impl.install_packages(self.rootdir, self.configdir,
                                       'Foonux 16.04', [('buggerbogger', None)])
        self.assertEqual(len(result.splitlines()), 1)
        self.assertIn('buggerbogger', result)
        self.assertIn('not exist', result)

        # can interleave with other operations
        dpkg = subprocess.Popen(['dpkg-query', '-Wf${Version}', 'dash'],
                                stdout=subprocess.PIPE)
        dash_version = dpkg.communicate()[0].decode()
        self.assertEqual(dpkg.returncode, 0)

        self.assertEqual(impl.get_version('dash'), dash_version)
        self.assertRaises(ValueError, impl.get_available_version, 'buggerbogger')

        # still installs packages after above operations
        os.unlink(os.path.join(self.rootdir, 'usr/bin/stat'))
        os.unlink(os.path.join(self.rootdir, 'packages.txt'))
        impl.install_packages(self.rootdir, self.configdir, 'Foonux 16.04',
                              [('coreutils', v_coreutils),
                               ('dpkg', None),
                              ], False, self.cachedir)
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/bin/stat')))
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/bin/dpkg')))

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_install_packages_unversioned(self):
        '''install_packages() without versions and no cache'''

        self._setup_foonux_config(release='xenial')
        obsolete = impl.install_packages(self.rootdir, self.configdir,
                                         'Foonux 16.04',
                                         [('coreutils', None),
                                          ('tzdata', None),
                                         ], False, None)

        self.assertEqual(obsolete, '')
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/bin/stat')))
        self.assert_elf_arch(os.path.join(self.rootdir, 'usr/bin/stat'),
                             impl.get_system_architecture())
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/lib/debug/.build-id')))
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/share/zoneinfo/zone.tab')))

        # does not clobber config dir
        self.assertEqual(os.listdir(self.configdir), ['Foonux 16.04'])
        self.assertEqual(sorted(os.listdir(os.path.join(self.configdir, 'Foonux 16.04'))),
                         ['armhf', 'codename', 'sources.list', 'trusted.gpg.d'])
        self.assertEqual(sorted(os.listdir(os.path.join(self.configdir, 'Foonux 16.04', 'armhf'))),
                         ['sources.list', 'trusted.gpg.d'])

        # no cache
        self.assertEqual(os.listdir(self.cachedir), [])

        # keeps track of package versions
        with open(os.path.join(self.rootdir, 'packages.txt')) as f:
            pkglist = f.read().splitlines()
        self.assertIn('coreutils 8.25-2ubuntu2', pkglist)
        self.assertIn('coreutils-dbgsym 8.25-2ubuntu2', pkglist)
        self.assertIn('tzdata 2016d-0ubuntu0.16.04', pkglist)
        self.assertEqual(len(pkglist), 3, str(pkglist))

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_install_packages_dependencies(self):
        '''install packages's dependencies'''

        self._setup_foonux_config(release='xenial')
        # coreutils should always depend on libc6
        result = impl.install_packages(self.rootdir, self.configdir,
                                       'Foonux 16.04',
                                       [('coreutils', None)],
                                       False, None, install_deps=True)

        # check packages.txt for a dependency
        with open(os.path.join(self.rootdir, 'packages.txt')) as f:
            pkglist = f.read().splitlines()
        self.assertIn('coreutils 8.25-2ubuntu2', pkglist)
        self.assertIn('libc6 2.23-0ubuntu3', pkglist)

        # ensure obsolete packages doesn't include libc6
        self.assertNotIn('libc6', result)

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_install_packages_system(self):
        '''install_packages() with system configuration'''

        # trigger an unrelated package query here to get the cache set up,
        # reproducing an install failure when the internal caches are not
        # reset properly
        impl.get_version('dash')

        self._setup_foonux_config(impl.get_distro_codename())
        lsb_release = subprocess.Popen(['lsb_release', '-sr'],
                                       stdout=subprocess.PIPE)
        system_version = lsb_release.communicate()[0].decode('UTF-8').strip()
        result = impl.install_packages(self.rootdir, None, system_version,
                                       [('coreutils', impl.get_version('coreutils')),
                                        ('tzdata', '1.1'),
                                       ], False, self.cachedir)

        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/bin/stat')))
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/share/zoneinfo/zone.tab')))

        # complains about obsolete packages
        self.assertGreaterEqual(len(result.splitlines()), 1)
        self.assertIn('tzdata', result)
        self.assertIn('1.1', result)

        # caches packages
        cache = os.listdir(os.path.join(self.cachedir, 'system', 'apt',
                                        'var', 'cache', 'apt', 'archives'))
        cache_names = [p.split('_')[0] for p in cache]
        self.assertIn('coreutils', cache_names)
        self.assertIn('coreutils-dbgsym', cache_names)
        self.assertIn('tzdata', cache_names)

        # works with relative paths and existing cache
        os.unlink(os.path.join(self.rootdir, 'usr/bin/stat'))
        os.unlink(os.path.join(self.rootdir, 'packages.txt'))
        orig_cwd = os.getcwd()
        try:
            os.chdir(self.workdir)
            impl.install_packages('root', None, None,
                                  [('coreutils', None)], False, 'cache')
        finally:
            os.chdir(orig_cwd)
            self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                        'usr/bin/stat')))

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_install_packages_error(self):
        '''install_packages() with errors'''

        # sources.list with invalid format
        self._setup_foonux_config()
        with open(os.path.join(self.configdir, 'Foonux 14.04', 'sources.list'), 'w') as f:
            f.write('bogus format')

        try:
            impl.install_packages(self.rootdir, self.configdir, 'Foonux 14.04',
                                  [('tzdata', None)], False, self.cachedir)
            self.fail('install_packages() unexpectedly succeeded with broken sources.list')
        except SystemError as e:
            self.assertIn('bogus', str(e))
            self.assertNotIn('Exception', str(e))

        # sources.list with wrong server
        with open(os.path.join(self.configdir, 'Foonux 14.04', 'sources.list'), 'w') as f:
            f.write('deb http://archive.ubuntu.com/nosuchdistro/ trusty main\n')

        try:
            impl.install_packages(self.rootdir, self.configdir, 'Foonux 14.04',
                                  [('tzdata', None)], False, self.cachedir)
            self.fail('install_packages() unexpectedly succeeded with broken server URL')
        except SystemError as e:
            self.assertIn('nosuchdistro', str(e))
            try:
                self.assertRegex(str(e), ".*'http://archive.ubuntu.com/nosuchdistro trusty.*' does not have a Release file")
            except AssertionError:
                self.assertIn('index files failed to download', str(e))

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_install_packages_permanent_sandbox(self):
        '''install_packages() with a permanent sandbox'''

        self._setup_foonux_config()
        zonetab = os.path.join(self.rootdir, 'usr/share/zoneinfo/zone.tab')

        impl.install_packages(self.rootdir, self.configdir, 'Foonux 14.04',
                              [('tzdata', None)], False, self.cachedir, permanent_rootdir=True)

        # This will now be using a Cache with our rootdir.
        archives = apt_pkg.config.find_dir('Dir::Cache::archives')
        tzdata = glob.glob(os.path.join(archives, 'tzdata*.deb'))
        if not tzdata:
            self.fail('tzdata was not downloaded')
        tzdata_written = os.path.getctime(tzdata[0])
        zonetab_written = os.path.getctime(zonetab)

        impl.install_packages(self.rootdir, self.configdir, 'Foonux 14.04',
                              [('coreutils', None), ('tzdata', None)], False, self.cachedir,
                              permanent_rootdir=True)

        if not glob.glob(os.path.join(archives, 'coreutils*.deb')):
            self.fail('coreutils was not downloaded.')
            self.assertEqual(os.path.getctime(tzdata[0]), tzdata_written,
                             'tzdata downloaded twice.')
            self.assertEqual(zonetab_written, os.path.getctime(zonetab),
                             'zonetab written twice.')
            self.assertTrue(os.path.exists(
                os.path.join(self.rootdir, 'usr/bin/stat')))

        # Prevent packages from downloading.
        orig_apt_proxy = apt_pkg.config.get('Acquire::http::Proxy')
        apt_pkg.config.set('Acquire::http::Proxy', 'http://nonexistent')
        orig_http_proxy = os.environ.get('http_proxy')
        os.environ['http_proxy'] = 'http://nonexistent'
        try:
            orig_no_proxy = os.environ['no_proxy']
            del os.environ['no_proxy']
        except KeyError:
            orig_no_proxy = None

        self.assertRaises(SystemExit, impl.install_packages, self.rootdir,
                          self.configdir, 'Foonux 14.04', [('libc6', None)], False,
                          self.cachedir, permanent_rootdir=True)

        # These packages exist, so attempting to install them should not fail.
        impl.install_packages(self.rootdir, self.configdir, 'Foonux 14.04',
                              [('coreutils', None), ('tzdata', None)], False, self.cachedir,
                              permanent_rootdir=True)
        # even without cached debs, trying to install the same versions should
        # be a no-op and succeed
        for f in glob.glob('%s/Foonux 14.04/apt/var/cache/apt/archives/coreutils*' % self.cachedir):
            os.unlink(f)
        impl.install_packages(self.rootdir, self.configdir, 'Foonux 14.04',
                              [('coreutils', None)], False, self.cachedir,
                              permanent_rootdir=True)

        # trying to install another package should fail, though
        self.assertRaises(SystemExit, impl.install_packages, self.rootdir,
                          self.configdir, 'Foonux 14.04', [('aspell-doc', None)], False,
                          self.cachedir, permanent_rootdir=True)

        # restore original proxy settings
        if orig_http_proxy:
            os.environ['http_proxy'] = orig_http_proxy
        else:
            del os.environ['http_proxy']
        if orig_no_proxy:
            os.environ['no_proxy'] = orig_no_proxy
        apt_pkg.config.set('Acquire::http::Proxy', orig_apt_proxy)

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_install_packages_permanent_sandbox_repack(self):
        self._setup_foonux_config()
        include_path = os.path.join(self.rootdir, 'usr/include/krb5.h')
        impl.install_packages(self.rootdir, self.configdir, 'Foonux 14.04',
                              [('libkrb5-dev', None)], False, self.cachedir,
                              permanent_rootdir=True)
        self.assertIn('mit-krb5/', os.readlink(include_path))

        impl.install_packages(self.rootdir, self.configdir, 'Foonux 14.04',
                              [('heimdal-dev', None)], False, self.cachedir,
                              permanent_rootdir=True)
        self.assertIn('heimdal/', os.readlink(include_path))

        impl.install_packages(self.rootdir, self.configdir, 'Foonux 14.04',
                              [('libkrb5-dev', None)], False, self.cachedir,
                              permanent_rootdir=True)
        self.assertIn('mit-krb5/', os.readlink(include_path))

    @unittest.skipUnless(_has_internet(), 'online test')
    @unittest.skipIf(impl.get_system_architecture() == 'armhf', 'native armhf architecture')
    def test_install_packages_armhf(self):
        '''install_packages() for foreign architecture armhf'''

        self._setup_foonux_config(release='xenial')
        vers = '16.04'
        # install the GPG key for ports and xenial
        keyring_dir = os.path.join(self.configdir, 'Foonux %s' % vers, 'trusted.gpg.d')
        os.makedirs(keyring_dir, exist_ok=True)
        subprocess.check_call(['/usr/lib/apt/apt-helper', 'download-file',
                               'http://ports.ubuntu.com/project/ubuntu-archive-keyring.gpg',
                               os.path.join(keyring_dir, 'ports.ubuntu.com.gpg')],
                              stdout=subprocess.DEVNULL)
        obsolete = impl.install_packages(self.rootdir, self.configdir, 'Foonux %s' % vers,
                                         [('coreutils', None),
                                          ('libc6', '2.23-0ubuntu0'),
                                         ], False, self.cachedir,
                                         architecture='armhf')

        self.assertEqual(obsolete, 'libc6 version 2.23-0ubuntu0 required, but 2.23-0ubuntu3 is available\n')

        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/bin/stat')))
        self.assert_elf_arch(os.path.join(self.rootdir, 'usr/bin/stat'), 'armhf')
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/share/doc/libc6/copyright')))
        # caches packages
        cache = os.listdir(os.path.join(self.cachedir, 'Foonux 16.04', 'armhf', 'apt',
                                        'var', 'cache', 'apt', 'archives'))
        self.assertIn('coreutils_8.25-2ubuntu2_armhf.deb', cache)
        self.assertIn('libc6_2.23-0ubuntu3_armhf.deb', cache)

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_install_packages_from_launchpad(self):
        '''install_packages() using packages only available on Launchpad'''

        self._setup_foonux_config()
        obsolete = impl.install_packages(self.rootdir, self.configdir, 'Foonux 14.04',
                                         [('oxideqt-codecs',
                                           '1.6.6-0ubuntu0.14.04.1'),
                                          ('distro-info-data',
                                           '0.18ubuntu0.2'),
                                          ('qemu-utils',
                                           '2.0.0+dfsg-2ubuntu1.11'),
                                          ('unity-services',
                                           '7.2.5+14.04.20150521.1-0ubuntu1'),
                                         ], False, self.cachedir)

        def sandbox_ver(pkg, debian=True):
            if debian:
                changelog = 'changelog.Debian.gz'
            else:
                changelog = 'changelog.gz'
            with gzip.open(os.path.join(self.rootdir, 'usr/share/doc', pkg,
                                        changelog)) as f:
                return f.readline().decode().split()[1][1:-1]

        self.assertEqual(obsolete, '')

        # packages get installed
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/share/doc/oxideqt-codecs/copyright')))
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
                                                    'usr/share/distro-info/ubuntu.csv')))

        # their versions are as expected
        self.assertEqual(sandbox_ver('oxideqt-codecs'),
                         '1.6.6-0ubuntu0.14.04.1')
        self.assertEqual(sandbox_ver('oxideqt-codecs-dbg'),
                         '1.6.6-0ubuntu0.14.04.1')
        self.assertEqual(sandbox_ver('distro-info-data', debian=False),
                         '0.18ubuntu0.2')

        # keeps track of package versions
        with open(os.path.join(self.rootdir, 'packages.txt')) as f:
            pkglist = f.read().splitlines()
        self.assertIn('oxideqt-codecs 1.6.6-0ubuntu0.14.04.1', pkglist)
        self.assertIn('oxideqt-codecs-dbg 1.6.6-0ubuntu0.14.04.1', pkglist)
        self.assertIn('distro-info-data 0.18ubuntu0.2', pkglist)
        self.assertIn('qemu-utils-dbgsym 2.0.0+dfsg-2ubuntu1.11',
                      pkglist)
        self.assertIn('unity-services-dbgsym 7.2.5+14.04.20150521.1-0ubuntu1',
                      pkglist)

        # caches packages, and their versions are as expected
        cache = os.listdir(os.path.join(self.cachedir, 'Foonux 14.04', 'apt',
                                        'var', 'cache', 'apt', 'archives'))

        # archive and launchpad versions of packages exist in the cache, so use a list
        cache_versions = []
        for p in cache:
            try:
                (name, ver) = p.split('_')[:2]
                cache_versions.append((name, ver))
            except ValueError:
                pass  # not a .deb, ignore
        self.assertIn(('oxideqt-codecs', '1.6.6-0ubuntu0.14.04.1'), cache_versions)
        self.assertIn(('oxideqt-codecs-dbg', '1.6.6-0ubuntu0.14.04.1'), cache_versions)
        self.assertIn(('distro-info-data', '0.18ubuntu0.2'), cache_versions)
        self.assertIn(('qemu-utils-dbgsym', '2.0.0+dfsg-2ubuntu1.11'), cache_versions)

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_install_old_packages(self):
        '''sandbox will install older package versions from launchpad'''

        self._setup_foonux_config()
        obsolete = impl.install_packages(self.rootdir, self.configdir, 'Foonux 14.04',
                                         [('oxideqt-codecs',
                                           '1.7.8-0ubuntu0.14.04.1'),
                                         ], False, self.cachedir)

        self.assertEqual(obsolete, '')

        def sandbox_ver(pkg):
            with gzip.open(os.path.join(self.rootdir, 'usr/share/doc', pkg,
                                        'changelog.Debian.gz')) as f:
                return f.readline().decode().split()[1][1:-1]

        # the version is as expected
        self.assertEqual(sandbox_ver('oxideqt-codecs'),
                         '1.7.8-0ubuntu0.14.04.1')

        # keeps track of package version
        with open(os.path.join(self.rootdir, 'packages.txt')) as f:
            pkglist = f.read().splitlines()
        self.assertIn('oxideqt-codecs 1.7.8-0ubuntu0.14.04.1', pkglist)

        obsolete = impl.install_packages(self.rootdir, self.configdir, 'Foonux 14.04',
                                         [('oxideqt-codecs',
                                           '1.6.6-0ubuntu0.14.04.1'),
                                         ], False, self.cachedir)

        self.assertEqual(obsolete, '')

        # the old version is installed
        self.assertEqual(sandbox_ver('oxideqt-codecs'),
                         '1.6.6-0ubuntu0.14.04.1')

        # the old versions is tracked
        with open(os.path.join(self.rootdir, 'packages.txt')) as f:
            pkglist = f.read().splitlines()
        self.assertIn('oxideqt-codecs 1.6.6-0ubuntu0.14.04.1', pkglist)

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_get_source_tree_sandbox(self):
        self._setup_foonux_config()
        out_dir = os.path.join(self.workdir, 'out')
        os.mkdir(out_dir)
        impl._build_apt_sandbox(self.rootdir, os.path.join(self.configdir, 'Foonux 14.04', 'sources.list'),
                                'ubuntu', 'trusty', origins=None)
        res = impl.get_source_tree('base-files', out_dir, sandbox=self.rootdir,
                                   apt_update=True)
        self.assertTrue(os.path.isdir(os.path.join(res, 'debian')))
        # this needs to be updated when the release in _setup_foonux_config
        # changes
        self.assertTrue(res.endswith('/base-files-7.2ubuntu5'),
                        'unexpected version: ' + res.split('/')[-1])

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_get_source_tree_lp_sandbox(self):
        self._setup_foonux_config()
        out_dir = os.path.join(self.workdir, 'out')
        os.mkdir(out_dir)
        impl._build_apt_sandbox(self.rootdir, os.path.join(self.configdir, 'Foonux 14.04', 'sources.list'),
                                'ubuntu', 'trusty', origins=None)
        res = impl.get_source_tree('debian-installer', out_dir, version='20101020ubuntu318.16',
                                   sandbox=self.rootdir, apt_update=True)
        self.assertTrue(os.path.isdir(os.path.join(res, 'debian')))
        # this needs to be updated when the release in _setup_foonux_config
        # changes
        self.assertTrue(res.endswith('/debian-installer-20101020ubuntu318.16'),
                        'unexpected version: ' + res.split('/')[-1])

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_create_sources_for_a_named_ppa(self):
        '''Add sources.list entries for a named PPA.'''
        ppa = 'LP-PPA-daisy-pluckers-daisy-seeds'
        self._setup_foonux_config()
        impl._build_apt_sandbox(self.rootdir, os.path.join(self.configdir, 'Foonux 14.04', 'sources.list'),
                                'ubuntu', 'trusty', origins=[ppa])
        with open(os.path.join(self.rootdir, 'etc', 'apt', 'sources.list.d', ppa + '.list')) as f:
            sources = f.read().splitlines()
        self.assertIn('deb http://ppa.launchpad.net/daisy-pluckers/daisy-seeds/ubuntu trusty main main/debug', sources)
        self.assertIn('deb-src http://ppa.launchpad.net/daisy-pluckers/daisy-seeds/ubuntu trusty main', sources)

        d = subprocess.Popen(['gpg', '--no-options', '--no-default-keyring',
                              '--no-auto-check-trustdb', '--trust-model',
                              'always', '--batch', '--list-keys', '--keyring',
                              os.path.join(self.rootdir, 'etc', 'apt', 'trusted.gpg.d', 'LP-PPA-daisy-pluckers-daisy-seeds.gpg')],
                             stdout=subprocess.PIPE)
        apt_keys = d.communicate()[0].decode()
        assert d.returncode == 0
        self.assertIn('Launchpad PPA for Daisy Pluckers', apt_keys)

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_create_sources_for_an_unnamed_ppa(self):
        '''Add sources.list entries for an unnamed PPA.'''
        ppa = 'LP-PPA-apport-hackers-apport-autopkgtests'
        self._setup_foonux_config(release='focal', ppa=True)
        impl._build_apt_sandbox(self.rootdir, os.path.join(self.configdir, 'Foonux 20.04', 'sources.list'),
                                'ubuntu', 'focal', origins=[ppa])
        with open(os.path.join(self.rootdir, 'etc', 'apt', 'sources.list.d', ppa + '.list')) as f:
            sources = f.read().splitlines()
        self.assertIn('deb http://ppa.launchpad.net/apport-hackers/apport-autopkgtests/ubuntu focal main', sources)
        self.assertIn('deb-src http://ppa.launchpad.net/apport-hackers/apport-autopkgtests/ubuntu focal main', sources)

        d = subprocess.Popen(['gpg', '--no-options', '--no-default-keyring',
                              '--no-auto-check-trustdb', '--trust-model',
                              'always', '--batch', '--list-keys', '--keyring',
                              os.path.join(self.rootdir, 'etc', 'apt', 'trusted.gpg.d', 'LP-PPA-apport-hackers.gpg')],
                             stdout=subprocess.PIPE)
        apt_keys = d.communicate()[0].decode()
        assert d.returncode == 0
        self.assertIn('', apt_keys)

    def test_use_sources_for_a_ppa(self):
        '''Use a sources.list.d file for a PPA.'''
        ppa = 'fooser-bar-ppa'
        self._setup_foonux_config(ppa=True)
        impl._build_apt_sandbox(self.rootdir, os.path.join(self.configdir, 'Foonux 14.04', 'sources.list'),
                                'ubuntu', 'trusty', origins=['LP-PPA-%s' % ppa])
        with open(os.path.join(self.rootdir, 'etc', 'apt', 'sources.list.d', ppa + '.list')) as f:
            sources = f.read().splitlines()
        self.assertIn('deb http://ppa.launchpad.net/fooser/bar-ppa/ubuntu trusty main main/debug', sources)
        self.assertIn('deb-src http://ppa.launchpad.net/fooser/bar-ppa/ubuntu trusty main', sources)

    @unittest.skipUnless(_has_internet(), 'online test')
    def test_install_package_from_a_ppa(self):
        '''Install a package from a PPA.'''
        ppa = 'LP-PPA-apport-hackers-apport-autopkgtests'
        self._setup_foonux_config(release='focal')
        obsolete = impl.install_packages(self.rootdir, self.configdir, 'Foonux 20.04',
                                         [('apport',
                                           '2.20.11-0ubuntu27.14~ppa1')
                                         ], False, self.cachedir, origins=[ppa])

        self.assertEqual(obsolete, '')

        def sandbox_ver(pkg):
            with gzip.open(os.path.join(self.rootdir, 'usr/share/doc', pkg,
                                        'changelog.Debian.gz')) as f:
                return f.readline().decode().split()[1][1:-1]

        self.assertEqual(sandbox_ver('apport'),
                         '2.20.11-0ubuntu27.14~ppa1')

    def _setup_foonux_config(self, updates=False, release='trusty', ppa=False):
        '''Set up directories and configuration for install_packages()

           If ppa is True, then a sources.list file for a PPA will be created
           in sources.list.d used to test copying of a sources.list file to a
           sandbox.
        '''
        versions = {'trusty': '14.04',
                    'xenial': '16.04',
                    'boinic': '18.04',
                    'focal': '20.04'}
        vers = versions[release]
        self.cachedir = os.path.join(self.workdir, 'cache')
        self.rootdir = os.path.join(self.workdir, 'root')
        self.configdir = os.path.join(self.workdir, 'config')
        os.mkdir(self.cachedir)
        os.mkdir(self.rootdir)
        os.mkdir(self.configdir)
        os.mkdir(os.path.join(self.configdir, 'Foonux %s' % vers))
        with open(os.path.join(self.configdir, 'Foonux %s' % vers, 'sources.list'), 'w') as f:
            f.write('deb http://archive.ubuntu.com/ubuntu/ %s main\n' % release)
            f.write('deb-src http://archive.ubuntu.com/ubuntu/ %s main\n' % release)
            f.write('deb http://ddebs.ubuntu.com/ %s main\n' % release)
            if updates:
                f.write('deb http://archive.ubuntu.com/ubuntu/ %s-updates main\n' % release)
                f.write('deb-src http://archive.ubuntu.com/ubuntu/ %s-updates main\n' % release)
                f.write('deb http://ddebs.ubuntu.com/ %s-updates main\n' % release)
        if ppa:
            os.mkdir(os.path.join(self.configdir, 'Foonux %s' % vers, 'sources.list.d'))
            with open(os.path.join(self.configdir, 'Foonux %s' % vers, 'sources.list.d', 'fooser-bar-ppa.list'), 'w') as f:
                f.write('deb http://ppa.launchpad.net/fooser/bar-ppa/ubuntu %s main main/debug\n' % release)
                f.write('deb-src http://ppa.launchpad.net/fooser/bar-ppa/ubuntu %s main\n' % release)
        os.mkdir(os.path.join(self.configdir, 'Foonux %s' % vers, 'armhf'))
        with open(os.path.join(self.configdir, 'Foonux %s' % vers, 'armhf', 'sources.list'), 'w') as f:
            f.write('deb http://ports.ubuntu.com/ %s main\n' % release)
            f.write('deb-src http://ports.ubuntu.com/ %s main\n' % release)
            f.write('deb http://ddebs.ubuntu.com/ %s main\n' % release)
            if updates:
                f.write('deb http://ports.ubuntu.com/ %s-updates main\n' % release)
                f.write('deb-src http://ports.ubuntu.com/ %s-updates main\n' % release)
                f.write('deb http://ddebs.ubuntu.com/ %s-updates main\n' % release)
        with open(os.path.join(self.configdir, 'Foonux %s' % vers, 'codename'), 'w') as f:
            f.write('%s' % release)

        # install GPG key for ddebs
        keyring_dir = os.path.join(self.configdir, 'Foonux %s' % vers, 'trusted.gpg.d')
        os.makedirs(keyring_dir, exist_ok=True)
        shutil.copy('/usr/share/keyrings/ubuntu-archive-keyring.gpg', keyring_dir)
        subprocess.check_call(['/usr/lib/apt/apt-helper', 'download-file',
                               'http://ddebs.ubuntu.com/dbgsym-release-key.asc',
                               os.path.join(keyring_dir, 'ddebs.ubuntu.com.asc')],
                              stdout=subprocess.DEVNULL)
        # Create an architecture specific symlink, otherwise it cannot be
        # found for armhf in __AptDpkgPackageInfo._build_apt_sandbox() as
        # that looks for trusted.gpg.d relative to sources.list.
        keyring_arch_dir = os.path.join(self.configdir, 'Foonux %s' % vers, 'armhf', 'trusted.gpg.d')
        os.symlink("../trusted.gpg.d", keyring_arch_dir)

    def assert_elf_arch(self, path, expected):
        '''Assert that an ELF file is for an expected machine type.

        Expected is a Debian-style architecture (i386, amd64, armhf)
        '''
        archmap = {
            'i386': '80386',
            'amd64': 'X86-64',
            'armhf': 'ARM',
        }

        # get ELF machine type
        readelf = subprocess.Popen(['readelf', '-e', path], env={},
                                   stdout=subprocess.PIPE,
                                   universal_newlines=True)
        out = readelf.communicate()[0]
        assert readelf.returncode == 0
        for line in out.splitlines():
            if line.startswith('  Machine:'):
                machine = line.split(None, 1)[1]
                break
        else:
            self.fail('could not find Machine: in readelf output')

        self.assertTrue(archmap[expected] in machine,
                        '%s has unexpected machine type "%s" for architecture %s' % (
                            path, machine, expected))


# only execute if dpkg is available
try:
    if subprocess.call(['dpkg', '--help'], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE) == 0:
        unittest.main()
except OSError:
    pass
