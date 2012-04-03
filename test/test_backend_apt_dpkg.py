import unittest, gzip, imp, subprocess, tempfile, shutil, os, os.path, time

if os.environ.get('APPORT_TEST_LOCAL'):
    impl = imp.load_source('', 'backends/packaging-apt-dpkg.py').impl
else:
    from apport.packaging_impl import impl

def _has_default_route():
    '''Return if there is a default route.

    This is a reasonable indicator that online tests can be run.
    '''
    if os.environ.get('SKIP_ONLINE_TESTS'):
        return False
    if _has_default_route.cache is None:
        _has_default_route.cache = False
        route = subprocess.Popen(['/sbin/route', '-n'],
            stdout=subprocess.PIPE)
        for l in route.stdout:
            if l.decode('UTF-8').startswith('0.0.0.0 '):
                _has_default_route.cache = True
        route.wait()

    return _has_default_route.cache

_has_default_route.cache = None

class T(unittest.TestCase):
    def setUp(self):
        # save and restore configuration file
        self.orig_conf = impl.configuration
        self.workdir = tempfile.mkdtemp()

        try:
            impl.get_available_version('coreutils-dbgsym')
            self.has_dbgsym = True
        except ValueError:
            self.has_dbgsym = False

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
                fd.write('''2e41290da2fa3f68bd3313174467e3b5  %s
f6423dfbc4faf022e58b4d3f5ff71a70  %s
deadbeef000001111110000011110000  /bin/\xc3\xa4
''' % (f1[1:], f2))
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
            with open(sumfile) as fd:
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
        d  = impl.get_dependencies('bash')
        self.assertTrue(len(d) > 2)
        self.assertTrue('libc6' in d)
        for dep in d:
            self.assertTrue(impl.get_version(dep))

        # Pre-Depends: only
        d  = impl.get_dependencies('coreutils')
        self.assertTrue(len(d) >= 1)
        self.assertTrue('libc6' in d)
        for dep in d:
            self.assertTrue(impl.get_version(dep))

        # Depends: only
        d  = impl.get_dependencies('libc6')
        self.assertTrue(len(d) >= 1)
        for dep in d:
            self.assertTrue(impl.get_version(dep))

    def test_get_source(self):
        '''get_source().'''

        self.assertRaises(ValueError, impl.get_source, 'nonexisting')
        self.assertEqual(impl.get_source('bash'), 'bash')
        self.assertTrue('glibc' in impl.get_source('libc6'))

    def test_get_package_origin(self):
        '''get_package_origin().'''

        # determine distro name
        distro = subprocess.check_output(['lsb_release', '-si']).decode('UTF-8').strip()

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
        self.assertTrue('/bin/bash' in impl.get_files('bash'))

    def test_get_file_package(self):
        '''get_file_package() on installed files.'''

        self.assertEqual(impl.get_file_package('/bin/bash'), 'bash')
        self.assertEqual(impl.get_file_package('/bin/cat'), 'coreutils')
        self.assertEqual(impl.get_file_package('/etc/blkid.tab'), 'libblkid1')
        self.assertEqual(impl.get_file_package('/nonexisting'), None)

    def test_get_file_package_uninstalled(self):
        '''get_file_package() on uninstalled packages.'''

        # determine distro release code name
        lsb_release = subprocess.Popen(['lsb_release', '-sc'],
            stdout=subprocess.PIPE)
        release_name = lsb_release.communicate()[0].decode('UTF-8').strip()
        assert lsb_release.returncode == 0

        # generate a test Contents.gz
        basedir = tempfile.mkdtemp()
        try:
            mapdir = os.path.join(basedir, 'dists', release_name)
            os.makedirs(mapdir)
            with gzip.open(os.path.join(mapdir, 'Contents-%s.gz' %
                impl.get_system_architecture()), 'w') as f:
                f.write(b'''
foo header
FILE                                                    LOCATION
usr/bin/frobnicate                                      foo/frob
usr/bin/frob                                            foo/frob-utils
bo/gu/s                                                 na/mypackage
''')

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
            cache_file = os.listdir(cache_dir)[0]
            self.assertTrue(cache_file.startswith('Contents-'))
            self.assertEqual(impl.get_file_package('/bo/gu/s', True, cache_dir), 'mypackage')

            # valid cache, should not need to access the mirror
            impl.set_mirror('file:///foo/nonexisting')
            self.assertEqual(impl.get_file_package('/bo/gu/s', True, cache_dir), 'mypackage')

            # outdated cache, must refresh the cache and hit the invalid
            # mirror
            now = int(time.time())
            os.utime(os.path.join(cache_dir, cache_file), (now, now-90000))

            self.assertRaises(IOError, impl.get_file_package, '/bo/gu/s', True, cache_dir)
        finally:
            shutil.rmtree(basedir)

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
        self.assertTrue('\n' not in arch)

    def test_get_library_paths(self):
        '''get_library_paths().'''

        paths = impl.get_library_paths()
        # must be nonempty without line breaks
        self.assertNotEqual(paths, '')
        self.assertTrue(':' in paths)
        self.assertTrue('/lib' in paths)
        self.assertTrue('\n' not in paths)

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

    def test_get_kernel_pacakge(self):
        '''get_kernel_package().'''

        self.assertTrue('linux' in impl.get_kernel_package())

    def test_package_name_glob(self):
        '''package_name_glob().'''

        self.assertTrue(len(impl.package_name_glob('a*')) > 5)
        self.assertTrue('bash' in impl.package_name_glob('ba*h'))
        self.assertEqual(impl.package_name_glob('bash'), ['bash'])
        self.assertEqual(impl.package_name_glob('xzywef*'), [])

    @unittest.skipUnless(_has_default_route(), 'online test')
    def test_install_packages_versioned(self):
        '''install_packages() with versions and with cache'''

        self._setup_foonux_config()
        impl.install_packages(self.rootdir, self.configdir, 'Foonux 1.2',
                [('coreutils', '7.4-2ubuntu2'),
                 ('libc6', '2.11.1-0ubuntu7'),
                 ('tzdata', '2010i-1'),
                ], False, self.cachedir)

        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/bin/stat')))
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/lib/debug/usr/bin/stat')))
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/share/zoneinfo/zone.tab')))
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/share/doc/libc6/copyright')))

        # does not clobber config dir
        self.assertEqual(os.listdir(self.configdir), ['Foonux 1.2'])
        self.assertEqual(os.listdir(os.path.join(self.configdir, 'Foonux 1.2')),
                ['sources.list'])

        # caches packages
        cache = os.listdir(os.path.join(self.cachedir, 'Foonux 1.2', 'apt',
            'var', 'cache', 'apt', 'archives'))
        cache_names = [p.split('_')[0] for p in cache]
        self.assertTrue('coreutils' in cache_names)
        self.assertTrue('coreutils-dbgsym' in cache_names)
        self.assertTrue('tzdata' in cache_names)
        self.assertTrue('libc6' in cache_names)
        self.assertTrue('libc6-dbg' in cache_names)

        # installs cached packages
        os.unlink(os.path.join(self.rootdir, 'usr/bin/stat'))
        impl.install_packages(self.rootdir, self.configdir, 'Foonux 1.2',
                [('coreutils', '7.4-2ubuntu2'),
                ], False, self.cachedir)
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/bin/stat')))

        # complains about obsolete packages
        result = impl.install_packages(self.rootdir, self.configdir,
                'Foonux 1.2', [('gnome-common', '1.1')])
        self.assertEqual(len(result.splitlines()), 1)
        self.assertTrue('gnome-common' in result)
        self.assertTrue('1.1' in result)
        # ... but installs the current version anyway
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/bin/gnome-autogen.sh')))

        # does not crash on nonexisting packages
        result = impl.install_packages(self.rootdir, self.configdir,
                'Foonux 1.2', [('buggerbogger', None)])
        self.assertEqual(len(result.splitlines()), 1)
        self.assertTrue('buggerbogger' in result)
        self.assertTrue('not exist' in result)

        # can interleave with other operations
        dpkg = subprocess.Popen(['dpkg-query', '-Wf${Version}', 'dash'],
                stdout=subprocess.PIPE)
        coreutils_version = dpkg.communicate()[0].decode()
        self.assertEqual(dpkg.returncode, 0)

        self.assertEqual(impl.get_version('dash'), coreutils_version)
        self.assertRaises(ValueError, impl.get_available_version, 'buggerbogger')

        # still installs packages after above operations
        os.unlink(os.path.join(self.rootdir, 'usr/bin/stat'))
        impl.install_packages(self.rootdir, self.configdir, 'Foonux 1.2',
                [('coreutils', '7.4-2ubuntu2'),
                 ('dpkg', None),
                ], False, self.cachedir)
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/bin/stat')))
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/bin/dpkg')))

    @unittest.skipUnless(_has_default_route(), 'online test')
    def test_install_packages_unversioned(self):
        '''install_packages() without versions and no cache'''

        self._setup_foonux_config()
        impl.install_packages(self.rootdir, self.configdir, 'Foonux 1.2',
                [('coreutils', None),
                 ('tzdata', None),
                ], False, None)

        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/bin/stat')))
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/lib/debug/usr/bin/stat')))
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/share/zoneinfo/zone.tab')))

        # does not clobber config dir
        self.assertEqual(os.listdir(self.configdir), ['Foonux 1.2'])
        self.assertEqual(os.listdir(os.path.join(self.configdir, 'Foonux 1.2')),
                ['sources.list'])

        # no cache
        self.assertEqual(os.listdir(self.cachedir), [])

    @unittest.skipUnless(_has_default_route(), 'online test')
    def test_install_packages_system(self):
        '''install_packages() with system configuration'''

        # trigger an unrelated package query here to get the cache set up,
        # reproducing an install failure when the internal caches are not
        # reset properly
        impl.get_version('dash')

        self._setup_foonux_config()
        result = impl.install_packages(self.rootdir, None, None,
                [('coreutils', impl.get_version('coreutils')),
                 ('tzdata', '1.1'),
                ], False, self.cachedir)

        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/bin/stat')))
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/share/zoneinfo/zone.tab')))

        # complains about obsolete packages
        self.assertEqual(len(result.splitlines()), 1)
        self.assertTrue('tzdata' in result)
        self.assertTrue('1.1' in result)

        # caches packages
        cache = os.listdir(os.path.join(self.cachedir, 'system', 'apt',
            'var', 'cache', 'apt', 'archives'))
        cache_names = [p.split('_')[0] for p in cache]
        self.assertTrue('coreutils' in cache_names)
        self.assertEqual('coreutils-dbgsym' in cache_names, self.has_dbgsym)
        self.assertTrue('tzdata' in cache_names)

        # works with relative paths and existing cache
        os.unlink(os.path.join(self.rootdir, 'usr/bin/stat'))
        orig_cwd = os.getcwd()
        try:
            os.chdir(self.workdir)
            impl.install_packages('root', None, None,
                    [('coreutils', None)], False, 'cache')
        finally:
            os.chdir(orig_cwd)
        self.assertTrue(os.path.exists(os.path.join(self.rootdir,
            'usr/bin/stat')))

    @unittest.skipUnless(_has_default_route(), 'online test')
    def test_install_packages_error(self):
        '''install_packages() with errors'''

        # sources.list with invalid format
        self._setup_foonux_config()
        with open(os.path.join(self.configdir, 'Foonux 1.2', 'sources.list'), 'w') as f:
            f.write('bogus format')

        try:
            impl.install_packages(self.rootdir, self.configdir, 'Foonux 1.2',
                    [('tzdata', None)], False, self.cachedir)
            self.fail('install_packages() unexpectedly succeeded with broken sources.list')
        except SystemError as e:
            self.assertTrue('bogus' in str(e))
            self.assertFalse('Exception' in str(e))

        # sources.list with wrong server
        with open(os.path.join(self.configdir, 'Foonux 1.2', 'sources.list'), 'w') as f:
            f.write('deb http://archive.ubuntu.com/nosuchdistro/ lucid main\n')

        try:
            impl.install_packages(self.rootdir, self.configdir, 'Foonux 1.2',
                    [('tzdata', None)], False, self.cachedir)
            self.fail('install_packages() unexpectedly succeeded with broken server URL')
        except SystemError as e:
            self.assertTrue('nosuchdistro' in str(e), str(e))
            self.assertTrue('index files failed to download' in str(e))

    def _setup_foonux_config(self):
        '''Set up directories and configuration for install_packages()'''

        self.cachedir = os.path.join(self.workdir, 'cache')
        self.rootdir = os.path.join(self.workdir, 'root')
        self.configdir = os.path.join(self.workdir, 'config')
        os.mkdir(self.cachedir)
        os.mkdir(self.rootdir)
        os.mkdir(self.configdir)
        os.mkdir(os.path.join(self.configdir, 'Foonux 1.2'))
        with open(os.path.join(self.configdir, 'Foonux 1.2', 'sources.list'), 'w') as f:
            f.write('deb http://archive.ubuntu.com/ubuntu/ lucid main\n')
            f.write('deb http://ddebs.ubuntu.com/ lucid main\n')

# only execute if dpkg is available
try:
    if subprocess.call(['dpkg', '--help'], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE) == 0:
        unittest.main()
except OSError:
    pass
