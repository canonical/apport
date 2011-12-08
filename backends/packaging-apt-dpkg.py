'''apport.PackageInfo class implementation for python-apt and dpkg.

This is used on Debian and derivatives such as Ubuntu.
'''

# Copyright (C) 2007 - 2011 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import subprocess, os, glob, stat, sys, tempfile, glob, re, shutil, time
import hashlib

import warnings
warnings.filterwarnings('ignore', 'apt API not stable yet', FutureWarning)
import apt

import apport
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

    def _cache(self):
        '''Return apt.Cache() (initialized lazily).'''

        if not self._apt_cache:
            try:
                # avoid spewage on stdout
                self._apt_cache = apt.Cache(apt.progress.base.OpProgress())
            except AttributeError:
                # older python-apt versions do not yet have above argument
                self._apt_cache = apt.Cache()
        return self._apt_cache

    def _apt_pkg(self, package):
        '''Return apt.Cache()[package] (initialized lazily).
        
        Throw a ValueError if the package does not exist.
        '''
        try:
            return self._cache()[package]
        except KeyError:
            raise ValueError('package does not exist')

    def get_version(self, package):
        '''Return the installed version of a package.'''

        pkg = self._apt_pkg(package)
        inst = pkg.installed
        if not inst:
            raise ValueError('package does not exist')
        return inst.version

    def get_available_version(self, package):
        '''Return the latest available version of a package.'''

        return self._apt_pkg(package).candidate.version

    def get_dependencies(self, package):
        '''Return a list of packages a package depends on.'''

        cur_ver = self._apt_pkg(package)._pkg.current_ver
        if not cur_ver:
            # happens with virtual packages
            return []
        return [d[0].target_pkg.name for d in cur_ver.depends_list.get('Depends', []) +
            cur_ver.depends_list.get('PreDepends', [])]

    def get_source(self, package):
        '''Return the source package name for a package.'''

        if self._apt_pkg(package).installed:
            return self._apt_pkg(package).installed.source_name
        elif self._apt_pkg(package).candidate:
            return self._apt_pkg(package).candidate.source_name
        else:
            raise ValueError('package %s does not exist' % package)

    def is_distro_package(self, package):
        '''Check if a package is a genuine distro package (True) or comes from
        a third-party source.'''

        lsb_release = subprocess.Popen(['lsb_release', '-i', '-s'],
            stdout=subprocess.PIPE)
        this_os = lsb_release.communicate()[0].decode().strip()
        assert lsb_release.returncode == 0

        pkg = self._apt_pkg(package)
        # some PPA packages have installed version None, see LP#252734
        if pkg.installed and pkg.installed.version is None:
            return False

        native_origins = [this_os]
        for f in glob.glob('/etc/apport/native-origins.d/*'):
            try:
                with open(f) as fd:
                    for line in fd:
                        line = line.strip()
                        if line:
                            native_origins.append(line)
            except IOError:
                pass

        origins = None
        origins = pkg.candidate.origins
        if origins: # might be None
            for o in origins:
                if o.origin in native_origins:
                    return True
        return False

    def get_architecture(self, package):
        '''Return the architecture of a package.

        This might differ on multiarch architectures (e. g.  an i386 Firefox
        package on a x86_64 system)'''

        if self._apt_pkg(package).installed:
            return self._apt_pkg(package).installed.architecture or 'unknown'
        elif self._apt_pkg(package).candidate:
            return self._apt_pkg(package).candidate.architecture or 'unknown'
        else:
            raise ValueError('package %s does not exist' % package)

    def get_files(self, package):
        '''Return list of files shipped by a package.'''

        list = self._call_dpkg(['-L', package])
        if list is None:
            return None
        return [f for f in list.splitlines() if not f.startswith('diverted')]

    def get_modified_files(self, package):
        '''Return list of all modified files of a package.'''

        # get the maximum mtime of package files that we consider unmodified
        listfile = '/var/lib/dpkg/info/%s:%s.list' % (package, self.get_system_architecture())
        if not os.path.exists(listfile):
            listfile = '/var/lib/dpkg/info/%s.list' % package
        try:
            s = os.stat(listfile)
            if not stat.S_ISREG(s.st_mode):
                raise OSError
            max_time = max(s.st_mtime, s.st_ctime)
        except OSError:
            return []

        # create a list of files with a newer timestamp for md5sum'ing
        sums = ''
        sumfile = '/var/lib/dpkg/info/%s:%s.md5sums' % (package, self.get_system_architecture())
        if not os.path.exists(sumfile):
            sumfile = '/var/lib/dpkg/info/%s.md5sums' % package
            if not os.path.exists(sumfile):
                # some packages do not ship md5sums
                return []

        with open(sumfile) as fd:
            for line in fd:
                try:
                    # ignore lines with NUL bytes (happens, LP#96050)
                    if '\0' in line:
                        apport.warning('%s contains NUL character, ignoring line', sumfile)
                        continue
                    words  = line.split()
                    if not words:
                        apport.warning('%s contains empty line, ignoring line', sumfile)
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

    def get_modified_conffiles(self, package):
        '''Return modified configuration files of a package.

        Return a file name -> file contents map of all configuration files of
        package. Please note that apport.hookutils.attach_conffiles() is the
        official user-facing API for this, which will ask for confirmation and
        allows filtering.
        '''
        dpkg = subprocess.Popen(['dpkg-query','-W','--showformat=${Conffiles}',
            package], stdout=subprocess.PIPE, close_fds=True)

        out = dpkg.communicate()[0].decode()
        if dpkg.returncode != 0:
           return {}

        modified = {}
        for line in out.splitlines():
            if not line:
                continue
            # just take the first two fields, to not stumble over obsolete
            # conffiles
            path, default_md5sum = line.strip().split()[:2]

            if os.path.exists(path):
                with open(path, 'rb') as fd:
                    contents = fd.read()
                m = hashlib.md5()
                m.update(contents)
                calculated_md5sum = m.hexdigest()

                if calculated_md5sum != default_md5sum:
                    modified[path] = contents
            else:
                modified[path] = '[deleted]'

        return modified

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
            out = p.communicate()[0].decode('UTF-8')
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
        downloaded maps. If it is not set, a temporary directory will be used.
        '''
        # check if the file is a diversion
        dpkg = subprocess.Popen(['/usr/sbin/dpkg-divert', '--list', file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = dpkg.communicate()[0].decode('UTF-8')
        if dpkg.returncode == 0 and out:
            pkg = out.split()[-1]
            if pkg != 'hardening-wrapper':
                return pkg

        fname = os.path.splitext(os.path.basename(file))[0].lower()

        all_lists = []
        likely_lists = []
        for f in glob.glob('/var/lib/dpkg/info/*.list'):
            p = os.path.splitext(os.path.basename(f))[0].lower().split(':')[0]
            if p in fname or fname in p:
                likely_lists.append(f)
            else:
                all_lists.append(f)

        # first check the likely packages
        match = self.__fgrep_files(file, likely_lists)
        if not match:
            match = self.__fgrep_files(file, all_lists)

        if match:
            return os.path.splitext(os.path.basename(match))[0].split(':')[0]

        if uninstalled:
            return self._search_contents(file, map_cachedir)
        else:
            return None

    @classmethod
    def get_system_architecture(klass):
        '''Return the architecture of the system, in the notation used by the
        particular distribution.'''

        dpkg = subprocess.Popen(['dpkg', '--print-architecture'],
            stdout=subprocess.PIPE)
        arch = dpkg.communicate()[0].decode().strip()
        assert dpkg.returncode == 0
        assert arch
        return arch

    def get_library_paths(self):
        '''Return a list of default library search paths.
        
        The entries should be separated with a colon ':', like for
        $LD_LIBRARY_PATH. This needs to take any multiarch directories into
        account.
        '''
        dpkg = subprocess.Popen(['dpkg-architecture', '-qDEB_HOST_MULTIARCH'],
                stdout=subprocess.PIPE)
        multiarch_triple = dpkg.communicate()[0].decode().strip()
        assert dpkg.returncode == 0

        return '/lib/%s:/lib' % multiarch_triple

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
            subprocess.call('debian/rules patch || debian/rules apply-patches ' \
                '|| debian/rules apply-dpatches || '\
                'debian/rules unpack || debian/rules patch-stamp || ' \
                'debian/rules setup', shell=True, cwd=root,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            pass

        return root

    def get_kernel_package(self):
        '''Return the actual Linux kernel package name.

        This is used when the user reports a bug against the "linux" package.
        '''
        # TODO: Ubuntu specific
        return 'linux-image-' + os.uname()[2]

    def _install_debug_kernel(self, report):
        '''Install kernel debug package 

        Ideally this would be just another package but the kernel is
        special in various ways currently so we can not use the apt
        method.
        '''
        import urllib, apt_pkg
        installed = []
        outdated = []
        kver = report['Uname'].split()[1]
        arch = report['Architecture']
        ver = report['Package'].split()[1]
        debug_pkgname = 'linux-image-debug-%s' % kver
        c = self._cache()
        if debug_pkgname in c and c[debug_pkgname].isInstalled:
            #print('kernel ddeb already installed')
            return (installed, outdated)
        target_dir = apt_pkg.Config.FindDir('Dir::Cache::archives')+'/partial'
        deb = '%s_%s_%s.ddeb' % (debug_pkgname, ver, arch)
        # FIXME: this package is currently not in Packages.gz
        url = 'http://ddebs.ubuntu.com/pool/main/l/linux/%s' % deb
        out = open(os.path.join(target_dir, deb), 'w')
        # urlretrieve does not return 404 in the headers so we use urlopen
        u = urllib.urlopen(url)
        if u.getcode() > 400:
            return ('', 'linux')
        while True:
            block = u.read(8*1024)
            if not block:
                break
            out.write(block)
        out.flush()
        ret = subprocess.call(['dpkg', '-i', os.path.join(target_dir, deb)])
        if ret == 0:
            installed.append(deb.split('_')[0])
        return (installed, outdated)

    def install_packages(self, rootdir, configdir, release, packages,
            verbose=False, cache_dir=None):
        '''Install packages into a sandbox (for apport-retrace).

        In order to work without any special permissions and without touching
        the running system, this should only download and unpack packages into
        the given root directory, not install them into the system.

        configdir points to a directory with by-release configuration files for
        the packaging system; this is completely dependent on the backend
        implementation, the only assumption is that this looks into
        configdir/release/, so that you can use retracing for multiple
        DistroReleases. As a special case, if configdir is None, it uses the
        current system configuration, and "release" is ignored.

        release is the value of the report's 'DistroRelease' field.

        packages is a list of ('packagename', 'version') tuples. If the version
        is None, it should install the most current available version.
        
        If cache_dir is given, then the downloaded packages will be stored
        there, to speed up subsequent retraces.

        Return a string with outdated packages, or None if all packages were
        installed.

        If something is wrong with the environment (invalid configuration,
        package servers down, etc.), this should raise a SystemError with a
        meaningful error message.
        '''
        if not configdir:
            apt_sources = '/etc/apt/sources.list'
        else:
            apt_sources = os.path.join(configdir, release, 'sources.list')
        if not os.path.exists(apt_sources):
            raise SystemError('%s does not exist' % apt_sources)

        # create apt sandbox
        if cache_dir:
            tmp_aptroot = False
            if configdir:
                aptroot = os.path.join(cache_dir, release, 'apt')
            else:
                aptroot = os.path.join(cache_dir, 'system', 'apt')
            try:
                os.makedirs(aptroot)
            except OSError:
                pass
        else:
            tmp_aptroot = True
            aptroot = tempfile.mkdtemp()

        self._build_apt_sandbox(aptroot, apt_sources)

        if verbose:
            fetchProgress = apt.progress.text.AcquireProgress()
        else:
            fetchProgress = apt.progress.base.AcquireProgress()
        c = apt.Cache(rootdir=os.path.abspath(aptroot))
        try:
            c.update(fetchProgress)
        except apt.cache.FetchFailedException as e:
            raise SystemError(str(e))
        c.open()

        obsolete = ''

        # mark packages for installation
        real_pkgs = set()
        for (pkg, ver) in packages:
            try:
                candidate = c[pkg].candidate
            except KeyError:
                candidate = None
            if not candidate:
                m = 'package %s does not exist, ignoring' % pkg
                obsolete += m + '\n'
                apport.warning(m)
                continue

            if ver and candidate.version != ver:
                w = '%s version %s required, but %s is available' % (pkg, ver, candidate.version)
                obsolete += w + '\n'
            real_pkgs.add(pkg)

            if candidate.architecture != 'all':
                if pkg + '-dbg' in c:
                    real_pkgs.add(pkg + '-dbg')
                elif pkg + '-dbgsym' in c:
                    real_pkgs.add(pkg + '-dbgsym')
                    if c[pkg + '-dbgsym'].candidate.version != candidate.version:
                        obsolete += 'outdated debug symbol package for %s: package version %s dbgsym version %s\n' % (
                                pkg, candidate.version, c[pkg + '-dbgsym'].candidate.version)

        for p in real_pkgs:
            c[p].mark_install(False, False)

        # fetch packages
        fetcher = apt.apt_pkg.Acquire(fetchProgress)
        try:
            res = c.fetch_archives(fetcher=fetcher)
        except apt.cache.FetchFailedException as e:
            apport.error('Package download error, try again later: %s', str(e))
            sys.exit(99) # transient error

        # unpack packages
        if verbose:
            print('Extracting downloaded debs...')
        for i in fetcher.items:
            subprocess.check_call(['dpkg', '-x', i.destfile, rootdir])
            real_pkgs.remove(os.path.basename(i.destfile).split('_', 1)[0])

        if tmp_aptroot:
            shutil.rmtree(aptroot)

        # check bookkeeping that apt fetcher really got everything
        assert not real_pkgs, 'apt fetcher did not fetch these packages: ' \
            + ' '.join(real_pkgs)

        # work around python-apt bug that causes parts of the Cache(rootdir=)
        # argument configuration to be persistent; this resets the apt
        # configuration to system defaults again
        apt.Cache(rootdir='/')
        self._apt_cache = None

        return obsolete

    def package_name_glob(self, nameglob):
        '''Return known package names which match given glob.'''

        return glob.fnmatch.filter(self._cache().keys(), nameglob)

    #
    # Internal helper methods
    #

    def _call_dpkg(self, args):
        '''Call dpkg with given arguments and return output, or return None on
        error.'''

        dpkg = subprocess.Popen(['dpkg'] + args, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        out = dpkg.communicate(input)[0].decode('UTF-8')
        if dpkg.returncode == 0:
            return out
        else:
            raise ValueError('package does not exist')

    def _check_files_md5(self, sumfile):
        '''Internal function for calling md5sum.

        This is separate from get_modified_files so that it is automatically
        testable.'''

        if os.path.exists(sumfile):
            m = subprocess.Popen(['/usr/bin/md5sum', '-c', sumfile],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                cwd='/', env={})
            out = m.communicate()[0].decode()
        else:
            m = subprocess.Popen(['/usr/bin/md5sum', '-c'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, cwd='/', env={})
            out = m.communicate(sumfile.encode())[0].decode()

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
                if len(fields) >= 3 and fields[0] == 'deb' and fields[1].startswith('http://'):
                    self._mirror = fields[1]
                    break
            else:
                raise SystemError('cannot determine default mirror: /etc/apt/sources.list does not contain a valid deb line')

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

        # check if map exists and is younger than a day; if not, we need to
        # refresh it
        try:
            st = os.stat(map)
            age = int(time.time() - st.st_mtime)
        except OSError:
            age = None

        if age is None or age >= 86400:
            # determine distro release code name
            lsb_release = subprocess.Popen(['lsb_release', '-sc'],
                stdout=subprocess.PIPE)
            release_name = lsb_release.communicate()[0].decode('UTF-8').strip()
            assert lsb_release.returncode == 0

            url = '%s/dists/%s/Contents-%s.gz' % (self._get_mirror(), release_name, arch)
            try:
                from urllib.request import urlopen
            except ImportError:
                from urllib import urlopen

            src = urlopen(url)
            with open(map, 'wb') as f:
                while True:
                    data = src.read(1000000)
                    if not data:
                        break
                    f.write(data)
            src.close()
            assert os.path.exists(map)

        if file.startswith('/'):
            file = file[1:]

        # zgrep is magnitudes faster than a 'gzip.open/split() loop'
        package = None
        zgrep = subprocess.Popen(['zgrep', '-m1', '^%s[[:space:]]' % file, map],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = zgrep.communicate()[0].decode('UTF-8')
        # we do not check the return code, since zgrep -m1 often errors out
        # with 'stdout: broken pipe'
        if out:
            package = out.split()[1].split(',')[0].split('/')[-1]

        return package

    @classmethod
    def _build_apt_sandbox(klass, apt_root, apt_sources):
        # pre-create directories, to avoid apt.Cache() printing "creating..."
        # messages on stdout
        if not os.path.exists(os.path.join(apt_root, 'var', 'lib', 'apt')):
            os.makedirs(os.path.join(apt_root, 'var', 'lib', 'apt', 'lists', 'partial'))
            os.makedirs(os.path.join(apt_root, 'var', 'cache', 'apt', 'archives', 'partial'))
            os.makedirs(os.path.join(apt_root, 'var', 'lib', 'dpkg'))

        # install apt sources
        list_d = os.path.join(apt_root, 'etc', 'apt', 'sources.list.d')
        if os.path.exists(list_d):
            shutil.rmtree(list_d)
        if os.path.isdir(apt_sources + '.d'):
            shutil.copytree(apt_sources + '.d', list_d)
        else:
            os.makedirs(list_d)
        with open(apt_sources) as src:
            with open(os.path.join(apt_root, 'etc', 'apt', 'sources.list'), 'w') as dest:
                dest.write(src.read())

        # install apt keyrings; prefer the ones from the config dir, fall back
        # to system
        trusted_gpg = os.path.join(os.path.dirname(apt_sources), 'trusted.gpg')
        if os.path.exists(trusted_gpg):
            shutil.copy(trusted_gpg, os.path.join(apt_root, 'etc', 'apt'))
        elif os.path.exists('/etc/apt/trusted.gpg'):
            shutil.copy('/etc/apt/trusted.gpg', os.path.join(apt_root, 'etc', 'apt'))

        trusted_d = os.path.join(apt_root, 'etc', 'apt', 'trusted.gpg.d')
        if os.path.exists(trusted_d):
            shutil.rmtree(trusted_d)

        if os.path.exists(trusted_gpg + '.d'):
            shutil.copytree(trusted_gpg + '.d', trusted_d)
        elif os.path.exists('/etc/apt/trusted.gpg.d'):
            shutil.copytree('/etc/apt/trusted.gpg.d', trusted_d)
        else:
            os.makedirs(trusted_d)

    def compare_versions(self, ver1, ver2):
        '''Compare two package versions.

        Return -1 for ver < ver2, 0 for ver1 == ver2, and 1 for ver1 > ver2.'''

        return apt.apt_pkg.version_compare(ver1, ver2)

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
            with open(self.configuration) as f:
                conf = f.read()
        except IOError:
            # if the file does not exist, assume it's enabled
            return True

        return re.search('^\s*enabled\s*=\s*0\s*$', conf, re.M) is None

impl = __AptDpkgPackageInfo()

#
# Unit test
#

if __name__ == '__main__':
    import unittest, gzip

    def _has_default_route():
        '''Return if there is a default route.

        This is a reasonable indicator that online tests can be run.
        '''
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

    class _T(unittest.TestCase):

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
                with open(sumfile, 'w') as fd:
                    fd.write('''2e41290da2fa3f68bd3313174467e3b5  %s
f6423dfbc4faf022e58b4d3f5ff71a70  %s
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
            if self.has_dbgsym:
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
            self.assertEqual('coreutils-dbgsym' in cache_names, self.has_dbgsym)
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
            if self.has_dbgsym:
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
