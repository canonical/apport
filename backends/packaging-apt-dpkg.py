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

import subprocess, os, glob, stat, sys, tempfile, re, shutil, time
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
        self._sandbox_apt_cache = None
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

        self._sandbox_apt_cache = None
        if not self._apt_cache:
            try:
                # avoid spewage on stdout
                progress = apt.progress.base.OpProgress()
                self._apt_cache = apt.Cache(progress, rootdir='/')
            except AttributeError:
                # older python-apt versions do not yet have above argument
                self._apt_cache = apt.Cache(rootdir='/')
        return self._apt_cache

    def _sandbox_cache(self, aptroot, apt_sources, fetchProgress):
        '''Build apt sandbox and return apt.Cache(rootdir=) (initialized lazily).

        Clear the package selection on subsequent calls.
        '''
        self._apt_cache = None
        if not self._sandbox_apt_cache:
            self._build_apt_sandbox(aptroot, apt_sources)
            rootdir = os.path.abspath(aptroot)
            self._sandbox_apt_cache = apt.Cache(rootdir=rootdir)
            try:
                # We don't need to update this multiple times.
                self._sandbox_apt_cache.update(fetchProgress)
            except apt.cache.FetchFailedException as e:
                raise SystemError(str(e))
            self._sandbox_apt_cache.open()
        else:
            self._sandbox_apt_cache.clear()
        return self._sandbox_apt_cache

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

    def get_package_origin(self, package):
        '''Return package origin.

        Return the repository name from which a package was installed, or None
        if it cannot be determined.

        Throw ValueError if package is not installed.
        '''
        pkg = self._apt_pkg(package).installed
        if not pkg:
            raise ValueError('package is not installed')
        for origin in pkg.origins:
            if origin.origin:
                return origin.origin
        return None

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

        if pkg.candidate and pkg.candidate.origins:  # might be None
            for o in pkg.candidate.origins:
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
                    words = line.split()
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
        dpkg = subprocess.Popen(['dpkg-query', '-W', '--showformat=${Conffiles}',
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
                file_list[i:(i + slice_size)], stdin=subprocess.PIPE,
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
        target_dir = apt_pkg.Config.FindDir('Dir::Cache::archives') + '/partial'
        deb = '%s_%s_%s.ddeb' % (debug_pkgname, ver, arch)
        # FIXME: this package is currently not in Packages.gz
        url = 'http://ddebs.ubuntu.com/pool/main/l/linux/%s' % deb
        out = open(os.path.join(target_dir, deb), 'w')
        # urlretrieve does not return 404 in the headers so we use urlopen
        u = urllib.urlopen(url)
        if u.getcode() > 400:
            return ('', 'linux')
        while True:
            block = u.read(8 * 1024)
            if not block:
                break
            out.write(block)
        out.flush()
        ret = subprocess.call(['dpkg', '-i', os.path.join(target_dir, deb)])
        if ret == 0:
            installed.append(deb.split('_')[0])
        return (installed, outdated)

    def install_packages(self, rootdir, configdir, release, packages,
            verbose=False, cache_dir=None, permanent_rootdir=False):
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

        If permanent_rootdir is True, then the sandbox created from the
        downloaded packages will be reused, to speed up subsequent retraces.

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
            if not os.path.isdir(aptroot):
                os.makedirs(aptroot)
        else:
            tmp_aptroot = True
            aptroot = tempfile.mkdtemp()

        if verbose:
            fetchProgress = apt.progress.text.AcquireProgress()
        else:
            fetchProgress = apt.progress.base.AcquireProgress()
        if not tmp_aptroot:
            c = self._sandbox_cache(aptroot, apt_sources, fetchProgress)
        else:
            self._build_apt_sandbox(aptroot, apt_sources)
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

        last_written = time.time()
        # fetch packages
        fetcher = apt.apt_pkg.Acquire(fetchProgress)
        try:
            c.fetch_archives(fetcher=fetcher)
        except apt.cache.FetchFailedException as e:
            apport.error('Package download error, try again later: %s', str(e))
            sys.exit(99)  # transient error

        # unpack packages
        if verbose:
            print('Extracting downloaded debs...')
        for i in fetcher.items:
            if not permanent_rootdir or os.path.getctime(i.destfile) > last_written:
                subprocess.check_call(['dpkg', '-x', i.destfile, rootdir])
            real_pkgs.remove(os.path.basename(i.destfile).split('_', 1)[0])

        if tmp_aptroot:
            shutil.rmtree(aptroot)

        # check bookkeeping that apt fetcher really got everything
        assert not real_pkgs, 'apt fetcher did not fetch these packages: ' \
            + ' '.join(real_pkgs)

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
            out = m.communicate()[0].decode(errors='replace')
        else:
            m = subprocess.Popen(['/usr/bin/md5sum', '-c'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, cwd='/', env={})
            out = m.communicate(sumfile)[0].decode(errors='replace')

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
