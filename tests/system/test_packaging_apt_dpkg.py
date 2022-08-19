import glob
import gzip
import os
import shutil
import subprocess
import tempfile
import unittest

from apt import apt_pkg

from apport.packaging_impl.apt_dpkg import impl
from tests.helper import has_internet


@unittest.skipIf(shutil.which("dpkg") is None, "dpkg not available")
class T(unittest.TestCase):
    # pylint: disable=protected-access

    def setUp(self):
        # save and restore configuration file
        self.orig_conf = impl.configuration
        self.orig_environ = os.environ.copy()
        self.workdir = tempfile.mkdtemp()
        os.environ["HOME"] = self.workdir
        self.cachedir = os.path.join(self.workdir, "cache")
        self.rootdir = os.path.join(self.workdir, "root")
        self.configdir = os.path.join(self.workdir, "config")
        # reset internal caches between tests
        impl._apt_cache = None
        impl._sandbox_apt_cache = None

    def tearDown(self):
        impl.configuration = self.orig_conf
        os.environ.clear()
        os.environ.update(self.orig_environ)
        shutil.rmtree(self.workdir)

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_packages_versioned(self):
        """install_packages() with versions and with cache"""
        release = self._setup_foonux_config(updates=True)
        wanted = {
            "coreutils": "8.32-4.1ubuntu1",
            "libc6": "2.35-0ubuntu3",
            "libcurl4": "7.81.0-1",  # should not come from -updates
            "tzdata": None,  # should come from -updates, > 2022a
        }
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            list(wanted.items()),
            False,
            self.cachedir,
        )

        def sandbox_ver(pkg):
            with gzip.open(
                os.path.join(
                    self.rootdir, "usr/share/doc", pkg, "changelog.Debian.gz"
                )
            ) as f:
                return f.readline().decode().split()[1][1:-1]

        self.assertEqual(obsolete, "")

        # packages get installed
        self.assertTrue(
            os.path.exists(os.path.join(self.rootdir, "usr/bin/stat"))
        )
        self.assert_elf_arch(
            os.path.join(self.rootdir, "usr/bin/stat"),
            impl.get_system_architecture(),
        )
        self.assertTrue(
            os.path.exists(
                os.path.join(self.rootdir, "usr/lib/debug/.build-id")
            )
        )
        self.assertTrue(
            os.path.exists(
                os.path.join(self.rootdir, "usr/share/zoneinfo/zone.tab")
            )
        )
        for library in ("libc6", "libcurl4"):
            copyright_filename = f"usr/share/doc/{library}/copyright"
            self.assertTrue(
                os.path.exists(os.path.join(self.rootdir, copyright_filename))
            )

        # their versions are as expected
        self.assertEqual(sandbox_ver("coreutils"), wanted["coreutils"])
        self.assertEqual(sandbox_ver("libc6"), wanted["libc6"])
        self.assertEqual(sandbox_ver("libc6-dbg"), wanted["libc6"])
        self.assertEqual(sandbox_ver("libcurl4"), wanted["libcurl4"])
        self.assertGreater(sandbox_ver("tzdata"), "2022a")

        with open(
            os.path.join(self.rootdir, "packages.txt"), encoding="utf-8"
        ) as f:
            pkglist = f.read().splitlines()
        self.assertIn(f"coreutils {wanted['coreutils']}", pkglist)
        self.assertIn(f"coreutils-dbgsym {wanted['coreutils']}", pkglist)
        self.assertIn(f"libc6 {wanted['libc6']}", pkglist)
        self.assertIn(f"libc6-dbg {wanted['libc6']}", pkglist)
        self.assertIn(f"libcurl4 {wanted['libcurl4']}", pkglist)
        self.assertIn(f"libcurl4-dbgsym {wanted['libcurl4']}", pkglist)
        self.assertIn("tzdata " + sandbox_ver("tzdata"), pkglist)
        self.assertEqual(len(pkglist), 7, str(pkglist))

        # does not clobber config dir
        self.assertEqual(os.listdir(self.configdir), [release])
        self.assertEqual(
            sorted(os.listdir(os.path.join(self.configdir, release))),
            ["armhf", "codename", "sources.list", "trusted.gpg.d"],
        )
        self.assertEqual(
            sorted(os.listdir(os.path.join(self.configdir, release, "armhf"))),
            ["sources.list", "trusted.gpg.d"],
        )

        # caches packages, and their versions are as expected
        cache = os.listdir(
            os.path.join(
                self.cachedir,
                release,
                "apt",
                "var",
                "cache",
                "apt",
                "archives",
            )
        )
        cache_versions = {}
        for p in cache:
            try:
                (name, ver) = p.split("_")[:2]
                cache_versions[name] = ver
            except ValueError:
                pass  # not a .deb, ignore
        self.assertEqual(cache_versions["coreutils"], wanted["coreutils"])
        self.assertEqual(
            cache_versions["coreutils-dbgsym"], wanted["coreutils"]
        )
        self.assertEqual(cache_versions["libc6"], wanted["libc6"])
        self.assertEqual(cache_versions["libc6-dbg"], wanted["libc6"])
        self.assertEqual(cache_versions["libcurl4"], wanted["libcurl4"])
        self.assertIn("tzdata", cache_versions)

        # installs cached packages
        os.unlink(os.path.join(self.rootdir, "usr/bin/stat"))
        os.unlink(os.path.join(self.rootdir, "packages.txt"))
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [("coreutils", wanted["coreutils"])],
            False,
            self.cachedir,
        )
        self.assertEqual(obsolete, "")
        self.assertTrue(
            os.path.exists(os.path.join(self.rootdir, "usr/bin/stat"))
        )

        # complains about obsolete packages
        result = impl.install_packages(
            self.rootdir, self.configdir, release, [("aspell-doc", "1.1")]
        )
        self.assertIn(
            "aspell-doc version 1.1 required, but 0.60.8-4build1", result
        )
        # ... but installs the current version anyway
        self.assertTrue(
            os.path.exists(
                os.path.join(self.rootdir, "usr/share/info/aspell.info.gz")
            )
        )
        self.assertGreaterEqual(sandbox_ver("aspell-doc"), "0.60.8")

        # does not crash on nonexisting packages
        result = impl.install_packages(
            self.rootdir, self.configdir, release, [("buggerbogger", None)]
        )
        self.assertEqual(len(result.splitlines()), 1)
        self.assertIn("buggerbogger", result)
        self.assertIn("not exist", result)

        # can interleave with other operations
        dpkg = subprocess.run(
            ["dpkg-query", "-Wf${Version}", "dash"],
            check=True,
            stdout=subprocess.PIPE,
        )
        dash_version = dpkg.stdout.decode()

        self.assertEqual(impl.get_version("dash"), dash_version)
        self.assertRaises(
            ValueError, impl.get_available_version, "buggerbogger"
        )

        # still installs packages after above operations
        os.unlink(os.path.join(self.rootdir, "usr/bin/stat"))
        os.unlink(os.path.join(self.rootdir, "packages.txt"))
        impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [("coreutils", wanted["coreutils"]), ("dpkg", None)],
            False,
            self.cachedir,
        )
        self.assertTrue(
            os.path.exists(os.path.join(self.rootdir, "usr/bin/stat"))
        )
        self.assertTrue(
            os.path.exists(os.path.join(self.rootdir, "usr/bin/dpkg"))
        )

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_packages_unversioned(self):
        """install_packages() without versions and no cache"""
        release = self._setup_foonux_config()
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [("coreutils", None), ("tzdata", None)],
            False,
            None,
        )

        self.assertEqual(obsolete, "")
        self.assertTrue(
            os.path.exists(os.path.join(self.rootdir, "usr/bin/stat"))
        )
        self.assert_elf_arch(
            os.path.join(self.rootdir, "usr/bin/stat"),
            impl.get_system_architecture(),
        )
        self.assertTrue(
            os.path.exists(
                os.path.join(self.rootdir, "usr/lib/debug/.build-id")
            )
        )
        self.assertTrue(
            os.path.exists(
                os.path.join(self.rootdir, "usr/share/zoneinfo/zone.tab")
            )
        )

        # does not clobber config dir
        self.assertEqual(os.listdir(self.configdir), [release])
        self.assertEqual(
            sorted(os.listdir(os.path.join(self.configdir, release))),
            ["armhf", "codename", "sources.list", "trusted.gpg.d"],
        )
        self.assertEqual(
            sorted(os.listdir(os.path.join(self.configdir, release, "armhf"))),
            ["sources.list", "trusted.gpg.d"],
        )

        # no cache
        self.assertEqual(os.listdir(self.cachedir), [])

        # keeps track of package versions
        with open(
            os.path.join(self.rootdir, "packages.txt"), encoding="utf-8"
        ) as f:
            pkglist = f.read().splitlines()
        self.assertIn("coreutils 8.32-4.1ubuntu1", pkglist)
        self.assertIn("coreutils-dbgsym 8.32-4.1ubuntu1", pkglist)
        self.assertIn("tzdata 2022a-0ubuntu1", pkglist)
        self.assertEqual(len(pkglist), 3, str(pkglist))

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_packages_dependencies(self):
        """install packages's dependencies"""
        release = self._setup_foonux_config()
        # coreutils should always depend on libc6
        result = impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [("coreutils", None)],
            False,
            None,
            install_deps=True,
        )

        # check packages.txt for a dependency
        with open(
            os.path.join(self.rootdir, "packages.txt"), encoding="utf-8"
        ) as f:
            pkglist = f.read().splitlines()
        self.assertIn("coreutils 8.32-4.1ubuntu1", pkglist)
        self.assertIn("libc6 2.35-0ubuntu3", pkglist)

        # ensure obsolete packages doesn't include libc6
        self.assertNotIn("libc6", result)

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_packages_system(self):
        """install_packages() with system configuration"""
        # trigger an unrelated package query here to get the cache set up,
        # reproducing an install failure when the internal caches are not
        # reset properly
        impl.get_version("dash")

        release = " ".join(impl.get_os_version())
        cachedir = os.path.join(self.workdir, "cache")
        rootdir = os.path.join(self.workdir, "root")

        result = impl.install_packages(
            rootdir,
            None,
            release,
            [("coreutils", impl.get_version("coreutils")), ("tzdata", "1.1")],
            False,
            cachedir,
        )

        self.assertTrue(os.path.exists(os.path.join(rootdir, "usr/bin/stat")))
        self.assertTrue(
            os.path.exists(
                os.path.join(rootdir, "usr/share/zoneinfo/zone.tab")
            )
        )

        # complains about obsolete packages
        self.assertGreaterEqual(len(result.splitlines()), 1)
        self.assertIn("tzdata", result)
        self.assertIn("1.1", result)

        # caches packages
        cache = os.listdir(
            os.path.join(
                cachedir, "system", "apt", "var", "cache", "apt", "archives"
            )
        )
        cache_names = [p.split("_")[0] for p in cache]
        self.assertIn("coreutils", cache_names)
        self.assertIn("coreutils-dbgsym", cache_names)
        self.assertIn("tzdata", cache_names)

        # works with relative paths and existing cache
        os.unlink(os.path.join(rootdir, "usr/bin/stat"))
        os.unlink(os.path.join(rootdir, "packages.txt"))
        orig_cwd = os.getcwd()
        try:
            os.chdir(self.workdir)
            impl.install_packages(
                "root", None, None, [("coreutils", None)], False, "cache"
            )
        finally:
            os.chdir(orig_cwd)
            self.assertTrue(
                os.path.exists(os.path.join(rootdir, "usr/bin/stat"))
            )

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_packages_error(self):
        """install_packages() with errors"""
        # sources.list with invalid format
        release = self._setup_foonux_config()
        with open(
            os.path.join(self.configdir, release, "sources.list"),
            "w",
            encoding="utf-8",
        ) as f:
            f.write("bogus format")

        try:
            impl.install_packages(
                self.rootdir,
                self.configdir,
                release,
                [("tzdata", None)],
                False,
                self.cachedir,
            )
            self.fail(
                "install_packages() unexpectedly succeeded"
                " with broken sources.list"
            )
        except SystemError as error:
            self.assertIn("bogus", str(error))
            self.assertNotIn("Exception", str(error))

        # sources.list with wrong server
        with open(
            os.path.join(self.configdir, release, "sources.list"),
            "w",
            encoding="utf-8",
        ) as f:
            f.write("deb http://archive.ubuntu.com/nosuchdistro/ jammy main\n")

        try:
            impl.install_packages(
                self.rootdir,
                self.configdir,
                release,
                [("tzdata", None)],
                False,
                self.cachedir,
            )
            self.fail(
                "install_packages() unexpectedly succeeded"
                " with broken server URL"
            )
        except SystemError as error:
            self.assertIn("nosuchdistro", str(error))
            try:
                self.assertRegex(
                    str(error),
                    ".*'http://archive.ubuntu.com/nosuchdistro jammy.*'"
                    " does not have a Release file",
                )
            except AssertionError:
                self.assertIn("index files failed to download", str(error))

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_packages_permanent_sandbox(self):
        """install_packages() with a permanent sandbox"""
        release = self._setup_foonux_config()
        zonetab = os.path.join(self.rootdir, "usr/share/zoneinfo/zone.tab")

        impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [("tzdata", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )

        # This will now be using a Cache with our rootdir.
        archives = apt_pkg.config.find_dir("Dir::Cache::archives")
        tzdata = glob.glob(os.path.join(archives, "tzdata*.deb"))
        if not tzdata:
            self.fail("tzdata was not downloaded")
        tzdata_written = os.path.getctime(tzdata[0])
        zonetab_written = os.path.getctime(zonetab)

        impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [("coreutils", None), ("tzdata", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )

        if not glob.glob(os.path.join(archives, "coreutils*.deb")):
            self.fail("coreutils was not downloaded.")
            self.assertEqual(
                os.path.getctime(tzdata[0]),
                tzdata_written,
                "tzdata downloaded twice.",
            )
            self.assertEqual(
                zonetab_written,
                os.path.getctime(zonetab),
                "zonetab written twice.",
            )
            self.assertTrue(
                os.path.exists(os.path.join(self.rootdir, "usr/bin/stat"))
            )

        # Prevent packages from downloading.
        orig_apt_proxy = apt_pkg.config.get("Acquire::http::Proxy")
        apt_pkg.config.set("Acquire::http::Proxy", "http://nonexistent")
        orig_http_proxy = os.environ.get("http_proxy")
        os.environ["http_proxy"] = "http://nonexistent"
        try:
            orig_no_proxy = os.environ["no_proxy"]
            del os.environ["no_proxy"]
        except KeyError:
            orig_no_proxy = None

        self.assertRaises(
            SystemExit,
            impl.install_packages,
            self.rootdir,
            self.configdir,
            release,
            [("libc6", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )

        # These packages exist, so attempting to install them should not fail.
        impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [("coreutils", None), ("tzdata", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )
        # even without cached debs, trying to install the same versions should
        # be a no-op and succeed
        for f in glob.glob(
            f"{self.cachedir}/{release}/apt/var/cache/apt/archives/coreutils*"
        ):
            os.unlink(f)
        impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [("coreutils", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )

        # trying to install another package should fail, though
        self.assertRaises(
            SystemExit,
            impl.install_packages,
            self.rootdir,
            self.configdir,
            release,
            [("aspell-doc", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )

        # restore original proxy settings
        if orig_http_proxy:
            os.environ["http_proxy"] = orig_http_proxy
        else:
            del os.environ["http_proxy"]
        if orig_no_proxy:
            os.environ["no_proxy"] = orig_no_proxy
        apt_pkg.config.set("Acquire::http::Proxy", orig_apt_proxy)

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_packages_permanent_sandbox_repack(self):
        # Both packages needs to conflict with each other, because they
        # ship the same file.
        release = self._setup_foonux_config()
        impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [("libcurl4-gnutls-dev", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )
        curl_library = self._get_library_path("libcurl.so", self.rootdir)
        self.assertEqual("libcurl-gnutls.so", os.readlink(curl_library))

        impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [("libcurl4-nss-dev", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )
        self.assertEqual("libcurl-nss.so", os.readlink(curl_library))

        impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [("libcurl4-gnutls-dev", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )
        self.assertEqual("libcurl-gnutls.so", os.readlink(curl_library))

    @unittest.skipUnless(has_internet(), "online test")
    @unittest.skipIf(
        impl.get_system_architecture() == "armhf", "native armhf architecture"
    )
    def test_install_packages_armhf(self):
        """install_packages() for foreign architecture armhf"""
        release = self._setup_foonux_config()
        wanted_version = "2.35-0ubuntu0"
        got_version = "2.35-0ubuntu3"
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [("coreutils", None), ("libc6", wanted_version)],
            False,
            self.cachedir,
            architecture="armhf",
        )

        self.assertEqual(
            obsolete,
            f"libc6 version {wanted_version} required,"
            f" but {got_version} is available\n",
        )

        self.assertTrue(
            os.path.exists(os.path.join(self.rootdir, "usr/bin/stat"))
        )
        self.assert_elf_arch(
            os.path.join(self.rootdir, "usr/bin/stat"), "armhf"
        )
        self.assertTrue(
            os.path.exists(
                os.path.join(self.rootdir, "usr/share/doc/libc6/copyright")
            )
        )
        # caches packages
        cache = os.listdir(
            os.path.join(
                self.cachedir,
                release,
                "armhf",
                "apt",
                "var",
                "cache",
                "apt",
                "archives",
            )
        )
        self.assertIn("coreutils_8.32-4.1ubuntu1_armhf.deb", cache)
        self.assertIn(f"libc6_{got_version}_armhf.deb", cache)

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_packages_from_launchpad(self):
        """install_packages() using packages only available on Launchpad"""
        release = self._setup_foonux_config(release="focal")
        # Wanted are superseded versions from -updates or -security.
        wanted = {
            "distro-info-data": "0.43ubuntu1.9",  # arch all
            "libc6": "2.31-0ubuntu9.4",  # -dbg, arch specfic
            "qemu-utils": "1:4.2-3ubuntu6.1",  # -dbgsym, arch specific
        }
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            list(wanted.items()),
            False,
            self.cachedir,
        )

        def sandbox_ver(pkg, debian=True):
            if debian:
                changelog = "changelog.Debian.gz"
            else:
                changelog = "changelog.gz"
            with gzip.open(
                os.path.join(self.rootdir, "usr/share/doc", pkg, changelog)
            ) as f:
                return f.readline().decode().split()[1][1:-1]

        self.assertEqual(obsolete, "")

        # packages get installed
        self.assertTrue(
            os.path.exists(
                os.path.join(self.rootdir, "usr/share/distro-info/ubuntu.csv")
            )
        )
        self.assertTrue(
            os.path.exists(
                os.path.join(self.rootdir, "usr/lib/debug/.build-id")
            )
        )
        self.assertTrue(
            os.path.exists(os.path.join(self.rootdir, "usr/bin/qemu-img"))
        )

        # their versions are as expected
        self.assertEqual(
            sandbox_ver("distro-info-data", debian=False),
            wanted["distro-info-data"],
        )
        self.assertEqual(sandbox_ver("libc6"), wanted["libc6"])
        self.assertEqual(sandbox_ver("libc6-dbg"), wanted["libc6"])

        # keeps track of package versions
        with open(
            os.path.join(self.rootdir, "packages.txt"), encoding="utf-8"
        ) as f:
            pkglist = f.read().splitlines()
        self.assertIn(
            f"distro-info-data {wanted['distro-info-data']}", pkglist
        )
        self.assertIn(f"libc6 {wanted['libc6']}", pkglist)
        self.assertIn(f"libc6-dbg {wanted['libc6']}", pkglist)
        self.assertIn(f"qemu-utils {wanted['qemu-utils']}", pkglist)
        self.assertIn(f"qemu-utils-dbgsym {wanted['qemu-utils']}", pkglist)

        # caches packages, and their versions are as expected
        cache = os.listdir(
            os.path.join(
                self.cachedir,
                release,
                "apt",
                "var",
                "cache",
                "apt",
                "archives",
            )
        )

        # archive and launchpad versions of packages exist in the cache,
        # so use a list
        cache_versions = []
        for p in cache:
            try:
                (name, ver) = p.split("_")[:2]
                cache_versions.append((name, ver))
            except ValueError:
                pass  # not a .deb, ignore
        self.assertIn(
            ("distro-info-data", wanted["distro-info-data"]), cache_versions
        )
        self.assertIn(("libc6-dbg", wanted["libc6"]), cache_versions)
        self.assertIn(
            ("qemu-utils-dbgsym", self._strip_epoch(wanted["qemu-utils"])),
            cache_versions,
        )

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_old_packages(self):
        """sandbox will install older package versions from launchpad"""
        release = self._setup_foonux_config()
        wanted_package = "libcurl4"
        wanted_version = "7.81.0-1"  # pre-release version
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [(wanted_package, wanted_version)],
            False,
            self.cachedir,
        )

        self.assertEqual(obsolete, "")

        def sandbox_ver(pkg):
            with gzip.open(
                os.path.join(
                    self.rootdir, "usr/share/doc", pkg, "changelog.Debian.gz"
                )
            ) as f:
                return f.readline().decode().split()[1][1:-1]

        # the version is as expected
        self.assertEqual(sandbox_ver(wanted_package), wanted_version)

        # keeps track of package version
        with open(
            os.path.join(self.rootdir, "packages.txt"), encoding="utf-8"
        ) as f:
            pkglist = f.read().splitlines()
        self.assertIn(f"{wanted_package} {wanted_version}", pkglist)

        wanted_version = "7.74.0-1.3ubuntu3"
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [(wanted_package, wanted_version)],
            False,
            self.cachedir,
        )

        self.assertEqual(obsolete, "")

        # the old version is installed
        self.assertEqual(sandbox_ver(wanted_package), wanted_version)

        # the old versions is tracked
        with open(
            os.path.join(self.rootdir, "packages.txt"), encoding="utf-8"
        ) as f:
            pkglist = f.read().splitlines()
        self.assertIn(f"{wanted_package} {wanted_version}", pkglist)

    @unittest.skipUnless(has_internet(), "online test")
    def test_get_source_tree_sandbox(self):
        release = self._setup_foonux_config()
        out_dir = os.path.join(self.workdir, "out")
        os.mkdir(out_dir)
        impl._build_apt_sandbox(
            self.rootdir,
            os.path.join(self.configdir, release, "sources.list"),
            "ubuntu",
            "jammy",
            origins=None,
        )
        res = impl.get_source_tree("base-files", out_dir, sandbox=self.rootdir)
        self.assertTrue(os.path.isdir(os.path.join(res, "debian")))
        # this needs to be updated when the release in _setup_foonux_config
        # changes
        self.assertTrue(
            res.endswith("/base-files-12ubuntu4"),
            "unexpected version: " + res.split("/")[-1],
        )

    @unittest.skipUnless(has_internet(), "online test")
    def test_get_source_tree_lp_sandbox(self):
        release = self._setup_foonux_config()
        wanted_package = "curl"
        wanted_version = "7.81.0-1ubuntu1.2"  # superseded -security version
        out_dir = os.path.join(self.workdir, "out")
        os.mkdir(out_dir)
        impl._build_apt_sandbox(
            self.rootdir,
            os.path.join(self.configdir, release, "sources.list"),
            "ubuntu",
            "jammy",
            origins=None,
        )
        res = impl.get_source_tree(
            wanted_package,
            out_dir,
            version=wanted_version,
            sandbox=self.rootdir,
        )
        self.assertTrue(os.path.isdir(os.path.join(res, "debian")))
        # this needs to be updated when the release in _setup_foonux_config
        # changes
        upstream_version = wanted_version.split("-", maxsplit=1)[0]
        self.assertTrue(
            res.endswith(f"/{wanted_package}-{upstream_version}"),
            "unexpected version: " + res.split("/")[-1],
        )

    @unittest.skipUnless(has_internet(), "online test")
    def test_create_sources_for_a_named_ppa(self):
        """Add sources.list entries for a named PPA."""
        ppa = "LP-PPA-daisy-pluckers-daisy-seeds"
        release = self._setup_foonux_config()
        impl._build_apt_sandbox(
            self.rootdir,
            os.path.join(self.configdir, release, "sources.list"),
            "ubuntu",
            "jammy",
            origins=[ppa],
        )
        with open(
            os.path.join(
                self.rootdir, "etc", "apt", "sources.list.d", ppa + ".list"
            ),
            encoding="utf-8",
        ) as f:
            sources = f.read().splitlines()
        self.assertIn(
            "deb http://ppa.launchpad.net/daisy-pluckers/daisy-seeds/ubuntu"
            " jammy main main/debug",
            sources,
        )
        self.assertIn(
            "deb-src http://ppa.launchpad.net"
            "/daisy-pluckers/daisy-seeds/ubuntu jammy main",
            sources,
        )

        gpg = subprocess.run(
            [
                "gpg",
                "--no-options",
                "--no-default-keyring",
                "--no-auto-check-trustdb",
                "--trust-model",
                "always",
                "--batch",
                "--list-keys",
                "--keyring",
                os.path.join(
                    self.rootdir,
                    "etc",
                    "apt",
                    "trusted.gpg.d",
                    "LP-PPA-daisy-pluckers-daisy-seeds.gpg",
                ),
            ],
            check=True,
            stdout=subprocess.PIPE,
        )
        apt_keys = gpg.stdout.decode()
        self.assertIn("Launchpad PPA for Daisy Pluckers", apt_keys)

    @unittest.skipUnless(has_internet(), "online test")
    def test_create_sources_for_an_unnamed_ppa(self):
        """Add sources.list entries for an unnamed PPA."""
        ppa = "LP-PPA-apport-hackers-apport-autopkgtests"
        release = self._setup_foonux_config(ppa=True)
        impl._build_apt_sandbox(
            self.rootdir,
            os.path.join(self.configdir, release, "sources.list"),
            "ubuntu",
            "jammy",
            origins=[ppa],
        )
        with open(
            os.path.join(
                self.rootdir, "etc", "apt", "sources.list.d", ppa + ".list"
            ),
            encoding="utf-8",
        ) as f:
            sources = f.read().splitlines()
        self.assertIn(
            "deb http://ppa.launchpad.net"
            "/apport-hackers/apport-autopkgtests/ubuntu jammy main main/debug",
            sources,
        )
        self.assertIn(
            "deb-src http://ppa.launchpad.net"
            "/apport-hackers/apport-autopkgtests/ubuntu jammy main",
            sources,
        )

        gpg = subprocess.run(
            [
                "gpg",
                "--no-options",
                "--no-default-keyring",
                "--no-auto-check-trustdb",
                "--trust-model",
                "always",
                "--batch",
                "--list-keys",
                "--keyring",
                os.path.join(
                    self.rootdir,
                    "etc",
                    "apt",
                    "trusted.gpg.d",
                    "LP-PPA-apport-hackers.gpg",
                ),
            ],
            check=True,
            stdout=subprocess.PIPE,
        )
        apt_keys = gpg.stdout.decode()
        self.assertEqual("", apt_keys)

    def test_use_sources_for_a_ppa(self):
        """Use a sources.list.d file for a PPA."""
        ppa = "fooser-bar-ppa"
        release = self._setup_foonux_config(ppa=True)
        impl._build_apt_sandbox(
            self.rootdir,
            os.path.join(self.configdir, release, "sources.list"),
            "ubuntu",
            "jammy",
            origins=["LP-PPA-%s" % ppa],
        )
        with open(
            os.path.join(
                self.rootdir, "etc", "apt", "sources.list.d", ppa + ".list"
            ),
            encoding="utf-8",
        ) as f:
            sources = f.read().splitlines()
        self.assertIn(
            "deb http://ppa.launchpad.net/fooser/bar-ppa/ubuntu"
            " jammy main main/debug",
            sources,
        )
        self.assertIn(
            "deb-src http://ppa.launchpad.net/fooser/bar-ppa/ubuntu"
            " jammy main",
            sources,
        )

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_package_from_a_ppa(self):
        """Install a package from a PPA."""
        # Needs apport package in https://launchpad.net
        # /~apport-hackers/+archive/ubuntu/apport-autopkgtests
        ppa = "LP-PPA-apport-hackers-apport-autopkgtests"
        release = self._setup_foonux_config()
        wanted_package = "apport"
        wanted_version = "2.20.11-0ubuntu82.1~ppa2"
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            release,
            [(wanted_package, wanted_version)],
            False,
            self.cachedir,
            origins=[ppa],
        )

        self.assertEqual(obsolete, "")

        def sandbox_ver(pkg):
            with gzip.open(
                os.path.join(
                    self.rootdir, "usr/share/doc", pkg, "changelog.Debian.gz"
                )
            ) as f:
                return f.readline().decode().split()[1][1:-1]

        self.assertEqual(sandbox_ver(wanted_package), wanted_version)

    def _get_library_path(self, library_name: str, root_dir: str = "/") -> str:
        """Find library path regardless of the architecture."""
        libraries = glob.glob(
            os.path.join(root_dir, "usr/lib/*", library_name)
        )
        self.assertEqual(
            len(libraries), 1, f"glob for {library_name}: {libraries!r}"
        )
        return libraries[0]

    @staticmethod
    def _ubuntu_archive_uri(arch=None):
        """Return archive URI for the given architecture."""
        if arch is None:
            arch = impl.get_system_architecture()
        if arch in ("amd64", "i386"):
            return "http://archive.ubuntu.com/ubuntu"
        return "http://ports.ubuntu.com/ubuntu-ports"

    def _setup_foonux_config(self, updates=False, release="jammy", ppa=False):
        """Set up directories and configuration for install_packages()

        If ppa is True, then a sources.list file for a PPA will be created
        in sources.list.d used to test copying of a sources.list file to a
        sandbox.

        Return name and version of the operating system (DistroRelease
        field in crash report).
        """
        versions = {"focal": "20.04", "jammy": "22.04"}
        distro_release = f"Foonux {versions[release]}"
        config_release_dir = os.path.join(self.configdir, distro_release)
        os.mkdir(self.cachedir)
        os.mkdir(self.rootdir)
        os.mkdir(self.configdir)
        os.mkdir(config_release_dir)
        self._write_source_file(
            os.path.join(config_release_dir, "sources.list"),
            self._ubuntu_archive_uri(),
            release,
            updates,
        )
        if ppa:
            os.mkdir(os.path.join(config_release_dir, "sources.list.d"))
            with open(
                os.path.join(
                    config_release_dir, "sources.list.d", "fooser-bar-ppa.list"
                ),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(
                    f"deb http://ppa.launchpad.net/fooser/bar-ppa/ubuntu"
                    f" {release} main main/debug\n"
                    f"deb-src http://ppa.launchpad.net/fooser/bar-ppa/ubuntu"
                    f" {release} main\n"
                )
        os.mkdir(os.path.join(config_release_dir, "armhf"))
        self._write_source_file(
            os.path.join(config_release_dir, "armhf", "sources.list"),
            self._ubuntu_archive_uri("armhf"),
            release,
            updates,
        )
        with open(
            os.path.join(config_release_dir, "codename"), "w", encoding="utf-8"
        ) as f:
            f.write("%s" % release)

        # install GPG key for ddebs
        keyring_dir = os.path.join(config_release_dir, "trusted.gpg.d")
        self._copy_ubunut_keyrings(keyring_dir)
        # Create an architecture specific symlink, otherwise it cannot be
        # found for armhf in __AptDpkgPackageInfo._build_apt_sandbox() as
        # that looks for trusted.gpg.d relative to sources.list.
        keyring_arch_dir = os.path.join(
            config_release_dir, "armhf", "trusted.gpg.d"
        )
        os.symlink("../trusted.gpg.d", keyring_arch_dir)
        return distro_release

    @staticmethod
    def _strip_epoch(version: str) -> str:
        """Strip epoch from Debian package version."""
        return version.split(":", maxsplit=1)[-1]

    def _copy_ubunut_keyrings(self, keyring_dir: str) -> None:
        """Copy the archive and debug symbol archive keyring."""
        os.makedirs(keyring_dir, exist_ok=True)
        try:
            shutil.copy(
                "/usr/share/keyrings/ubuntu-archive-keyring.gpg", keyring_dir
            )
        except FileNotFoundError as error:  # pragma: no cover
            self.skipTest(
                f"{error.filename} missing. Please install ubuntu-keyring!"
            )

        dbgsym_keyring = "/usr/share/keyrings/ubuntu-dbgsym-keyring.gpg"
        if not os.path.isfile(dbgsym_keyring):
            self.skipTest(  # pragma: no cover
                f"{dbgsym_keyring} missing. "
                f"Please install ubuntu-dbgsym-keyring!"
            )
        # Convert from GPG keybox database format to OpenPGP Public Key format
        output_dbgsym_keyring = os.path.join(
            keyring_dir, os.path.basename(dbgsym_keyring)
        )
        try:
            with open(output_dbgsym_keyring, "wb") as gpg_key:
                gpg_cmd = [
                    "gpg",
                    "--no-default-keyring",
                    "--keyring",
                    dbgsym_keyring,
                    "--export",
                ]
                subprocess.check_call(gpg_cmd, stdout=gpg_key)
        except FileNotFoundError as error:  # pragma: no cover
            self.skipTest(f"{error.filename} not available")

    @staticmethod
    def _write_source_file(
        sources_filename: str, uri: str, release: str, updates: bool
    ) -> None:
        """Write sources.list file."""
        with open(sources_filename, "w", encoding="utf-8") as sources_file:
            sources_file.write(
                f"deb {uri} {release} main\n"
                f"deb-src {uri} {release} main\n"
                f"deb http://ddebs.ubuntu.com/ {release} main\n"
            )
            if updates:
                sources_file.write(
                    f"deb {uri} {release}-updates main\n"
                    f"deb-src {uri} {release}-updates main\n"
                    f"deb http://ddebs.ubuntu.com/ {release}-updates main\n"
                )

    def assert_elf_arch(self, path, expected):
        """Assert that an ELF file is for an expected machine type.

        Expected is a Debian-style architecture (i386, amd64, armhf)
        """
        archmap = {
            "amd64": "X86-64",
            "arm64": "AArch64",
            "armhf": "ARM",
            "i386": "80386",
            "ppc64el": "PowerPC64",
            "s390x": "IBM S/390",
        }

        # get ELF machine type
        readelf = subprocess.run(
            ["readelf", "-e", path],
            check=True,
            env={},
            stdout=subprocess.PIPE,
            text=True,
        )
        for line in readelf.stdout.splitlines():
            if line.startswith("  Machine:"):
                machine = line.split(None, 1)[1]
                break
        else:
            self.fail("could not find Machine: in readelf output")

        self.assertIn(
            archmap[expected],
            machine,
            '%s has unexpected machine type "%s" for architecture %s'
            % (path, machine, expected),
        )
