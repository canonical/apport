import glob
import gzip
import os
import shutil
import subprocess
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

from apt import apt_pkg

from tests.helper import has_internet
from tests.paths import is_local_source_directory

if is_local_source_directory():
    impl = (
        SourceFileLoader("", "backends/packaging-apt-dpkg.py")
        .load_module()
        .impl
    )
else:
    from apport.packaging_impl import impl


@unittest.skipIf(shutil.which("dpkg") is None, "dpkg not available")
class T(unittest.TestCase):
    def setUp(self):
        # save and restore configuration file
        self.orig_conf = impl.configuration
        self.orig_environ = os.environ.copy()
        self.workdir = tempfile.mkdtemp()
        os.environ["HOME"] = self.workdir
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

        self._setup_foonux_config(release="xenial", updates=True)
        v_coreutils = "8.25-2ubuntu2"
        v_libc = "2.23-0ubuntu3"
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 16.04",
            [
                ("coreutils", v_coreutils),  # should not come from updates
                ("libc6", v_libc),
                ("tzdata", None),  # should come from -updates, > 2014b-1
            ],
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
        self.assertTrue(
            os.path.exists(
                os.path.join(self.rootdir, "usr/share/doc/libc6/copyright")
            )
        )

        # their versions are as expected
        self.assertEqual(sandbox_ver("coreutils"), v_coreutils)
        self.assertEqual(sandbox_ver("libc6"), v_libc)
        self.assertEqual(sandbox_ver("libc6-dbg"), v_libc)
        self.assertGreater(sandbox_ver("tzdata"), "2016")

        with open(os.path.join(self.rootdir, "packages.txt")) as f:
            pkglist = f.read().splitlines()
        self.assertIn("coreutils " + v_coreutils, pkglist)
        self.assertIn("coreutils-dbgsym " + v_coreutils, pkglist)
        self.assertIn("libc6 " + v_libc, pkglist)
        self.assertIn("libc6-dbg " + v_libc, pkglist)
        self.assertIn("tzdata " + sandbox_ver("tzdata"), pkglist)
        self.assertEqual(len(pkglist), 5, str(pkglist))

        # does not clobber config dir
        self.assertEqual(os.listdir(self.configdir), ["Foonux 16.04"])
        self.assertEqual(
            sorted(os.listdir(os.path.join(self.configdir, "Foonux 16.04"))),
            ["armhf", "codename", "sources.list", "trusted.gpg.d"],
        )
        self.assertEqual(
            sorted(
                os.listdir(
                    os.path.join(self.configdir, "Foonux 16.04", "armhf")
                )
            ),
            ["sources.list", "trusted.gpg.d"],
        )

        # caches packages, and their versions are as expected
        cache = os.listdir(
            os.path.join(
                self.cachedir,
                "Foonux 16.04",
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
        self.assertEqual(cache_versions["coreutils"], v_coreutils)
        self.assertEqual(cache_versions["coreutils-dbgsym"], v_coreutils)
        self.assertIn("tzdata", cache_versions)
        self.assertEqual(cache_versions["libc6"], v_libc)
        self.assertEqual(cache_versions["libc6-dbg"], v_libc)

        # installs cached packages
        os.unlink(os.path.join(self.rootdir, "usr/bin/stat"))
        os.unlink(os.path.join(self.rootdir, "packages.txt"))
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 16.04",
            [("coreutils", v_coreutils)],
            False,
            self.cachedir,
        )
        self.assertEqual(obsolete, "")
        self.assertTrue(
            os.path.exists(os.path.join(self.rootdir, "usr/bin/stat"))
        )

        # complains about obsolete packages
        result = impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 16.04",
            [("aspell-doc", "1.1")],
        )
        self.assertIn(
            "aspell-doc version 1.1 required, but 0.60.7~20110707-3", result
        )
        # ... but installs the current version anyway
        self.assertTrue(
            os.path.exists(
                os.path.join(self.rootdir, "usr/share/info/aspell.info.gz")
            )
        )
        self.assertGreaterEqual(sandbox_ver("aspell-doc"), "0.60.7~2011")

        # does not crash on nonexisting packages
        result = impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 16.04",
            [("buggerbogger", None)],
        )
        self.assertEqual(len(result.splitlines()), 1)
        self.assertIn("buggerbogger", result)
        self.assertIn("not exist", result)

        # can interleave with other operations
        dpkg = subprocess.Popen(
            ["dpkg-query", "-Wf${Version}", "dash"], stdout=subprocess.PIPE
        )
        dash_version = dpkg.communicate()[0].decode()
        self.assertEqual(dpkg.returncode, 0)

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
            "Foonux 16.04",
            [("coreutils", v_coreutils), ("dpkg", None)],
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

        self._setup_foonux_config(release="xenial")
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 16.04",
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
        self.assertEqual(os.listdir(self.configdir), ["Foonux 16.04"])
        self.assertEqual(
            sorted(os.listdir(os.path.join(self.configdir, "Foonux 16.04"))),
            ["armhf", "codename", "sources.list", "trusted.gpg.d"],
        )
        self.assertEqual(
            sorted(
                os.listdir(
                    os.path.join(self.configdir, "Foonux 16.04", "armhf")
                )
            ),
            ["sources.list", "trusted.gpg.d"],
        )

        # no cache
        self.assertEqual(os.listdir(self.cachedir), [])

        # keeps track of package versions
        with open(os.path.join(self.rootdir, "packages.txt")) as f:
            pkglist = f.read().splitlines()
        self.assertIn("coreutils 8.25-2ubuntu2", pkglist)
        self.assertIn("coreutils-dbgsym 8.25-2ubuntu2", pkglist)
        self.assertIn("tzdata 2016d-0ubuntu0.16.04", pkglist)
        self.assertEqual(len(pkglist), 3, str(pkglist))

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_packages_dependencies(self):
        """install packages's dependencies"""

        self._setup_foonux_config(release="xenial")
        # coreutils should always depend on libc6
        result = impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 16.04",
            [("coreutils", None)],
            False,
            None,
            install_deps=True,
        )

        # check packages.txt for a dependency
        with open(os.path.join(self.rootdir, "packages.txt")) as f:
            pkglist = f.read().splitlines()
        self.assertIn("coreutils 8.25-2ubuntu2", pkglist)
        self.assertIn("libc6 2.23-0ubuntu3", pkglist)

        # ensure obsolete packages doesn't include libc6
        self.assertNotIn("libc6", result)

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_packages_system(self):
        """install_packages() with system configuration"""

        # trigger an unrelated package query here to get the cache set up,
        # reproducing an install failure when the internal caches are not
        # reset properly
        impl.get_version("dash")

        lsb_output = subprocess.check_output(["lsb_release", "-sir"]).decode()
        system_version = lsb_output.replace("\n", " ").strip()
        cachedir = os.path.join(self.workdir, "cache")
        rootdir = os.path.join(self.workdir, "root")

        result = impl.install_packages(
            rootdir,
            None,
            system_version,
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
        self._setup_foonux_config()
        with open(
            os.path.join(self.configdir, "Foonux 14.04", "sources.list"), "w"
        ) as f:
            f.write("bogus format")

        try:
            impl.install_packages(
                self.rootdir,
                self.configdir,
                "Foonux 14.04",
                [("tzdata", None)],
                False,
                self.cachedir,
            )
            self.fail(
                "install_packages() unexpectedly succeeded"
                " with broken sources.list"
            )
        except SystemError as e:
            self.assertIn("bogus", str(e))
            self.assertNotIn("Exception", str(e))

        # sources.list with wrong server
        with open(
            os.path.join(self.configdir, "Foonux 14.04", "sources.list"), "w"
        ) as f:
            f.write(
                "deb http://archive.ubuntu.com/nosuchdistro/ trusty main\n"
            )

        try:
            impl.install_packages(
                self.rootdir,
                self.configdir,
                "Foonux 14.04",
                [("tzdata", None)],
                False,
                self.cachedir,
            )
            self.fail(
                "install_packages() unexpectedly succeeded"
                " with broken server URL"
            )
        except SystemError as e:
            self.assertIn("nosuchdistro", str(e))
            try:
                self.assertRegex(
                    str(e),
                    ".*'http://archive.ubuntu.com/nosuchdistro trusty.*'"
                    " does not have a Release file",
                )
            except AssertionError:
                self.assertIn("index files failed to download", str(e))

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_packages_permanent_sandbox(self):
        """install_packages() with a permanent sandbox"""

        self._setup_foonux_config()
        zonetab = os.path.join(self.rootdir, "usr/share/zoneinfo/zone.tab")

        impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 14.04",
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
            "Foonux 14.04",
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
            "Foonux 14.04",
            [("libc6", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )

        # These packages exist, so attempting to install them should not fail.
        impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 14.04",
            [("coreutils", None), ("tzdata", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )
        # even without cached debs, trying to install the same versions should
        # be a no-op and succeed
        for f in glob.glob(
            "%s/Foonux 14.04/apt/var/cache/apt/archives/coreutils*"
            % self.cachedir
        ):
            os.unlink(f)
        impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 14.04",
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
            "Foonux 14.04",
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
        self._setup_foonux_config()
        include_path = os.path.join(self.rootdir, "usr/include/krb5.h")
        impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 14.04",
            [("libkrb5-dev", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )
        self.assertIn("mit-krb5/", os.readlink(include_path))

        impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 14.04",
            [("heimdal-dev", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )
        self.assertIn("heimdal/", os.readlink(include_path))

        impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 14.04",
            [("libkrb5-dev", None)],
            False,
            self.cachedir,
            permanent_rootdir=True,
        )
        self.assertIn("mit-krb5/", os.readlink(include_path))

    @unittest.skipUnless(has_internet(), "online test")
    @unittest.skipIf(
        impl.get_system_architecture() == "armhf", "native armhf architecture"
    )
    def test_install_packages_armhf(self):
        """install_packages() for foreign architecture armhf"""

        self._setup_foonux_config(release="xenial")
        vers = "16.04"
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux %s" % vers,
            [("coreutils", None), ("libc6", "2.23-0ubuntu0")],
            False,
            self.cachedir,
            architecture="armhf",
        )

        self.assertEqual(
            obsolete,
            "libc6 version 2.23-0ubuntu0 required,"
            " but 2.23-0ubuntu3 is available\n",
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
                "Foonux 16.04",
                "armhf",
                "apt",
                "var",
                "cache",
                "apt",
                "archives",
            )
        )
        self.assertIn("coreutils_8.25-2ubuntu2_armhf.deb", cache)
        self.assertIn("libc6_2.23-0ubuntu3_armhf.deb", cache)

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_packages_from_launchpad(self):
        """install_packages() using packages only available on Launchpad"""

        self._setup_foonux_config()
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 14.04",
            [
                ("oxideqt-codecs", "1.6.6-0ubuntu0.14.04.1"),
                ("distro-info-data", "0.18ubuntu0.2"),
                ("qemu-utils", "2.0.0+dfsg-2ubuntu1.11"),
                ("unity-services", "7.2.5+14.04.20150521.1-0ubuntu1"),
            ],
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
                os.path.join(
                    self.rootdir, "usr/share/doc/oxideqt-codecs/copyright"
                )
            )
        )
        self.assertTrue(
            os.path.exists(
                os.path.join(self.rootdir, "usr/share/distro-info/ubuntu.csv")
            )
        )

        # their versions are as expected
        self.assertEqual(
            sandbox_ver("oxideqt-codecs"), "1.6.6-0ubuntu0.14.04.1"
        )
        self.assertEqual(
            sandbox_ver("oxideqt-codecs-dbg"), "1.6.6-0ubuntu0.14.04.1"
        )
        self.assertEqual(
            sandbox_ver("distro-info-data", debian=False), "0.18ubuntu0.2"
        )

        # keeps track of package versions
        with open(os.path.join(self.rootdir, "packages.txt")) as f:
            pkglist = f.read().splitlines()
        self.assertIn("oxideqt-codecs 1.6.6-0ubuntu0.14.04.1", pkglist)
        self.assertIn("oxideqt-codecs-dbg 1.6.6-0ubuntu0.14.04.1", pkglist)
        self.assertIn("distro-info-data 0.18ubuntu0.2", pkglist)
        self.assertIn("qemu-utils-dbgsym 2.0.0+dfsg-2ubuntu1.11", pkglist)
        self.assertIn(
            "unity-services-dbgsym 7.2.5+14.04.20150521.1-0ubuntu1", pkglist
        )

        # caches packages, and their versions are as expected
        cache = os.listdir(
            os.path.join(
                self.cachedir,
                "Foonux 14.04",
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
            ("oxideqt-codecs", "1.6.6-0ubuntu0.14.04.1"), cache_versions
        )
        self.assertIn(
            ("oxideqt-codecs-dbg", "1.6.6-0ubuntu0.14.04.1"), cache_versions
        )
        self.assertIn(("distro-info-data", "0.18ubuntu0.2"), cache_versions)
        self.assertIn(
            ("qemu-utils-dbgsym", "2.0.0+dfsg-2ubuntu1.11"), cache_versions
        )

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_old_packages(self):
        """sandbox will install older package versions from launchpad"""

        self._setup_foonux_config()
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 14.04",
            [("oxideqt-codecs", "1.7.8-0ubuntu0.14.04.1")],
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
        self.assertEqual(
            sandbox_ver("oxideqt-codecs"), "1.7.8-0ubuntu0.14.04.1"
        )

        # keeps track of package version
        with open(os.path.join(self.rootdir, "packages.txt")) as f:
            pkglist = f.read().splitlines()
        self.assertIn("oxideqt-codecs 1.7.8-0ubuntu0.14.04.1", pkglist)

        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 14.04",
            [("oxideqt-codecs", "1.6.6-0ubuntu0.14.04.1")],
            False,
            self.cachedir,
        )

        self.assertEqual(obsolete, "")

        # the old version is installed
        self.assertEqual(
            sandbox_ver("oxideqt-codecs"), "1.6.6-0ubuntu0.14.04.1"
        )

        # the old versions is tracked
        with open(os.path.join(self.rootdir, "packages.txt")) as f:
            pkglist = f.read().splitlines()
        self.assertIn("oxideqt-codecs 1.6.6-0ubuntu0.14.04.1", pkglist)

    @unittest.skipUnless(has_internet(), "online test")
    def test_get_source_tree_sandbox(self):
        self._setup_foonux_config()
        out_dir = os.path.join(self.workdir, "out")
        os.mkdir(out_dir)
        impl._build_apt_sandbox(
            self.rootdir,
            os.path.join(self.configdir, "Foonux 14.04", "sources.list"),
            "ubuntu",
            "trusty",
            origins=None,
        )
        res = impl.get_source_tree(
            "base-files", out_dir, sandbox=self.rootdir, apt_update=True
        )
        self.assertTrue(os.path.isdir(os.path.join(res, "debian")))
        # this needs to be updated when the release in _setup_foonux_config
        # changes
        self.assertTrue(
            res.endswith("/base-files-7.2ubuntu5"),
            "unexpected version: " + res.split("/")[-1],
        )

    @unittest.skipUnless(has_internet(), "online test")
    def test_get_source_tree_lp_sandbox(self):
        self._setup_foonux_config()
        out_dir = os.path.join(self.workdir, "out")
        os.mkdir(out_dir)
        impl._build_apt_sandbox(
            self.rootdir,
            os.path.join(self.configdir, "Foonux 14.04", "sources.list"),
            "ubuntu",
            "trusty",
            origins=None,
        )
        res = impl.get_source_tree(
            "debian-installer",
            out_dir,
            version="20101020ubuntu318.16",
            sandbox=self.rootdir,
            apt_update=True,
        )
        self.assertTrue(os.path.isdir(os.path.join(res, "debian")))
        # this needs to be updated when the release in _setup_foonux_config
        # changes
        self.assertTrue(
            res.endswith("/debian-installer-20101020ubuntu318.16"),
            "unexpected version: " + res.split("/")[-1],
        )

    @unittest.skipUnless(has_internet(), "online test")
    def test_create_sources_for_a_named_ppa(self):
        """Add sources.list entries for a named PPA."""
        ppa = "LP-PPA-daisy-pluckers-daisy-seeds"
        self._setup_foonux_config()
        impl._build_apt_sandbox(
            self.rootdir,
            os.path.join(self.configdir, "Foonux 14.04", "sources.list"),
            "ubuntu",
            "trusty",
            origins=[ppa],
        )
        with open(
            os.path.join(
                self.rootdir, "etc", "apt", "sources.list.d", ppa + ".list"
            )
        ) as f:
            sources = f.read().splitlines()
        self.assertIn(
            "deb http://ppa.launchpad.net/daisy-pluckers/daisy-seeds/ubuntu"
            " trusty main main/debug",
            sources,
        )
        self.assertIn(
            "deb-src http://ppa.launchpad.net"
            "/daisy-pluckers/daisy-seeds/ubuntu trusty main",
            sources,
        )

        d = subprocess.Popen(
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
            stdout=subprocess.PIPE,
        )
        apt_keys = d.communicate()[0].decode()
        assert d.returncode == 0
        self.assertIn("Launchpad PPA for Daisy Pluckers", apt_keys)

    @unittest.skipUnless(has_internet(), "online test")
    def test_create_sources_for_an_unnamed_ppa(self):
        """Add sources.list entries for an unnamed PPA."""
        ppa = "LP-PPA-apport-hackers-apport-autopkgtests"
        self._setup_foonux_config(release="focal", ppa=True)
        impl._build_apt_sandbox(
            self.rootdir,
            os.path.join(self.configdir, "Foonux 20.04", "sources.list"),
            "ubuntu",
            "focal",
            origins=[ppa],
        )
        with open(
            os.path.join(
                self.rootdir, "etc", "apt", "sources.list.d", ppa + ".list"
            )
        ) as f:
            sources = f.read().splitlines()
        self.assertIn(
            "deb http://ppa.launchpad.net"
            "/apport-hackers/apport-autopkgtests/ubuntu focal main",
            sources,
        )
        self.assertIn(
            "deb-src http://ppa.launchpad.net"
            "/apport-hackers/apport-autopkgtests/ubuntu focal main",
            sources,
        )

        d = subprocess.Popen(
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
            stdout=subprocess.PIPE,
        )
        apt_keys = d.communicate()[0].decode()
        assert d.returncode == 0
        self.assertIn("", apt_keys)

    def test_use_sources_for_a_ppa(self):
        """Use a sources.list.d file for a PPA."""
        ppa = "fooser-bar-ppa"
        self._setup_foonux_config(ppa=True)
        impl._build_apt_sandbox(
            self.rootdir,
            os.path.join(self.configdir, "Foonux 14.04", "sources.list"),
            "ubuntu",
            "trusty",
            origins=["LP-PPA-%s" % ppa],
        )
        with open(
            os.path.join(
                self.rootdir, "etc", "apt", "sources.list.d", ppa + ".list"
            )
        ) as f:
            sources = f.read().splitlines()
        self.assertIn(
            "deb http://ppa.launchpad.net/fooser/bar-ppa/ubuntu"
            " trusty main main/debug",
            sources,
        )
        self.assertIn(
            "deb-src http://ppa.launchpad.net/fooser/bar-ppa/ubuntu"
            " trusty main",
            sources,
        )

    @unittest.skipUnless(has_internet(), "online test")
    def test_install_package_from_a_ppa(self):
        """Install a package from a PPA."""
        ppa = "LP-PPA-apport-hackers-apport-autopkgtests"
        self._setup_foonux_config(release="focal")
        obsolete = impl.install_packages(
            self.rootdir,
            self.configdir,
            "Foonux 20.04",
            [("apport", "2.20.11-0ubuntu27.14~ppa1")],
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

        self.assertEqual(sandbox_ver("apport"), "2.20.11-0ubuntu27.14~ppa1")

    def _setup_foonux_config(self, updates=False, release="trusty", ppa=False):
        """Set up directories and configuration for install_packages()

        If ppa is True, then a sources.list file for a PPA will be created
        in sources.list.d used to test copying of a sources.list file to a
        sandbox.
        """
        versions = {
            "trusty": "14.04",
            "xenial": "16.04",
            "boinic": "18.04",
            "focal": "20.04",
        }
        vers = versions[release]
        self.cachedir = os.path.join(self.workdir, "cache")
        self.rootdir = os.path.join(self.workdir, "root")
        self.configdir = os.path.join(self.workdir, "config")
        os.mkdir(self.cachedir)
        os.mkdir(self.rootdir)
        os.mkdir(self.configdir)
        os.mkdir(os.path.join(self.configdir, "Foonux %s" % vers))
        self._write_source_file(
            os.path.join(self.configdir, "Foonux %s" % vers, "sources.list"),
            "http://archive.ubuntu.com/ubuntu/",
            release,
            updates,
        )
        if ppa:
            os.mkdir(
                os.path.join(
                    self.configdir, "Foonux %s" % vers, "sources.list.d"
                )
            )
            with open(
                os.path.join(
                    self.configdir,
                    "Foonux %s" % vers,
                    "sources.list.d",
                    "fooser-bar-ppa.list",
                ),
                "w",
            ) as f:
                f.write(
                    f"deb http://ppa.launchpad.net/fooser/bar-ppa/ubuntu"
                    f" {release} main main/debug\n"
                    f"deb-src http://ppa.launchpad.net/fooser/bar-ppa/ubuntu"
                    f" {release} main\n"
                )
        os.mkdir(os.path.join(self.configdir, "Foonux %s" % vers, "armhf"))
        self._write_source_file(
            os.path.join(
                self.configdir, "Foonux %s" % vers, "armhf", "sources.list"
            ),
            "http://ports.ubuntu.com/",
            release,
            updates,
        )
        with open(
            os.path.join(self.configdir, "Foonux %s" % vers, "codename"), "w"
        ) as f:
            f.write("%s" % release)

        # install GPG key for ddebs
        keyring_dir = os.path.join(
            self.configdir, "Foonux %s" % vers, "trusted.gpg.d"
        )
        self._copy_ubunut_keyrings(keyring_dir)
        # Create an architecture specific symlink, otherwise it cannot be
        # found for armhf in __AptDpkgPackageInfo._build_apt_sandbox() as
        # that looks for trusted.gpg.d relative to sources.list.
        keyring_arch_dir = os.path.join(
            self.configdir, "Foonux %s" % vers, "armhf", "trusted.gpg.d"
        )
        os.symlink("../trusted.gpg.d", keyring_arch_dir)

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

    def _write_source_file(
        self, sources_filename: str, uri: str, release: str, updates: bool
    ) -> None:
        """Write sources.list file."""
        with open(sources_filename, "w") as sources_file:
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
        archmap = {"i386": "80386", "amd64": "X86-64", "armhf": "ARM"}

        # get ELF machine type
        readelf = subprocess.Popen(
            ["readelf", "-e", path],
            env={},
            stdout=subprocess.PIPE,
            universal_newlines=True,
        )
        out = readelf.communicate()[0]
        assert readelf.returncode == 0
        for line in out.splitlines():
            if line.startswith("  Machine:"):
                machine = line.split(None, 1)[1]
                break
        else:
            self.fail("could not find Machine: in readelf output")

        self.assertTrue(
            archmap[expected] in machine,
            '%s has unexpected machine type "%s" for architecture %s'
            % (path, machine, expected),
        )
