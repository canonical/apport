import gzip
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from tests.helper import import_module_from_file
from tests.paths import is_local_source_directory

if is_local_source_directory():
    impl = import_module_from_file("backends/packaging-apt-dpkg.py").impl
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

    def test_check_files_md5(self):
        """_check_files_md5()."""

        td = tempfile.mkdtemp()
        try:
            f1 = os.path.join(td, "test 1.txt")
            f2 = os.path.join(td, "test:2.txt")
            sumfile = os.path.join(td, "sums.txt")
            with open(f1, "w") as fd:
                fd.write("Some stuff")
            with open(f2, "w") as fd:
                fd.write("More stuff")
            # use one relative and one absolute path in checksums file
            with open(sumfile, "wb") as fd:
                fd.write(
                    b"2e41290da2fa3f68bd3313174467e3b5  "
                    + f1[1:].encode()
                    + b"\n"
                )
                fd.write(
                    b"f6423dfbc4faf022e58b4d3f5ff71a70  " + f2.encode() + b"\n"
                )
                fd.write(b"deadbeef000001111110000011110000  /bin/\xc3\xa4")
            self.assertEqual(
                impl._check_files_md5(sumfile), [], "correct md5sums"
            )

            with open(f1, "w") as fd:
                fd.write("Some stuff!")
            self.assertEqual(
                impl._check_files_md5(sumfile), [f1[1:]], "file 1 wrong"
            )
            with open(f2, "w") as fd:
                fd.write("More stuff!")
            self.assertEqual(
                impl._check_files_md5(sumfile),
                [f1[1:], f2],
                "files 1 and 2 wrong",
            )
            with open(f1, "w") as fd:
                fd.write("Some stuff")
            self.assertEqual(
                impl._check_files_md5(sumfile), [f2], "file 2 wrong"
            )

            # check using a direct md5 list as argument
            with open(sumfile, "rb") as fd:
                self.assertEqual(
                    impl._check_files_md5(fd.read()), [f2], "file 2 wrong"
                )

        finally:
            shutil.rmtree(td)

    def test_get_version(self):
        """get_version()."""

        self.assertTrue(impl.get_version("libc6").startswith("2"))
        self.assertRaises(ValueError, impl.get_version, "nonexisting")
        self.assertRaises(ValueError, impl.get_version, "wukrainian")

    def test_get_available_version(self):
        """get_available_version()."""

        self.assertTrue(impl.get_available_version("libc6").startswith("2"))
        self.assertRaises(
            ValueError, impl.get_available_version, "nonexisting"
        )

    def test_get_dependencies(self):
        """get_dependencies()."""

        # package with both Depends: and Pre-Depends:
        d = impl.get_dependencies("bash")
        self.assertGreater(len(d), 2)
        self.assertIn("libc6", d)
        for dep in d:
            if dep == "bash-completion":
                # bash-completion is only in Recommends (maybe not installed)
                continue
            self.assertTrue(impl.get_version(dep))

        # Pre-Depends: only
        d = impl.get_dependencies("coreutils")
        self.assertGreaterEqual(len(d), 1)
        self.assertIn("libc6", d)
        for dep in d:
            self.assertTrue(impl.get_version(dep))

        # Depends: only
        d = impl.get_dependencies("libc-bin")
        self.assertGreaterEqual(len(d), 1)
        for dep in d:
            self.assertTrue(impl.get_version(dep))

    def test_get_source(self):
        """get_source()."""

        self.assertRaises(ValueError, impl.get_source, "nonexisting")
        self.assertEqual(impl.get_source("bash"), "bash")
        self.assertIn("glibc", impl.get_source("libc6"))

    def test_get_package_origin(self):
        """get_package_origin()."""

        # determine distro name
        distro = impl.get_os_version()[0]

        self.assertRaises(ValueError, impl.get_package_origin, "nonexisting")
        # this assumes that this package is not installed
        self.assertRaises(ValueError, impl.get_package_origin, "robocode-doc")
        # this assumes that bash is native
        self.assertEqual(impl.get_package_origin("bash"), distro)
        # no non-native test here, hard to come up with a generic one

    def test_is_distro_package(self):
        """is_distro_package()."""

        self.assertRaises(ValueError, impl.is_distro_package, "nonexisting")
        self.assertTrue(impl.is_distro_package("bash"))
        # no False test here, hard to come up with a generic one

    def test_get_architecture(self):
        """get_architecture()."""

        self.assertRaises(ValueError, impl.get_architecture, "nonexisting")
        # just assume that bash uses the native architecture
        d = subprocess.Popen(
            ["dpkg", "--print-architecture"], stdout=subprocess.PIPE
        )
        system_arch = d.communicate()[0].decode().strip()
        assert d.returncode == 0
        self.assertEqual(impl.get_architecture("bash"), system_arch)

    def test_get_files(self):
        """get_files()."""

        self.assertRaises(ValueError, impl.get_files, "nonexisting")
        self.assertIn("/bin/bash", impl.get_files("bash"))

    def test_get_file_package(self):
        """get_file_package() on installed files."""

        self.assertEqual(impl.get_file_package("/bin/bash"), "bash")
        self.assertEqual(impl.get_file_package("/bin/cat"), "coreutils")
        self.assertEqual(
            impl.get_file_package("/etc/pam.conf"), "libpam-runtime"
        )
        self.assertEqual(impl.get_file_package("/nonexisting"), None)

    def test_get_file_package_uninstalled(self):
        """get_file_package() on uninstalled packages."""

        # generate a test Contents.gz
        basedir = tempfile.mkdtemp()
        try:
            # test Contents.gz for release pocket
            mapdir = os.path.join(basedir, "dists", impl.get_distro_codename())
            os.makedirs(mapdir)
            with gzip.open(
                os.path.join(
                    mapdir, "Contents-%s.gz" % impl.get_system_architecture()
                ),
                "w",
            ) as f:
                f.write(
                    b"""\
usr/bin/frobnicate                                      foo/frob
usr/bin/frob                                            foo/frob-utils
bo/gu/s                                                 na/mypackage
bin/true                                                admin/superutils
"""
                )

            # test Contents.gz for -updates pocket
            mapdir = os.path.join(
                basedir, "dists", impl.get_distro_codename() + "-updates"
            )
            os.makedirs(mapdir)
            with gzip.open(
                os.path.join(
                    mapdir, "Contents-%s.gz" % impl.get_system_architecture()
                ),
                "w",
            ) as f:
                f.write(
                    b"lib/libnew.so.5                                        "
                    b" universe/libs/libnew5"
                )

            # use this as a mirror
            impl.set_mirror("file://" + basedir)

            self.assertEqual(
                impl.get_file_package("usr/bin/frob", False), None
            )
            # must not match frob (same file name prefix)
            self.assertEqual(
                impl.get_file_package("usr/bin/frob", True), "frob-utils"
            )
            self.assertEqual(
                impl.get_file_package("/usr/bin/frob", True), "frob-utils"
            )
            # find files from -updates pocket
            self.assertEqual(
                impl.get_file_package("/lib/libnew.so.5", False), None
            )
            self.assertEqual(
                impl.get_file_package("/lib/libnew.so.5", True), "libnew5"
            )

            # invalid mirror
            impl.set_mirror("file:///foo/nonexisting")
            self.assertRaises(
                OSError, impl.get_file_package, "usr/bin/frob", True
            )

            # valid mirror, test cache directory
            impl.set_mirror("file://" + basedir)
            cache_dir = os.path.join(basedir, "cache")
            os.mkdir(cache_dir)
            self.assertEqual(
                impl.get_file_package("usr/bin/frob", True, cache_dir),
                "frob-utils",
            )
            cache_dir_files = os.listdir(cache_dir)
            self.assertEqual(len(cache_dir_files), 3)
            self.assertEqual(
                impl.get_file_package("/bo/gu/s", True, cache_dir), None
            )

            # valid cache, should not need to access the mirror
            impl.set_mirror("file:///foo/nonexisting")
            self.assertEqual(
                impl.get_file_package("/bin/true", True, cache_dir),
                "superutils",
            )
            self.assertEqual(
                impl.get_file_package("/bo/gu/s", True, cache_dir), None
            )
            self.assertEqual(
                impl.get_file_package("/lib/libnew.so.5", True, cache_dir),
                "libnew5",
            )

            # outdated cache, must refresh the cache and hit the invalid
            # mirror
            if "updates" in cache_dir_files[0]:
                cache_file = cache_dir_files[1]
            else:
                cache_file = cache_dir_files[0]
            now = int(time.time())
            os.utime(os.path.join(cache_dir, cache_file), (now, now - 90000))
        finally:
            shutil.rmtree(basedir)

    def test_get_file_package_uninstalled_multiarch(self):
        """get_file_package() on foreign arches and releases"""

        # map "Foonux 3.14" to "mocky"
        orig_distro_release_to_codename = impl._distro_release_to_codename
        impl._distro_release_to_codename = (
            lambda r: (r == "Foonux 3.14") and "mocky" or None
        )

        # generate test Contents.gz for two fantasy architectures
        basedir = tempfile.mkdtemp()
        try:
            mapdir = os.path.join(basedir, "dists", impl.get_distro_codename())
            os.makedirs(mapdir)
            with gzip.open(os.path.join(mapdir, "Contents-even.gz"), "w") as f:
                f.write(
                    b"""\
usr/lib/even/libfrob.so.1                               foo/libfrob1
usr/bin/frob                                            foo/frob-utils
"""
                )
            with gzip.open(os.path.join(mapdir, "Contents-odd.gz"), "w") as f:
                f.write(
                    b"""\
usr/lib/odd/libfrob.so.1                                foo/libfrob1
usr/bin/frob                                            foo/frob-utils
"""
                )

            # and another one for fantasy release
            os.mkdir(os.path.join(basedir, "dists", "mocky"))
            with gzip.open(
                os.path.join(basedir, "dists", "mocky", "Contents-even.gz"),
                "w",
            ) as f:
                f.write(
                    b"""\
usr/lib/even/libfrob.so.0                               foo/libfrob0
usr/bin/frob                                            foo/frob
"""
                )

            # use this as a mirror
            impl.set_mirror("file://" + basedir)

            # must not match system architecture
            self.assertEqual(
                impl.get_file_package("usr/bin/frob", False), None
            )
            # must match correct architecture
            self.assertEqual(
                impl.get_file_package("usr/bin/frob", True, arch="even"),
                "frob-utils",
            )
            self.assertEqual(
                impl.get_file_package("usr/bin/frob", True, arch="odd"),
                "frob-utils",
            )
            self.assertEqual(
                impl.get_file_package(
                    "/usr/lib/even/libfrob.so.1", True, arch="even"
                ),
                "libfrob1",
            )
            self.assertEqual(
                impl.get_file_package(
                    "/usr/lib/even/libfrob.so.1", True, arch="odd"
                ),
                None,
            )
            self.assertEqual(
                impl.get_file_package(
                    "/usr/lib/odd/libfrob.so.1", True, arch="odd"
                ),
                "libfrob1",
            )

            # for mocky release ("Foonux 3.14")
            self.assertEqual(
                impl.get_file_package(
                    "/usr/lib/even/libfrob.so.1",
                    True,
                    release="Foonux 3.14",
                    arch="even",
                ),
                None,
            )
            self.assertEqual(
                impl.get_file_package(
                    "/usr/lib/even/libfrob.so.0",
                    True,
                    release="Foonux 3.14",
                    arch="even",
                ),
                "libfrob0",
            )
            self.assertEqual(
                impl.get_file_package(
                    "/usr/bin/frob", True, release="Foonux 3.14", arch="even"
                ),
                "frob",
            )

            # invalid mirror
            impl.set_mirror("file:///foo/nonexisting")
            self.assertRaises(
                OSError,
                impl.get_file_package,
                "/usr/lib/even/libfrob.so.1",
                True,
                arch="even",
            )
            self.assertRaises(
                OSError,
                impl.get_file_package,
                "/usr/lib/even/libfrob.so.0",
                True,
                release="Foonux 3.14",
                arch="even",
            )

            # valid mirror, test caching
            impl.set_mirror("file://" + basedir)
            cache_dir = os.path.join(basedir, "cache")
            os.mkdir(cache_dir)
            self.assertEqual(
                impl.get_file_package(
                    "/usr/lib/even/libfrob.so.1", True, cache_dir, arch="even"
                ),
                "libfrob1",
            )
            self.assertEqual(len(os.listdir(cache_dir)), 2)

            self.assertEqual(
                impl.get_file_package(
                    "/usr/lib/even/libfrob.so.0",
                    True,
                    cache_dir,
                    release="Foonux 3.14",
                    arch="even",
                ),
                "libfrob0",
            )
            self.assertEqual(len(os.listdir(cache_dir)), 4)

            # valid cache, should not need to access the mirror
            impl.set_mirror("file:///foo/nonexisting")
            self.assertEqual(
                impl.get_file_package(
                    "usr/bin/frob", True, cache_dir, arch="even"
                ),
                "frob-utils",
            )
            self.assertEqual(
                impl.get_file_package(
                    "usr/bin/frob",
                    True,
                    cache_dir,
                    release="Foonux 3.14",
                    arch="even",
                ),
                "frob",
            )

            # but no cached file for the other arch
            self.assertRaises(
                OSError,
                impl.get_file_package,
                "usr/bin/frob",
                True,
                cache_dir,
                arch="odd",
            )

            # outdated cache, must refresh the cache and hit the invalid
            # mirror
            now = int(time.time())
            for cache_file in os.listdir(cache_dir):
                os.utime(
                    os.path.join(cache_dir, cache_file), (now, now - 90000)
                )

            self.assertRaises(
                OSError,
                impl.get_file_package,
                "usr/bin/frob",
                True,
                cache_dir,
                arch="even",
            )
        finally:
            shutil.rmtree(basedir)
            impl._distro_release_to_codename = orig_distro_release_to_codename

    def test_get_file_package_diversion(self):
        """get_file_package() for a diverted file."""

        output = subprocess.check_output(
            ["dpkg-divert", "--list"], env={}
        ).decode()

        for line in output.rstrip().split("\n"):
            fields = line.split(" ")
            # Local diversions have 6 fields.
            if len(fields) == 7:
                # pick first diversion we have
                break
        else:
            self.fail(
                f"No non-local diversion found. dpkg-divert output: {output}"
            )

        file = fields[2]
        pkg = fields[-1]

        self.assertEqual(impl.get_file_package(file), pkg)

    def test_mirror_from_apt_sources(self):
        s = os.path.join(self.workdir, "sources.list")

        # valid file, should grab the first mirror
        with open(s, "w") as f:
            f.write(
                """# some comment
deb-src http://source.mirror/foo tuxy main
deb http://binary.mirror/tuxy tuxy main
deb http://secondary.mirror tuxy extra
"""
            )
            f.flush()
            self.assertEqual(
                impl._get_primary_mirror_from_apt_sources(s),
                "http://binary.mirror/tuxy",
            )

        # valid file with options
        with open(s, "w") as f:
            f.write(
                """# some comment
deb-src http://source.mirror/foo tuxy main
deb [arch=flowerpc,leghf] http://binary.mirror/tuxy tuxy main
deb http://secondary.mirror tuxy extra
"""
            )
            f.flush()
            self.assertEqual(
                impl._get_primary_mirror_from_apt_sources(s),
                "http://binary.mirror/tuxy",
            )

        # empty file
        with open(s, "w") as f:
            f.flush()
        self.assertRaises(
            SystemError, impl._get_primary_mirror_from_apt_sources, s
        )

    def test_get_modified_conffiles(self):
        """get_modified_conffiles()"""

        # very shallow
        self.assertEqual(type(impl.get_modified_conffiles("bash")), type({}))
        self.assertEqual(type(impl.get_modified_conffiles("apport")), type({}))
        self.assertEqual(
            type(impl.get_modified_conffiles("nonexisting")), type({})
        )

    def test_get_system_architecture(self):
        """get_system_architecture()."""

        arch = impl.get_system_architecture()
        # must be nonempty without line breaks
        self.assertNotEqual(arch, "")
        self.assertNotIn("\n", arch)

    def test_get_library_paths(self):
        """get_library_paths()."""

        paths = impl.get_library_paths()
        # must be nonempty without line breaks
        self.assertNotEqual(paths, "")
        self.assertIn(":", paths)
        self.assertIn("/lib", paths)
        self.assertNotIn("\n", paths)

    def test_compare_versions(self):
        """compare_versions."""

        self.assertEqual(impl.compare_versions("1", "2"), -1)
        self.assertEqual(
            impl.compare_versions("1.0-1ubuntu1", "1.0-1ubuntu2"), -1
        )
        self.assertEqual(
            impl.compare_versions("1.0-1ubuntu1", "1.0-1ubuntu1"), 0
        )
        self.assertEqual(
            impl.compare_versions("1.0-1ubuntu2", "1.0-1ubuntu1"), 1
        )
        self.assertEqual(impl.compare_versions("1:1.0-1", "2007-2"), 1)
        self.assertEqual(impl.compare_versions("1:1.0-1~1", "1:1.0-1"), -1)

    def test_enabled(self):
        """enabled."""

        impl.configuration = "/nonexisting"
        self.assertEqual(impl.enabled(), True)

        f = tempfile.NamedTemporaryFile()
        impl.configuration = f.name
        f.write("# configuration file\nenabled = 1".encode())
        f.flush()
        self.assertEqual(impl.enabled(), True)
        f.close()

        f = tempfile.NamedTemporaryFile()
        impl.configuration = f.name
        f.write("# configuration file\n  enabled =0  ".encode())
        f.flush()
        self.assertEqual(impl.enabled(), False)
        f.close()

        f = tempfile.NamedTemporaryFile()
        impl.configuration = f.name
        f.write("# configuration file\nnothing here".encode())
        f.flush()
        self.assertEqual(impl.enabled(), True)
        f.close()

    def test_get_kernel_package(self):
        """get_kernel_package()."""

        self.assertIn("linux", impl.get_kernel_package())

    def test_package_name_glob(self):
        """package_name_glob()."""

        self.assertGreater(len(impl.package_name_glob("a*")), 5)
        self.assertIn("bash", impl.package_name_glob("ba*h"))
        self.assertEqual(impl.package_name_glob("bash"), ["bash"])
        self.assertEqual(impl.package_name_glob("xzywef*"), [])
