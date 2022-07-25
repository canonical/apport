import os
import pwd
import shutil
import sys
import tempfile
import time
import unittest
import unittest.mock

import apport.fileutils
import apport.packaging
import problem_report


class T(unittest.TestCase):
    def setUp(self):
        self.orig_core_dir = apport.fileutils.core_dir
        apport.fileutils.core_dir = tempfile.mkdtemp()
        self.orig_report_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = tempfile.mkdtemp()
        self.orig_config_file = apport.fileutils._config_file

    def tearDown(self):
        shutil.rmtree(apport.fileutils.core_dir)
        apport.fileutils.core_dir = self.orig_core_dir
        shutil.rmtree(apport.fileutils.report_dir)
        apport.fileutils.report_dir = self.orig_report_dir
        self.orig_report_dir = None
        apport.fileutils._config_file = self.orig_config_file

    def _create_reports(self, create_inaccessible=False):
        """Create some test reports"""

        r1 = os.path.join(apport.fileutils.report_dir, "rep1.crash")
        r2 = os.path.join(apport.fileutils.report_dir, "rep2.crash")

        with open(r1, "w") as fd:
            fd.write("report 1")
        with open(r2, "w") as fd:
            fd.write("report 2")
        os.chmod(r1, 0o600)
        os.chmod(r2, 0o600)
        if create_inaccessible:
            ri = os.path.join(
                apport.fileutils.report_dir, "inaccessible.crash"
            )
            with open(ri, "w") as fd:
                fd.write("inaccessible")
            os.chmod(ri, 0)
            return [r1, r2, ri]
        else:
            return [r1, r2]

    def test_find_package_desktopfile(self):
        """find_package_desktopfile()"""

        # package without any .desktop file
        nodesktop = "bash"
        assert (
            len(
                [
                    f
                    for f in apport.packaging.get_files(nodesktop)
                    if f.endswith(".desktop")
                ]
            )
            == 0
        )

        # find a package with one, a package with multiple .desktop files, and
        # a package with a NoDisplay .desktop file
        onedesktop = None
        multidesktop = None
        nodisplay = None
        found_some = False
        for d in sorted(os.listdir("/usr/share/applications/")):
            if not d.endswith(".desktop"):
                continue
            path = os.path.join("/usr/share/applications/", d)
            pkg = apport.packaging.get_file_package(path)
            if pkg is None:
                continue
            found_some = True

            display_num = 0
            no_display_num = 0
            for desktop_file in apport.packaging.get_files(pkg):
                if not desktop_file.endswith(".desktop"):
                    continue
                if desktop_file.startswith("/usr/share/mimelnk"):
                    continue
                with open(desktop_file, "rb") as desktop_file:
                    if b"NoDisplay=true" in desktop_file.read():
                        no_display_num += 1
                    else:
                        display_num += 1

            if not nodisplay and display_num == 0 and no_display_num == 1:
                nodisplay = pkg
            elif not onedesktop and display_num == 1:
                onedesktop = pkg
            elif not multidesktop and display_num > 1:
                multidesktop = pkg

            if onedesktop and multidesktop and nodisplay:
                break

        self.assertTrue(found_some)

        if nodesktop:
            self.assertEqual(
                apport.fileutils.find_package_desktopfile(nodesktop),
                None,
                "no-desktop package %s" % nodesktop,
            )
        if multidesktop:
            self.assertEqual(
                apport.fileutils.find_package_desktopfile(multidesktop),
                None,
                "multi-desktop package %s" % multidesktop,
            )
        if onedesktop:
            d = apport.fileutils.find_package_desktopfile(onedesktop)
            self.assertNotEqual(d, None, "one-desktop package %s" % onedesktop)
            self.assertTrue(os.path.exists(d))
            self.assertTrue(d.endswith(".desktop"))
        if nodisplay:
            self.assertEqual(
                apport.fileutils.find_package_desktopfile(nodisplay),
                None,
                "NoDisplay package %s" % nodisplay,
            )

    def test_find_file_package(self):
        """find_file_package()"""

        self.assertEqual(
            apport.fileutils.find_file_package("/bin/bash"), "bash"
        )
        self.assertEqual(
            apport.fileutils.find_file_package("/bin/cat"), "coreutils"
        )
        self.assertEqual(
            apport.fileutils.find_file_package("/nonexisting"), None
        )

    def test_seen(self):
        """get_new_reports() and seen_report()"""

        self.assertEqual(apport.fileutils.get_new_reports(), [])
        if os.getuid() == 0:
            tr = self._create_reports(True)
        else:
            tr = [
                r
                for r in self._create_reports(True)
                if "inaccessible" not in r
            ]
        self.assertEqual(set(apport.fileutils.get_new_reports()), set(tr))

        # now mark them as seen and check again
        nr = set(tr)
        for r in tr:
            self.assertEqual(apport.fileutils.seen_report(r), False)
            nr.remove(r)
            apport.fileutils.mark_report_seen(r)
            self.assertEqual(apport.fileutils.seen_report(r), True)
            self.assertEqual(set(apport.fileutils.get_new_reports()), nr)

    def test_mark_hanging_process(self):
        """mark_hanging_process()"""
        pr = problem_report.ProblemReport()
        pr["ExecutablePath"] = "/bin/bash"
        apport.fileutils.mark_hanging_process(pr, "1")
        uid = str(os.getuid())
        base = "_bin_bash.%s.1.hanging" % uid
        expected = os.path.join(apport.fileutils.report_dir, base)
        self.assertTrue(os.path.exists(expected))

    def test_mark_report_upload(self):
        """mark_report_upload()"""
        report = os.path.join(apport.fileutils.report_dir, "report.crash")
        apport.fileutils.mark_report_upload(report)
        expected = os.path.join(apport.fileutils.report_dir, "report.upload")
        self.assertTrue(os.path.exists(expected))

    def test_mark_2nd_report_upload(self):
        """mark_report_upload() for a previously uploaded report"""
        upload = os.path.join(apport.fileutils.report_dir, "report.upload")
        with open(upload, "w"):
            pass
        uploaded = os.path.join(apport.fileutils.report_dir, "report.uploaded")
        with open(uploaded, "w"):
            pass
        time.sleep(1)
        report = os.path.join(apport.fileutils.report_dir, "report.crash")
        with open(report, "w"):
            pass
        time.sleep(1)
        apport.fileutils.mark_report_upload(report)
        upload_st = os.stat(upload)
        report_st = os.stat(report)
        self.assertTrue(upload_st.st_mtime > report_st.st_mtime)

    def test_get_all_reports(self):
        """get_all_reports()"""

        self.assertEqual(apport.fileutils.get_all_reports(), [])
        if os.getuid() == 0:
            tr = self._create_reports(True)
        else:
            tr = [
                r
                for r in self._create_reports(True)
                if "inaccessible" not in r
            ]
        self.assertEqual(set(apport.fileutils.get_all_reports()), set(tr))

        # now mark them as seen and check again
        for r in tr:
            apport.fileutils.mark_report_seen(r)

        self.assertEqual(set(apport.fileutils.get_all_reports()), set(tr))

    def test_get_system_reports(self):
        """get_all_system_reports() and get_new_system_reports()"""

        self.assertEqual(apport.fileutils.get_all_reports(), [])
        self.assertEqual(apport.fileutils.get_all_system_reports(), [])
        if os.getuid() == 0:
            tr = self._create_reports(True)
            self.assertEqual(
                set(apport.fileutils.get_all_system_reports()), set(tr)
            )
            self.assertEqual(
                set(apport.fileutils.get_new_system_reports()), set(tr)
            )

            # now mark them as seen and check again
            for r in tr:
                apport.fileutils.mark_report_seen(r)

            self.assertEqual(
                set(apport.fileutils.get_all_system_reports()), set(tr)
            )
            self.assertEqual(
                set(apport.fileutils.get_new_system_reports()), set([])
            )
        else:
            tr = [
                r
                for r in self._create_reports(True)
                if "inaccessible" not in r
            ]
            self.assertEqual(
                set(apport.fileutils.get_all_system_reports()), set([])
            )
            self.assertEqual(
                set(apport.fileutils.get_new_system_reports()), set([])
            )

    @unittest.mock.patch.object(os, "stat")
    @unittest.mock.patch.object(pwd, "getpwuid")
    def test_get_system_reports_guest(self, getpwuid_mock, stat_mock):
        """get_all_system_reports() filters out reports from guest user"""

        self._create_reports()

        stat_mock.return_value.st_size = 1000
        stat_mock.return_value.st_uid = 123
        getpwuid_mock.return_value.pw_name = "guest_tmp987"
        self.assertEqual(apport.fileutils.get_all_system_reports(), [])

    def test_unwritable_report(self):
        """get_all_reports() and get_new_reports() for unwritable report"""

        self.assertEqual(apport.fileutils.get_all_reports(), [])
        self.assertEqual(apport.fileutils.get_all_system_reports(), [])

        r = os.path.join(apport.fileutils.report_dir, "unwritable.crash")
        with open(r, "w") as fd:
            fd.write("unwritable")
        os.chmod(r, 0o444)

        if os.getuid() == 0:
            self.assertEqual(set(apport.fileutils.get_new_reports()), set([r]))
            self.assertEqual(set(apport.fileutils.get_all_reports()), set([r]))
        else:
            self.assertEqual(set(apport.fileutils.get_new_reports()), set())
            self.assertEqual(set(apport.fileutils.get_all_reports()), set())

    def test_delete_report(self):
        """delete_report()"""

        tr = self._create_reports()

        while tr:
            self.assertEqual(set(apport.fileutils.get_all_reports()), set(tr))
            apport.fileutils.delete_report(tr.pop())

    def test_make_report_file(self):
        """make_report_file()"""

        pr = problem_report.ProblemReport()
        self.assertRaises(ValueError, apport.fileutils.make_report_file, pr)

        pr["Package"] = "bash 1"
        with apport.fileutils.make_report_file(pr) as f:
            path = f.name
            self.assertTrue(
                path.startswith("%s/bash" % apport.fileutils.report_dir), path
            )
            os.unlink(path)

        pr["ExecutablePath"] = "/bin/bash"
        with apport.fileutils.make_report_file(pr) as f:
            path = f.name
            self.assertTrue(
                path.startswith("%s/_bin_bash" % apport.fileutils.report_dir),
                path,
            )

        # file exists already, should fail now
        self.assertRaises(OSError, apport.fileutils.make_report_file, pr)

        # should still fail if it's a dangling symlink
        os.unlink(path)
        os.symlink(os.path.join(apport.fileutils.report_dir, "pwned"), path)
        self.assertRaises(OSError, apport.fileutils.make_report_file, pr)

    def test_check_files_md5(self):
        """check_files_md5()"""

        f1 = os.path.join(apport.fileutils.report_dir, "test 1.txt")
        f2 = os.path.join(apport.fileutils.report_dir, "test:2.txt")
        sumfile = os.path.join(apport.fileutils.report_dir, "sums.txt")
        with open(f1, "w") as fd:
            fd.write("Some stuff")
        with open(f2, "w") as fd:
            fd.write("More stuff")
        # use one relative and one absolute path in checksums file
        with open(sumfile, "w") as fd:
            fd.write(
                """2e41290da2fa3f68bd3313174467e3b5  %s
f6423dfbc4faf022e58b4d3f5ff71a70  %s
"""
                % (f1[1:], f2)
            )
        self.assertEqual(
            apport.fileutils.check_files_md5(sumfile), [], "correct md5sums"
        )

        with open(f1, "w") as fd:
            fd.write("Some stuff!")
        self.assertEqual(
            apport.fileutils.check_files_md5(sumfile), [f1[1:]], "file 1 wrong"
        )
        with open(f2, "w") as fd:
            fd.write("More stuff!")
        self.assertEqual(
            apport.fileutils.check_files_md5(sumfile),
            [f1[1:], f2],
            "files 1 and 2 wrong",
        )
        with open(f1, "w") as fd:
            fd.write("Some stuff")
        self.assertEqual(
            apport.fileutils.check_files_md5(sumfile), [f2], "file 2 wrong"
        )

    def test_get_config(self):
        """get_config()"""

        # nonexisting
        apport.fileutils._config_file = "/nonexisting"
        self.assertEqual(apport.fileutils.get_config("main", "foo"), None)
        self.assertEqual(
            apport.fileutils.get_config("main", "foo", "moo"), "moo"
        )
        apport.fileutils.get_config.config = None  # trash cache

        # empty
        with tempfile.NamedTemporaryFile() as f:
            apport.fileutils._config_file = f.name
            self.assertEqual(apport.fileutils.get_config("main", "foo"), None)
            self.assertEqual(
                apport.fileutils.get_config("main", "foo", "moo"), "moo"
            )
            apport.fileutils.get_config.config = None  # trash cache

            # nonempty
            f.write(
                b"[main]\none=1\ntwo = TWO\nb1 = 1\nb2=False\n"
                b"[spethial]\none= 99\n"
            )
            f.flush()
            self.assertEqual(apport.fileutils.get_config("main", "foo"), None)
            self.assertEqual(
                apport.fileutils.get_config("main", "foo", "moo"), "moo"
            )
            self.assertEqual(apport.fileutils.get_config("main", "one"), "1")
            self.assertEqual(
                apport.fileutils.get_config("main", "one", default="moo"), "1"
            )
            self.assertEqual(apport.fileutils.get_config("main", "two"), "TWO")
            self.assertEqual(
                apport.fileutils.get_config("main", "b1", boolean=True), True
            )
            self.assertEqual(
                apport.fileutils.get_config("main", "b2", boolean=True), False
            )
            self.assertEqual(
                apport.fileutils.get_config("main", "b3", boolean=True), None
            )
            self.assertEqual(
                apport.fileutils.get_config(
                    "main", "b3", default=False, boolean=True
                ),
                False,
            )
            self.assertEqual(
                apport.fileutils.get_config("spethial", "one"), "99"
            )
            self.assertEqual(
                apport.fileutils.get_config("spethial", "two"), None
            )
            self.assertEqual(
                apport.fileutils.get_config("spethial", "one", "moo"), "99"
            )
            self.assertEqual(
                apport.fileutils.get_config("spethial", "nope", "moo"), "moo"
            )
            apport.fileutils.get_config.config = None  # trash cache

            # interpolation
            f.write(b"[inter]\none=1\ntwo = TWO\ntest = %(two)s\n")
            f.flush()
            self.assertEqual(apport.fileutils.get_config("inter", "one"), "1")
            self.assertEqual(
                apport.fileutils.get_config("inter", "two"), "TWO"
            )
            self.assertEqual(
                apport.fileutils.get_config("inter", "test"), "%(two)s"
            )
            apport.fileutils.get_config.config = None  # trash cache

    def test_shared_libraries(self):
        """shared_libraries()"""

        libs = apport.fileutils.shared_libraries(sys.executable)
        self.assertGreater(len(libs), 3)
        self.assertIn("libc.so.6", libs)
        self.assertIn("libc.so.6", libs["libc.so.6"])
        self.assertTrue(os.path.exists(libs["libc.so.6"]))
        for library_name, library_path in libs.items():
            self.assertNotIn("vdso", library_name, libs)
            self.assertTrue(os.path.exists(library_path))

        self.assertEqual(
            apport.fileutils.shared_libraries("/non/existing"), {}
        )
        self.assertEqual(apport.fileutils.shared_libraries("/etc"), {})
        self.assertEqual(apport.fileutils.shared_libraries("/etc/passwd"), {})

    def test_links_with_shared_library(self):
        """links_with_shared_library()"""

        self.assertTrue(
            apport.fileutils.links_with_shared_library(sys.executable, "libc")
        )
        self.assertTrue(
            apport.fileutils.links_with_shared_library(
                sys.executable, "libc.so.6"
            )
        )
        self.assertFalse(
            apport.fileutils.links_with_shared_library(
                sys.executable, "libc.so.7"
            )
        )
        self.assertFalse(
            apport.fileutils.links_with_shared_library(sys.executable, "libd")
        )
        self.assertFalse(
            apport.fileutils.links_with_shared_library("/non/existing", "libc")
        )
        self.assertFalse(
            apport.fileutils.links_with_shared_library("/etc", "libc")
        )
        self.assertFalse(
            apport.fileutils.links_with_shared_library("/etc/passwd", "libc")
        )

    def test_get_core_path(self):
        """get_core_path()"""

        boot_id = apport.fileutils.get_boot_id()

        # Basic test
        (core_name, core_path) = apport.fileutils.get_core_path(
            pid=123, exe="/usr/bin/test", uid=234, timestamp=222222
        )
        expected = "core._usr_bin_test.234." + boot_id + ".123.222222"
        expected_path = os.path.join(apport.fileutils.core_dir, expected)
        self.assertEqual(core_name, expected)
        self.assertEqual(core_path, expected_path)

        # Test dots in exe names
        (core_name, core_path) = apport.fileutils.get_core_path(
            pid=123, exe="/usr/bin/test.sh", uid=234, timestamp=222222
        )
        expected = "core._usr_bin_test_sh.234." + boot_id + ".123.222222"
        expected_path = os.path.join(apport.fileutils.core_dir, expected)
        self.assertEqual(core_name, expected)
        self.assertEqual(core_path, expected_path)

        # Test no exe name
        (core_name, core_path) = apport.fileutils.get_core_path(
            pid=123, exe=None, uid=234, timestamp=222222
        )
        expected = "core.unknown.234." + boot_id + ".123.222222"
        expected_path = os.path.join(apport.fileutils.core_dir, expected)
        self.assertEqual(core_name, expected)
        self.assertEqual(core_path, expected_path)

        # Test no uid
        (core_name, core_path) = apport.fileutils.get_core_path(
            pid=123, exe="/usr/bin/test", uid=None, timestamp=222222
        )
        expected = (
            "core._usr_bin_test."
            + str(os.getuid())
            + "."
            + boot_id
            + ".123.222222"
        )
        expected_path = os.path.join(apport.fileutils.core_dir, expected)
        self.assertEqual(core_name, expected)
        self.assertEqual(core_path, expected_path)

    def test_clean_core_directory(self):
        """clean_core_directory()"""

        fake_uid = 5150
        extra_core_files = 4
        num_core_files = (
            apport.fileutils.max_corefiles_per_uid + extra_core_files
        )

        # Create some test files
        for x in range(num_core_files):
            core_path = apport.fileutils.get_core_path(
                pid=123 + x,
                exe="/usr/bin/test",
                uid=fake_uid,
                timestamp=222222 + x,
            )[1]
            with open(core_path, "w") as fd:
                fd.write("Some stuff")
                time.sleep(1)

        # Create a file with a different uid
        core_path = apport.fileutils.get_core_path(
            pid=231, exe="/usr/bin/test", uid=fake_uid + 1, timestamp=333333
        )[1]
        with open(core_path, "w") as fd:
            fd.write("Some stuff")

        # Make sure we have the proper number of test files
        self.assertEqual(
            num_core_files,
            len(apport.fileutils.find_core_files_by_uid(fake_uid)),
        )
        self.assertEqual(
            1, len(apport.fileutils.find_core_files_by_uid(fake_uid + 1))
        )

        # Clean out the directory
        apport.fileutils.clean_core_directory(fake_uid)

        # Make sure we have the proper number of test files. We should
        # have one less than max_corefiles_per_uid.
        self.assertEqual(
            apport.fileutils.max_corefiles_per_uid - 1,
            len(apport.fileutils.find_core_files_by_uid(fake_uid)),
        )
        self.assertEqual(
            1, len(apport.fileutils.find_core_files_by_uid(fake_uid + 1))
        )

        # Make sure we deleted the oldest ones
        for x in range(apport.fileutils.max_corefiles_per_uid - 1):
            offset = extra_core_files + x + 1
            core_path = apport.fileutils.get_core_path(
                pid=123 + offset,
                exe="/usr/bin/test",
                uid=fake_uid,
                timestamp=222222 + offset,
            )[1]
            self.assertTrue(os.path.exists(core_path))
