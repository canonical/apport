"""Integration tests for the apport.fileutils module."""

import glob
import os
import pwd
import re
import shutil
import sys
import tempfile
import time
import unittest
import unittest.mock
from collections.abc import Iterator
from unittest.mock import MagicMock

import apport.fileutils
import apport.packaging
import problem_report


class T(unittest.TestCase):
    # pylint: disable=protected-access
    """Integration tests for the apport.fileutils module."""

    orig_config_file: str
    orig_core_dir: str
    orig_report_dir: str

    def setUp(self) -> None:
        self.orig_core_dir = apport.fileutils.core_dir
        apport.fileutils.core_dir = tempfile.mkdtemp()
        self.orig_report_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = tempfile.mkdtemp()
        self.orig_config_file = apport.fileutils._CONFIG_FILE

    def tearDown(self):
        shutil.rmtree(apport.fileutils.core_dir)
        apport.fileutils.core_dir = self.orig_core_dir
        shutil.rmtree(apport.fileutils.report_dir)
        apport.fileutils.report_dir = self.orig_report_dir
        self.orig_report_dir = None
        apport.fileutils._CONFIG_FILE = self.orig_config_file

    @staticmethod
    def _create_reports(create_inaccessible: bool = False) -> list[str]:
        """Create some test reports."""
        r1 = os.path.join(apport.fileutils.report_dir, "rep1.crash")
        r2 = os.path.join(apport.fileutils.report_dir, "rep2.crash")

        with open(r1, "w", encoding="utf-8") as fd:
            fd.write("report 1")
        with open(r2, "w", encoding="utf-8") as fd:
            fd.write("report 2")
        os.chmod(r1, 0o600)
        os.chmod(r2, 0o600)
        if create_inaccessible:
            ri = os.path.join(apport.fileutils.report_dir, "inaccessible.crash")
            with open(ri, "w", encoding="utf-8") as fd:
                fd.write("inaccessible")
            os.chmod(ri, 0)
            return [r1, r2, ri]
        return [r1, r2]

    @staticmethod
    def _packages_with_desktop_files() -> Iterator[tuple[str, int, int]]:
        desktop_path_re = re.compile("^/usr/share/applications/[^/]+.desktop$")
        for path in sorted(glob.glob("/usr/share/applications/*.desktop")):
            pkg = apport.packaging.get_file_package(path)
            if pkg is None:
                continue

            display_num = 0
            no_display_num = 0
            for desktop_file in apport.packaging.get_files(pkg):
                if not desktop_path_re.match(desktop_file):
                    continue
                with open(desktop_file, "rb") as desktop_file:
                    if b"NoDisplay=true" in desktop_file.read():
                        no_display_num += 1
                    else:
                        display_num += 1

            yield (pkg, display_num, no_display_num)

    def test_find_package_desktopfile_none(self) -> None:
        """find_package_desktopfile() for a package without any .desktop file"""
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
        self.assertIsNone(
            apport.fileutils.find_package_desktopfile(nodesktop),
            f"no-desktop package {nodesktop}",
        )

    def test_find_package_desktopfile_one(self) -> None:
        """find_package_desktopfile() for a package with exactly one .desktop file"""
        for pkg, display_num, _ in self._packages_with_desktop_files():
            if display_num == 1:
                onedesktop = pkg
                break
        else:
            self.skipTest("no package with exactly one .desktop file found")

        d = apport.fileutils.find_package_desktopfile(onedesktop)
        self.assertIsNotNone(d, f"one-desktop package {onedesktop}")
        self.assertTrue(os.path.exists(d))
        self.assertTrue(d.endswith(".desktop"))

    def test_find_package_desktopfile_multiple(self) -> None:
        """find_package_desktopfile() for a package without multiple .desktop files"""
        for pkg, display_num, _ in self._packages_with_desktop_files():
            if display_num > 1:
                multidesktop = pkg
                break
        else:
            self.skipTest("no package with multiple .desktop files found")

        self.assertIsNone(
            apport.fileutils.find_package_desktopfile(multidesktop),
            f"multi-desktop package {multidesktop}",
        )

    def test_find_package_desktopfile_no_display(self) -> None:
        """find_package_desktopfile() for a package with a NoDisplay .desktop file"""
        nodisplay = None
        for pkg, display_num, no_display_num in self._packages_with_desktop_files():
            if display_num == 0 and no_display_num == 1:
                nodisplay = pkg
                break
        # expect a package with a NoDisplay .desktop file, e. g. python3.XX
        assert nodisplay is not None

        self.assertIsNone(
            apport.fileutils.find_package_desktopfile(nodisplay),
            f"NoDisplay package {nodisplay}",
        )

    def test_find_file_package(self) -> None:
        """find_file_package()"""
        self.assertEqual(apport.fileutils.find_file_package("/bin/bash"), "bash")
        self.assertEqual(apport.fileutils.find_file_package("/bin/cat"), "coreutils")
        self.assertIsNone(apport.fileutils.find_file_package("/nonexisting"))

    def test_seen(self) -> None:
        """get_new_reports() and seen_report()"""
        self.assertEqual(apport.fileutils.get_new_reports(), [])
        if os.getuid() == 0:
            tr = self._create_reports(True)
        else:
            tr = [r for r in self._create_reports(True) if "inaccessible" not in r]
        self.assertEqual(set(apport.fileutils.get_new_reports()), set(tr))

        # now mark them as seen and check again
        nr = set(tr)
        for r in tr:
            self.assertEqual(apport.fileutils.seen_report(r), False)
            nr.remove(r)
            apport.fileutils.mark_report_seen(r)
            self.assertEqual(apport.fileutils.seen_report(r), True)
            self.assertEqual(set(apport.fileutils.get_new_reports()), nr)

    def test_mark_hanging_process(self) -> None:
        """mark_hanging_process()"""
        pr = problem_report.ProblemReport()
        pr["ExecutablePath"] = "/bin/bash"
        apport.fileutils.mark_hanging_process(pr, 1)
        uid = str(os.getuid())
        base = f"_bin_bash.{uid}.1.hanging"
        expected = os.path.join(apport.fileutils.report_dir, base)
        self.assertTrue(os.path.exists(expected))

    def test_mark_report_upload(self) -> None:
        """mark_report_upload()"""
        report = os.path.join(apport.fileutils.report_dir, "report.crash")
        apport.fileutils.mark_report_upload(report)
        expected = os.path.join(apport.fileutils.report_dir, "report.upload")
        self.assertTrue(os.path.exists(expected))

    def test_mark_2nd_report_upload(self) -> None:
        """mark_report_upload() for a previously uploaded report"""
        upload = os.path.join(apport.fileutils.report_dir, "report.upload")
        with open(upload, "w", encoding="utf-8"):
            pass
        uploaded = os.path.join(apport.fileutils.report_dir, "report.uploaded")
        with open(uploaded, "w", encoding="utf-8"):
            pass
        time.sleep(1)
        report = os.path.join(apport.fileutils.report_dir, "report.crash")
        with open(report, "w", encoding="utf-8"):
            pass
        time.sleep(1)
        apport.fileutils.mark_report_upload(report)
        upload_st = os.stat(upload)
        report_st = os.stat(report)
        self.assertTrue(upload_st.st_mtime > report_st.st_mtime)

    def test_get_all_reports(self) -> None:
        """get_all_reports()"""
        self.assertEqual(apport.fileutils.get_all_reports(), [])
        if os.getuid() == 0:
            tr = self._create_reports(True)
        else:
            tr = [r for r in self._create_reports(True) if "inaccessible" not in r]
        self.assertEqual(set(apport.fileutils.get_all_reports()), set(tr))

        # now mark them as seen and check again
        for r in tr:
            apport.fileutils.mark_report_seen(r)

        self.assertEqual(set(apport.fileutils.get_all_reports()), set(tr))

    def test_get_system_reports(self) -> None:
        """get_all_system_reports() and get_new_system_reports()"""
        self.assertEqual(apport.fileutils.get_all_reports(), [])
        self.assertEqual(apport.fileutils.get_all_system_reports(), [])
        if os.getuid() == 0:
            tr = self._create_reports(True)
            self.assertEqual(set(apport.fileutils.get_all_system_reports()), set(tr))
            self.assertEqual(set(apport.fileutils.get_new_system_reports()), set(tr))

            # now mark them as seen and check again
            for r in tr:
                apport.fileutils.mark_report_seen(r)

            self.assertEqual(set(apport.fileutils.get_all_system_reports()), set(tr))
            self.assertEqual(set(apport.fileutils.get_new_system_reports()), set([]))
        else:
            tr = [r for r in self._create_reports(True) if "inaccessible" not in r]
            self.assertEqual(set(apport.fileutils.get_all_system_reports()), set([]))
            self.assertEqual(set(apport.fileutils.get_new_system_reports()), set([]))

    @unittest.mock.patch.object(os, "stat")
    @unittest.mock.patch.object(pwd, "getpwuid")
    def test_get_system_reports_guest(
        self, getpwuid_mock: MagicMock, stat_mock: MagicMock
    ) -> None:
        """get_all_system_reports() filters out reports from guest user"""
        self._create_reports()

        stat_mock.return_value.st_size = 1000
        stat_mock.return_value.st_uid = 123
        getpwuid_mock.return_value.pw_name = "guest_tmp987"
        self.assertEqual(apport.fileutils.get_all_system_reports(), [])

    def test_unwritable_report(self) -> None:
        """get_all_reports() and get_new_reports() for unwritable report"""
        self.assertEqual(apport.fileutils.get_all_reports(), [])
        self.assertEqual(apport.fileutils.get_all_system_reports(), [])

        r = os.path.join(apport.fileutils.report_dir, "unwritable.crash")
        with open(r, "w", encoding="utf-8") as fd:
            fd.write("unwritable")
        os.chmod(r, 0o444)

        if os.getuid() == 0:
            self.assertEqual(set(apport.fileutils.get_new_reports()), set([r]))
            self.assertEqual(set(apport.fileutils.get_all_reports()), set([r]))
        else:
            self.assertEqual(set(apport.fileutils.get_new_reports()), set())
            self.assertEqual(set(apport.fileutils.get_all_reports()), set())

    def test_delete_report(self) -> None:
        """delete_report()"""
        tr = self._create_reports()

        while tr:
            self.assertEqual(set(apport.fileutils.get_all_reports()), set(tr))
            apport.fileutils.delete_report(tr.pop())

    def test_make_report_file(self) -> None:
        """make_report_file()"""
        pr = problem_report.ProblemReport()
        self.assertRaises(ValueError, apport.fileutils.make_report_file, pr)

        pr["Package"] = "bash 1"
        with apport.fileutils.make_report_file(pr) as f:
            path = f.name
            self.assertTrue(
                path.startswith(f"{apport.fileutils.report_dir}/bash"), path
            )
            os.unlink(path)

        pr["ExecutablePath"] = "/bin/bash"
        with apport.fileutils.make_report_file(pr) as f:
            path = f.name
            self.assertTrue(
                path.startswith(f"{apport.fileutils.report_dir}/_bin_bash"), path
            )

        # file exists already, should fail now
        self.assertRaises(OSError, apport.fileutils.make_report_file, pr)

        # should still fail if it's a dangling symlink
        os.unlink(path)
        os.symlink(os.path.join(apport.fileutils.report_dir, "pwned"), path)
        self.assertRaises(OSError, apport.fileutils.make_report_file, pr)

    def test_make_report_file_uid_0(self) -> None:
        """make_report_file(report, uid=0)"""
        report = problem_report.ProblemReport()
        report["ExecutablePath"] = "/bin/sh"
        with apport.fileutils.make_report_file(report, uid=0) as report_file:
            self.assertEqual(
                report_file.name, f"{apport.fileutils.report_dir}/_bin_sh.0.crash"
            )

    def test_check_files_md5(self) -> None:
        """check_files_md5()"""
        f1 = os.path.join(apport.fileutils.report_dir, "test 1.txt")
        f2 = os.path.join(apport.fileutils.report_dir, "test:2.txt")
        sumfile = os.path.join(apport.fileutils.report_dir, "sums.txt")
        with open(f1, "w", encoding="utf-8") as fd:
            fd.write("Some stuff")
        with open(f2, "w", encoding="utf-8") as fd:
            fd.write("More stuff")
        # use one relative and one absolute path in checksums file
        with open(sumfile, "w", encoding="utf-8") as fd:
            fd.write(
                f"""2e41290da2fa3f68bd3313174467e3b5  {f1[1:]}
f6423dfbc4faf022e58b4d3f5ff71a70  {f2}
"""
            )
        self.assertEqual(
            apport.fileutils.check_files_md5(sumfile), [], "correct md5sums"
        )

        with open(f1, "w", encoding="utf-8") as fd:
            fd.write("Some stuff!")
        self.assertEqual(
            apport.fileutils.check_files_md5(sumfile), [f1[1:]], "file 1 wrong"
        )
        with open(f2, "w", encoding="utf-8") as fd:
            fd.write("More stuff!")
        self.assertEqual(
            apport.fileutils.check_files_md5(sumfile),
            [f1[1:], f2],
            "files 1 and 2 wrong",
        )
        with open(f1, "w", encoding="utf-8") as fd:
            fd.write("Some stuff")
        self.assertEqual(
            apport.fileutils.check_files_md5(sumfile), [f2], "file 2 wrong"
        )

    def test_get_config(self) -> None:
        """get_config()"""
        # nonexisting
        apport.fileutils._CONFIG_FILE = "/nonexisting"
        self.assertIsNone(apport.fileutils.get_config("main", "foo"))
        self.assertEqual(apport.fileutils.get_config("main", "foo", "moo"), "moo")
        apport.fileutils._get_config_parser.cache_clear()

        # empty
        with tempfile.NamedTemporaryFile() as f:
            apport.fileutils._CONFIG_FILE = f.name
            self.assertIsNone(apport.fileutils.get_config("main", "foo"))
            self.assertEqual(apport.fileutils.get_config("main", "foo", "moo"), "moo")
            apport.fileutils._get_config_parser.cache_clear()

            # nonempty
            f.write(
                b"[main]\none=1\ntwo = TWO\nb1 = 1\nb2=False\n[spethial]\none= 99\n"
            )
            f.flush()
            self.assertIsNone(apport.fileutils.get_config("main", "foo"))
            self.assertEqual(apport.fileutils.get_config("main", "foo", "moo"), "moo")
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
                apport.fileutils.get_config("main", "b3", default=False, boolean=True),
                False,
            )
            self.assertEqual(apport.fileutils.get_config("spethial", "one"), "99")
            self.assertIsNone(apport.fileutils.get_config("spethial", "two"))
            self.assertEqual(
                apport.fileutils.get_config("spethial", "one", "moo"), "99"
            )
            self.assertEqual(
                apport.fileutils.get_config("spethial", "nope", "moo"), "moo"
            )
            apport.fileutils._get_config_parser.cache_clear()

            # interpolation
            f.write(b"[inter]\none=1\ntwo = TWO\ntest = %(two)s\n")
            f.flush()
            self.assertEqual(apport.fileutils.get_config("inter", "one"), "1")
            self.assertEqual(apport.fileutils.get_config("inter", "two"), "TWO")
            self.assertEqual(apport.fileutils.get_config("inter", "test"), "%(two)s")
            apport.fileutils._get_config_parser.cache_clear()

    def test_shared_libraries(self) -> None:
        """shared_libraries()"""
        libs = apport.fileutils.shared_libraries(sys.executable)
        self.assertGreater(len(libs), 3)
        self.assertIn("libc.so.6", libs)
        self.assertIn("libc.so.6", libs["libc.so.6"])
        self.assertTrue(os.path.exists(libs["libc.so.6"]))
        for library_name, library_path in libs.items():
            self.assertNotIn("vdso", library_name, libs)
            self.assertTrue(os.path.exists(library_path))

        self.assertEqual(apport.fileutils.shared_libraries("/non/existing"), {})
        self.assertEqual(apport.fileutils.shared_libraries("/etc"), {})
        self.assertEqual(apport.fileutils.shared_libraries("/etc/passwd"), {})

    def test_links_with_shared_library(self) -> None:
        """links_with_shared_library()"""
        self.assertTrue(
            apport.fileutils.links_with_shared_library(sys.executable, "libc")
        )
        self.assertTrue(
            apport.fileutils.links_with_shared_library(sys.executable, "libc.so.6")
        )
        self.assertFalse(
            apport.fileutils.links_with_shared_library(sys.executable, "libc.so.7")
        )
        self.assertFalse(
            apport.fileutils.links_with_shared_library(sys.executable, "libd")
        )
        self.assertFalse(
            apport.fileutils.links_with_shared_library("/non/existing", "libc")
        )
        self.assertFalse(apport.fileutils.links_with_shared_library("/etc", "libc"))
        self.assertFalse(
            apport.fileutils.links_with_shared_library("/etc/passwd", "libc")
        )

    def test_get_core_path(self) -> None:
        """get_core_path()"""
        boot_id = apport.fileutils.get_boot_id()

        # Basic test
        (core_name, core_path) = apport.fileutils.get_core_path(
            pid=123, exe="/usr/bin/test", uid=234, timestamp=222222
        )
        expected = f"core._usr_bin_test.234.{boot_id}.123.222222"
        expected_path = os.path.join(apport.fileutils.core_dir, expected)
        self.assertEqual(core_name, expected)
        self.assertEqual(core_path, expected_path)

        # Test dots in exe names
        (core_name, core_path) = apport.fileutils.get_core_path(
            pid=123, exe="/usr/bin/test.sh", uid=234, timestamp=222222
        )
        expected = f"core._usr_bin_test_sh.234.{boot_id}.123.222222"
        expected_path = os.path.join(apport.fileutils.core_dir, expected)
        self.assertEqual(core_name, expected)
        self.assertEqual(core_path, expected_path)

        # Test no exe name
        (core_name, core_path) = apport.fileutils.get_core_path(
            pid=123, exe=None, uid=234, timestamp=222222
        )
        expected = f"core.unknown.234.{boot_id}.123.222222"
        expected_path = os.path.join(apport.fileutils.core_dir, expected)
        self.assertEqual(core_name, expected)
        self.assertEqual(core_path, expected_path)

        # Test no uid
        (core_name, core_path) = apport.fileutils.get_core_path(
            pid=123, exe="/usr/bin/test", uid=None, timestamp=222222
        )
        expected = f"core._usr_bin_test.{str(os.getuid())}.{boot_id}.123.222222"
        expected_path = os.path.join(apport.fileutils.core_dir, expected)
        self.assertEqual(core_name, expected)
        self.assertEqual(core_path, expected_path)

    def test_clean_core_directory(self) -> None:
        """clean_core_directory()"""
        fake_uid = 5150
        extra_core_files = 4
        num_core_files = apport.fileutils.max_corefiles_per_uid + extra_core_files

        # Create some test files
        for x in range(num_core_files):
            core_path = apport.fileutils.get_core_path(
                pid=123 + x, exe="/usr/bin/test", uid=fake_uid, timestamp=222222 + x
            )[1]
            with open(core_path, "w", encoding="utf-8") as fd:
                fd.write("Some stuff")
                time.sleep(1)

        # Create a file with a different uid
        core_path = apport.fileutils.get_core_path(
            pid=231, exe="/usr/bin/test", uid=fake_uid + 1, timestamp=333333
        )[1]
        with open(core_path, "w", encoding="utf-8") as fd:
            fd.write("Some stuff")

        # Make sure we have the proper number of test files
        self.assertEqual(
            num_core_files, len(apport.fileutils.find_core_files_by_uid(fake_uid))
        )
        self.assertEqual(1, len(apport.fileutils.find_core_files_by_uid(fake_uid + 1)))

        # Clean out the directory
        apport.fileutils.clean_core_directory(fake_uid)

        # Make sure we have the proper number of test files. We should
        # have one less than max_corefiles_per_uid.
        self.assertEqual(
            apport.fileutils.max_corefiles_per_uid - 1,
            len(apport.fileutils.find_core_files_by_uid(fake_uid)),
        )
        self.assertEqual(1, len(apport.fileutils.find_core_files_by_uid(fake_uid + 1)))

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
