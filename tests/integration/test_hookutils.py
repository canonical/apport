"""Integration tests for the apport.hookutils module."""

# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import locale
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from unittest.mock import MagicMock

import apport.hookutils
import apport.report
import problem_report
from tests.helper import skip_if_command_is_missing
from tests.paths import local_test_environment


class T(unittest.TestCase):
    """Integration tests for the apport.hookutils module."""

    orig_environ: dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.orig_environ = os.environ.copy()
        os.environ |= local_test_environment()

    @classmethod
    def tearDownClass(cls) -> None:
        os.environ.clear()
        os.environ.update(cls.orig_environ)

    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.workdir)

    @unittest.mock.patch(
        "apport.hookutils._root_command_prefix", MagicMock(return_value=[])
    )
    def test_attach_root_command_outputs(self) -> None:
        """attach_root_command_outputs()

        To not require root for this test, execute only commands that do
        not need root and mock _root_command_prefix().
        """
        report = problem_report.ProblemReport()
        command_map = {
            "BinaryBlob": r"printf '\303\050'",
            "EchoFoo": "echo foo",
            "EchoNothing": "echo",
            "EchoUnicode": "echo 'hä?'",
        }

        apport.hookutils.attach_root_command_outputs(report, command_map)

        self.assertEqual(report["BinaryBlob"], b"\303\050")
        self.assertEqual(report["EchoFoo"], "foo")
        self.assertEqual(report["EchoUnicode"], "hä?")
        self.assertEqual(
            set(report.keys()),
            {"Date", "BinaryBlob", "EchoFoo", "EchoUnicode", "ProblemType"},
        )

    @skip_if_command_is_missing("/usr/bin/as")
    def test_module_license_evaluation(self) -> None:
        """Module licenses can be validated correctly."""
        # pylint: disable=protected-access

        def _build_ko(license_name: str) -> str:
            ko_filename = os.path.join(self.workdir, f"{license_name}.ko")
            with tempfile.NamedTemporaryFile(
                mode="w+", prefix=f"{license_name}-", suffix=".S"
            ) as asm:
                asm.write(f'.section .modinfo\n.string "license={license_name}"\n')
                asm.flush()
                subprocess.check_call(["/usr/bin/as", asm.name, "-o", ko_filename])
            return ko_filename

        good_ko = _build_ko("GPL")
        bad_ko = _build_ko("BAD")

        # test:
        #  - unfindable module
        #  - fake GPL module
        #  - fake BAD module

        # direct license check
        self.assertEqual(
            apport.hookutils._get_module_license("does-not-exist"), "invalid"
        )
        self.assertIn("GPL", apport.hookutils._get_module_license(good_ko))
        self.assertIn("BAD", apport.hookutils._get_module_license(bad_ko))

        # check via nonfree_kernel_modules logic
        with tempfile.NamedTemporaryFile(mode="w+") as temp:
            temp.write(f"isofs\ndoes-not-exist\n{good_ko}\n{bad_ko}\n")
            temp.flush()
            nonfree = apport.hookutils.nonfree_kernel_modules(temp.name)
        self.assertIn("does-not-exist", nonfree)
        self.assertNotIn(good_ko, nonfree)
        self.assertIn(bad_ko, nonfree)

    @skip_if_command_is_missing("/sbin/modinfo")
    def test_real_module_license_evaluation(self) -> None:
        """Module licenses can be validated correctly for real module."""
        # pylint: disable=protected-access
        isofs_license = apport.hookutils._get_module_license("isofs")
        if isofs_license == "invalid":
            self.skipTest("kernel module 'isofs' not available")

        self.assertIn("GPL", isofs_license)

        with tempfile.NamedTemporaryFile() as temp:
            temp.write(b"isofs\n")
            temp.flush()
            nonfree = apport.hookutils.nonfree_kernel_modules(temp.name)
        self.assertNotIn("isofs", nonfree)

    def test_attach_file(self) -> None:
        """attach_file()"""
        with open("/etc/passwd", encoding="utf-8") as f:
            passwd_contents = f.read().strip()
        with open("/etc/issue", encoding="utf-8") as f:
            issue_contents = f.read().strip()

        # default key name
        report = problem_report.ProblemReport()
        default_keys = set(report)
        apport.hookutils.attach_file(report, "/etc/passwd")
        self.assertEqual(set(report) - default_keys, {".etc.passwd"})
        self.assertEqual(report[".etc.passwd"], passwd_contents)

        # custom key name
        report = problem_report.ProblemReport()
        apport.hookutils.attach_file(report, "/etc/passwd", "Passwd")
        self.assertEqual(set(report) - default_keys, {"Passwd"})
        self.assertEqual(report["Passwd"], passwd_contents)

        # nonexisting file
        report = problem_report.ProblemReport()
        apport.hookutils.attach_file(report, "/nonexisting")
        self.assertEqual(set(report) - default_keys, {".nonexisting"})
        self.assertTrue(report[".nonexisting"].startswith("Error: "))

        # symlink
        link = os.path.join(self.workdir, "symlink")
        os.symlink("/etc/passwd", link)
        report = problem_report.ProblemReport()
        apport.hookutils.attach_file(report, link, "Symlink")
        self.assertEqual(set(report) - default_keys, {"Symlink"})
        self.assertTrue(report["Symlink"].startswith("Error: "))

        # directory symlink
        link = os.path.join(self.workdir, "dirsymlink")
        os.symlink("/etc", link)
        report = problem_report.ProblemReport()
        apport.hookutils.attach_file(report, os.path.join(link, "passwd"), "DirSymlink")
        self.assertEqual(set(report) - default_keys, {"DirSymlink"})
        self.assertTrue(report["DirSymlink"].startswith("Error: "))

        # directory traversal
        report = problem_report.ProblemReport()
        apport.hookutils.attach_file(report, "/etc/../etc/passwd", "Traversal")
        self.assertEqual(set(report) - default_keys, {"Traversal"})
        self.assertTrue(report["Traversal"].startswith("Error: "))

        # existing key
        report = problem_report.ProblemReport()
        apport.hookutils.attach_file(report, "/etc/passwd")
        apport.hookutils.attach_file(report, "/etc/passwd")
        self.assertEqual(set(report) - default_keys, {".etc.passwd"})
        self.assertEqual(report[".etc.passwd"], passwd_contents)

        apport.hookutils.attach_file(
            report, "/etc/issue", ".etc.passwd", overwrite=False
        )
        self.assertEqual(set(report) - default_keys, {".etc.passwd", ".etc.passwd_"})
        self.assertEqual(report[".etc.passwd"], passwd_contents)
        self.assertEqual(report[".etc.passwd_"], issue_contents)

    def test_attach_file_binary(self) -> None:
        """attach_file() for binary files"""
        myfile = os.path.join(self.workdir, "data")
        with open(myfile, "wb") as f:
            f.write(b"a\xc3\xb6b\xffx")

        report = problem_report.ProblemReport()
        apport.hookutils.attach_file(report, myfile, key="data")
        self.assertEqual(report["data"], b"a\xc3\xb6b\xffx")

        apport.hookutils.attach_file(report, myfile, key="data", force_unicode=True)
        self.assertEqual(report["data"], b"a\xc3\xb6b\xef\xbf\xbdx".decode("UTF-8"))

    def test_attach_file_if_exists(self) -> None:
        """attach_file_if_exists()"""
        with open("/etc/passwd", encoding="utf-8") as f:
            passwd_contents = f.read().strip()

        # default key name
        report = problem_report.ProblemReport()
        default_keys = set(report)
        apport.hookutils.attach_file_if_exists(report, "/etc/passwd")
        self.assertEqual(set(report) - default_keys, {".etc.passwd"})
        self.assertEqual(report[".etc.passwd"], passwd_contents)

        # custom key name
        report = problem_report.ProblemReport()
        apport.hookutils.attach_file_if_exists(report, "/etc/passwd", "Passwd")
        self.assertEqual(set(report) - default_keys, {"Passwd"})
        self.assertEqual(report["Passwd"], passwd_contents)

        # symlink
        link = os.path.join(self.workdir, "symlink")
        os.symlink("/etc/passwd", link)
        report = problem_report.ProblemReport()
        apport.hookutils.attach_file_if_exists(report, link, "Symlink")
        self.assertEqual(set(report) - default_keys, {"Symlink"})
        self.assertTrue(report["Symlink"].startswith("Error: "))

        # nonexisting file
        report = problem_report.ProblemReport()
        apport.hookutils.attach_file_if_exists(report, "/nonexisting")
        self.assertEqual(set(report) - default_keys, set())

        # directory traversal
        report = problem_report.ProblemReport()
        apport.hookutils.attach_file_if_exists(report, "/etc/../etc/passwd")
        self.assertEqual(set(report) - default_keys, set())

    def test_recent_syslog(self) -> None:
        """recent_syslog"""
        self.assertEqual(
            apport.hookutils.recent_syslog(re.compile("."), path="/nonexisting"), ""
        )
        self.assertEqual(
            apport.hookutils.recent_syslog(re.compile("ThisCantPossiblyHitAnything")),
            "",
        )
        if os.path.exists("/run/systemd/system") or os.access(
            "/var/log/syslog", os.R_OK
        ):
            self.assertNotEqual(len(apport.hookutils.recent_syslog(re.compile("."))), 0)

    def test_recent_syslog_overflow(self) -> None:
        """recent_syslog on a huge file"""
        log = os.path.join(self.workdir, "syslog")
        with open(log, "w", encoding="utf-8") as f:
            lines = 1000000
            while lines >= 0:
                f.write("Apr 20 11:30:00 komputer kernel: bogus message\n")
                lines -= 1

        mem_before = self._get_mem_usage()
        data = apport.hookutils.recent_syslog(re.compile("kernel"), path=log)
        mem_after = self._get_mem_usage()
        delta_kb = mem_after - mem_before
        sys.stderr.write(f"[Δ {delta_kb} kB] ")
        self.assertLess(delta_kb, 5000)

        self.assertRegex(data, "^Apr 20 11:30:00 komputer kernel: bogus message\n")
        self.assertGreater(len(data), 100000)
        self.assertLess(len(data), 1000000)

    @unittest.skipIf(
        apport.hookutils.apport.hookutils.in_session_of_problem(apport.report.Report())
        is None,
        "no logind session",
    )
    def test_in_session_of_problem(self) -> None:
        """in_session_of_problem()"""
        report = apport.report.Report(date="Sat Jan  1 12:00:00 2011")
        self.assertFalse(apport.hookutils.in_session_of_problem(report))

        report = apport.report.Report(date="Mon Oct 10 21:06:03 2009")
        self.assertFalse(apport.hookutils.in_session_of_problem(report))

        report = apport.report.Report()
        self.assertTrue(apport.hookutils.in_session_of_problem(report))

        self.assertIsNone(apport.hookutils.in_session_of_problem({}))

        orig_ctime = locale.getlocale(locale.LC_TIME)
        try:
            locale.setlocale(locale.LC_TIME, "C")

            report = apport.report.Report(date="Sat Jan  1 12:00:00 2011")
            self.assertFalse(apport.hookutils.in_session_of_problem(report))

            report = apport.report.Report(date="Mon Oct 10 21:06:03 2009")
            self.assertFalse(apport.hookutils.in_session_of_problem(report))

            report = apport.report.Report(date="Tue Jan  1 12:00:00 2038")
            self.assertTrue(apport.hookutils.in_session_of_problem(report))
        finally:
            locale.setlocale(locale.LC_TIME, orig_ctime)

    def test_xsession_errors(self) -> None:
        """xsession_errors()"""
        with open(
            os.path.join(self.workdir, ".xsession-errors"), "w", encoding="UTF-8"
        ) as f:
            f.write(
                """\
Loading profile from /etc/profile
gnome-session[1948]: WARNING: standard glib warning
EggSMClient-CRITICAL **: egg_sm_client_set_mode: standard glib assertion
24/02/2012 11:14:46 Sending credentials s3kr1t

** WARNING **: nonstandard warning

WARN  2012-02-24 11:23:47 unity <unknown>:0 some unicode ♥ ♪

GNOME_KEYRING_CONTROL=/tmp/keyring-u7hrD6

(gnome-settings-daemon:5115): Gdk-WARNING **: The program\
 'gnome-settings-daemon' received an X Window System error.
This probably reflects a bug in the program.
The error was 'BadMatch (invalid parameter attributes)'.
  (Details: serial 723 error_code 8 request_code 143 minor_code 22)
  (Note to programmers: normally, X errors are reported asynchronously;
   that is, you will receive the error a while after causing it.
   To debug your program, run it with the --sync command line
   option to change this behavior. You can then get a meaningful
   backtrace from your debugger if you break on the gdk_x_error() function.)"

GdkPixbuf-CRITICAL **: gdk_pixbuf_scale_simple: another standard glib assertion
"""
            )
        orig_home = os.environ.get("HOME")
        try:
            os.environ["HOME"] = self.workdir

            # explicit pattern
            pattern = re.compile("notfound")
            self.assertEqual(apport.hookutils.xsession_errors(pattern), "")

            pattern = re.compile(r"^\w+-CRITICAL")
            res = apport.hookutils.xsession_errors(pattern).splitlines()
            self.assertEqual(len(res), 2)
            self.assertTrue(res[0].startswith("EggSMClient-CRITICAL"))
            self.assertTrue(res[1].startswith("GdkPixbuf-CRITICAL"))

            # default pattern includes glib assertions and X Errors
            res = apport.hookutils.xsession_errors()
            self.assertNotIn("nonstandard warning", res)
            self.assertNotIn("keyring", res)
            self.assertNotIn("credentials", res)
            self.assertIn("WARNING: standard glib warning", res)
            self.assertIn("GdkPixbuf-CRITICAL", res)
            self.assertIn("'gnome-settings-daemon' received an X Window", res)
            self.assertIn("BadMatch", res)
            self.assertIn("serial 723", res)

        finally:
            if orig_home is not None:
                os.environ["HOME"] = orig_home
            else:
                os.unsetenv("HOME")

    @staticmethod
    @unittest.mock.patch(
        "apport.hookutils._root_command_prefix", MagicMock(return_value=[])
    )
    def test_no_crashes() -> None:
        """Functions do not crash (very shallow)."""
        report = problem_report.ProblemReport()
        apport.hookutils.attach_hardware(report)
        apport.hookutils.attach_alsa(report)
        apport.hookutils.attach_network(report)
        apport.hookutils.attach_wifi(report)
        apport.hookutils.attach_printing(report)
        apport.hookutils.attach_conffiles(report, "bash")
        apport.hookutils.attach_conffiles(report, "apport")
        apport.hookutils.attach_conffiles(report, "nonexisting")
        apport.hookutils.attach_default_grub(report)

    def test_command_output(self) -> None:
        """Test apport.hookutils.command_output."""
        orig_lcm = os.environ.get("LC_MESSAGES")
        os.environ["LC_MESSAGES"] = "en_US.UTF-8"
        try:
            # default mode: disable translations
            out = apport.hookutils.command_output(["env"])
            self.assertIn("LC_MESSAGES=C", out)

            # keep locale
            out = apport.hookutils.command_output(["env"], keep_locale=True)
            self.assertNotIn("LC_MESSAGES=C", out)
        finally:
            if orig_lcm is not None:
                os.environ["LC_MESSAGES"] = orig_lcm
            else:
                del os.environ["LC_MESSAGES"]

        # nonexisting binary
        out = apport.hookutils.command_output(["/non existing"])
        self.assertTrue(out.startswith("Error: [Errno 2]"))

        # stdin
        out = apport.hookutils.command_output(["cat"], input=b"hello")
        self.assertEqual(out, "hello")

    @staticmethod
    def _get_mem_usage() -> int:
        """Get current memory usage in kB."""
        with open("/proc/self/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmSize:"):
                    return int(line.split()[1])

        raise SystemError("did not find VmSize: in /proc/self/status")
