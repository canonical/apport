import atexit
import grp
import io
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import unittest.mock

import apport.packaging
import apport.report
import problem_report
from tests.helper import skip_if_command_is_missing
from tests.paths import patch_data_dir, restore_data_dir


class T(unittest.TestCase):
    # pylint: disable=protected-access

    @classmethod
    def setUpClass(cls):
        cls.orig_data_dir = patch_data_dir(apport.report)

    @classmethod
    def tearDownClass(cls):
        restore_data_dir(apport.report, cls.orig_data_dir)

    def wait_for_proc_cmdline(self, pid: int, timeout_sec=10.0) -> None:
        assert pid
        elapsed_time = 0.0
        while elapsed_time < timeout_sec:
            with open(f"/proc/{pid}/cmdline", encoding="utf-8") as fd:
                if fd.read():
                    return

            time.sleep(0.1)
            elapsed_time += 0.1

        self.fail(
            f"/proc/{pid}/cmdline not readable within"
            f" {int(elapsed_time)} seconds."
        )

    def test_add_package_info(self):
        """add_package_info()."""

        # determine bash version
        bashversion = apport.packaging.get_version("bash")

        pr = apport.report.Report()
        pr.add_package_info("bash")
        self.assertEqual(pr["Package"], "bash " + bashversion.strip())
        self.assertEqual(pr["SourcePackage"], "bash")
        self.assertIn("libc", pr["Dependencies"])

        # test without specifying a package, but with ExecutablePath
        pr = apport.report.Report()
        self.assertRaises(KeyError, pr.add_package_info)
        pr["ExecutablePath"] = "/bin/bash"
        pr.add_package_info()
        self.assertEqual(pr["Package"], "bash " + bashversion.strip())
        self.assertEqual(pr["SourcePackage"], "bash")
        self.assertIn("libc", pr["Dependencies"])
        # check for stray empty lines
        self.assertNotIn("\n\n", pr["Dependencies"])
        self.assertIn("PackageArchitecture", pr)

        pr = apport.report.Report()
        pr["ExecutablePath"] = "/nonexisting"
        pr.add_package_info()
        self.assertNotIn("Package", pr)

    def test_add_os_info(self):
        """add_os_info()."""

        pr = apport.report.Report()
        pr.add_os_info()
        self.assertTrue(pr["Uname"].startswith("Linux"))
        self.assertTrue(hasattr(pr["DistroRelease"], "startswith"))
        self.assertGreater(len(pr["DistroRelease"]), 5)
        self.assertNotEqual(pr["Architecture"], "")

        # does not overwrite an already existing uname
        pr["Uname"] = "foonux 1.2"
        dr = pr["DistroRelease"]
        del pr["DistroRelease"]
        pr.add_os_info()
        self.assertEqual(pr["Uname"], "foonux 1.2")
        self.assertEqual(pr["DistroRelease"], dr)

    def test_add_user_info(self):
        """add_user_info()."""

        pr = apport.report.Report()
        pr.add_user_info()
        self.assertIn("UserGroups", pr)

        # double-check that user group names are removed
        for g in pr["UserGroups"].split():
            if g == "N/A":
                continue
            self.assertLess(grp.getgrnam(g).gr_gid, 1000)
        self.assertNotIn(grp.getgrgid(os.getgid()).gr_name, pr["UserGroups"])

    def test_add_proc_info(self):
        """add_proc_info()."""

        # check without additional safe environment variables
        pr = apport.report.Report()
        self.assertEqual(pr.pid, None)
        pr.add_proc_info()
        self.assertEqual(pr.pid, os.getpid())
        self.assertTrue(
            set(
                ["ProcEnviron", "ProcMaps", "ProcCmdline", "ProcMaps"]
            ).issubset(set(pr.keys())),
            "report has required fields",
        )
        if "LANG" in os.environ:
            self.assertIn("LANG=" + os.environ["LANG"], pr["ProcEnviron"])
        else:
            self.assertNotIn("LANG=", pr["ProcEnviron"])
        self.assertNotIn("USER", pr["ProcEnviron"])
        self.assertNotIn("PWD", pr["ProcEnviron"])
        self.assertRegex(pr["ExecutablePath"], r".*\.py$")
        self.assertEqual(
            int(pr["ExecutableTimestamp"]),
            int(os.stat(pr["ExecutablePath"]).st_mtime),
        )

        # check with one additional safe environment variable
        pr = apport.report.Report()
        pr.add_proc_info(extraenv=["PWD"])
        self.assertNotIn("USER", pr["ProcEnviron"])
        if "PWD" in os.environ:
            self.assertIn("PWD=" + os.environ["PWD"], pr["ProcEnviron"])

        # check process from other user
        restore_root = False
        if os.getuid() == 0:
            # temporarily drop to normal user "mail"
            os.setresuid(8, 8, -1)
            restore_root = True
        pr = apport.report.Report()
        self.assertRaises(
            ValueError, pr.add_proc_info, 1
        )  # EPERM for init process
        if restore_root:
            os.setresuid(0, 0, -1)

        self.assertEqual(pr.pid, 1)
        self.assertIn("Pid:\t1", pr["ProcStatus"])
        self.assertTrue(
            pr["ProcEnviron"].startswith("Error:"), pr["ProcEnviron"]
        )
        self.assertNotIn("InterpreterPath", pr)

        # check escaping of ProcCmdline
        with subprocess.Popen(
            ["cat", "/foo bar", "\\h", "\\ \\", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as cat:
            self.wait_for_proc_cmdline(cat.pid)
            pr = apport.report.Report()
            pr.add_proc_info(pid=cat.pid)
            self.assertEqual(pr.pid, cat.pid)
            cat.communicate(b"\n")
        self.assertEqual(
            pr["ProcCmdline"], "cat /foo\\ bar \\\\h \\\\\\ \\\\ -"
        )
        self.assertEqual(pr["ExecutablePath"], "/usr/bin/cat")
        self.assertNotIn("InterpreterPath", pr)
        self.assertIn("/bin/cat", pr["ProcMaps"])
        self.assertIn("[stack]", pr["ProcMaps"])

        # check correct handling of executable symlinks
        assert os.path.islink(
            "/bin/sh"
        ), "/bin/sh needs to be a symlink for this test"
        with subprocess.Popen(["sh"], stdin=subprocess.PIPE) as shell:
            self.wait_for_proc_cmdline(shell.pid)
            pr = apport.report.Report()
            pr.pid = shell.pid
            pr.add_proc_info()
            shell.communicate(b"exit\n")
        self.assertNotIn("InterpreterPath", pr)
        self.assertEqual(pr["ExecutablePath"], os.path.realpath("/bin/sh"))
        self.assertEqual(
            int(pr["ExecutableTimestamp"]),
            int(os.stat(os.path.realpath("/bin/sh")).st_mtime),
        )

        # check correct handling of interpreted executables: shell
        with subprocess.Popen(
            ["zgrep", "foo"], stdin=subprocess.PIPE
        ) as zgrep:
            self.wait_for_proc_cmdline(zgrep.pid)
            pr = apport.report.Report()
            pr.add_proc_info(pid=zgrep.pid)
            zgrep.communicate(b"\n")
        self.assertTrue(pr["ExecutablePath"].endswith("bin/zgrep"))
        with open(pr["ExecutablePath"], encoding="utf-8") as fd:
            self.assertEqual(
                pr["InterpreterPath"],
                os.path.realpath(fd.readline().strip()[2:]),
            )
        self.assertEqual(
            int(pr["ExecutableTimestamp"]),
            int(os.stat(pr["ExecutablePath"]).st_mtime),
        )
        self.assertIn("[stack]", pr["ProcMaps"])

        # check correct handling of interpreted executables: python
        (fd, testscript) = tempfile.mkstemp()
        os.write(
            fd,
            textwrap.dedent(
                f"""\
                #!/usr/bin/{os.getenv('PYTHON', 'python3')}
                import sys
                sys.stdin.readline()
                """
            ).encode("ascii"),
        )
        os.close(fd)
        os.chmod(testscript, 0o755)
        with subprocess.Popen(
            [testscript], stdin=subprocess.PIPE, stderr=subprocess.PIPE
        ) as process:
            self.wait_for_proc_cmdline(process.pid)
            pr = apport.report.Report()
            pr.add_proc_info(pid=process.pid)
            process.communicate(b"\n")
        self.assertEqual(pr["ExecutablePath"], testscript)
        self.assertEqual(
            int(pr["ExecutableTimestamp"]), int(os.stat(testscript).st_mtime)
        )
        os.unlink(testscript)
        self.assertIn("python", pr["InterpreterPath"])
        self.assertIn("python", pr["ProcMaps"])
        self.assertIn("[stack]", pr["ProcMaps"])

        # test process is gone, should complain about nonexisting PID
        self.assertRaises(ValueError, pr.add_proc_info, process.pid)

    def test_add_proc_info_nonascii(self):
        """add_proc_info() for non-ASCII values"""

        lang = b"n\xc3\xb6_v\xc3\xb8lid"

        # one variable from each category (ignored/filtered/shown)
        with subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            env={
                "MYNAME": b"J\xc3\xbcrgen-Ren\xc3\xa9",
                "XDG_RUNTIME_DIR": b"/a\xc3\xafb",
                "LANG": lang,
            },
        ) as cat:
            time.sleep(0.1)
            r = apport.report.Report()
            r.add_proc_environ(pid=cat.pid)
            cat.communicate(b"")
        self.assertIn(lang, r["ProcEnviron"].encode("UTF-8"))
        self.assertIn("XDG_RUNTIME_DIR=<set>", r["ProcEnviron"])

    def test_add_proc_info_current_desktop(self):
        """add_proc_info() CurrentDesktop"""

        with subprocess.Popen(
            ["cat"], stdin=subprocess.PIPE, env={"LANG": "xx_YY.UTF-8"}
        ) as cat:
            time.sleep(0.1)
            r = apport.report.Report()
            r.add_proc_info(pid=cat.pid)
            cat.communicate(b"")
        self.assertEqual(r["ProcEnviron"], "LANG=xx_YY.UTF-8")
        self.assertNotIn("CurrentDesktop", r)

        with subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            env={"LANG": "xx_YY.UTF-8", "XDG_CURRENT_DESKTOP": "Pixel Pusher"},
        ) as cat:
            time.sleep(0.1)
            r = apport.report.Report()
            r.add_proc_info(pid=cat.pid)
            cat.communicate(b"")
        self.assertEqual(r["ProcEnviron"], "LANG=xx_YY.UTF-8")
        self.assertEqual(r["CurrentDesktop"], "Pixel Pusher")

    def test_add_path_classification(self):
        """classification of $PATH."""

        # system default
        with subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            env={
                "PATH": "/usr/local/sbin:/usr/local/bin"
                ":/usr/sbin:/usr/bin:/sbin:/bin:/usr/games"
            },
        ) as cat:
            time.sleep(0.1)
            r = apport.report.Report()
            r.add_proc_environ(pid=cat.pid)
            cat.communicate(b"")
        self.assertNotIn("PATH", r["ProcEnviron"])

        # no user paths
        with subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        ) as cat:
            time.sleep(0.1)
            r = apport.report.Report()
            r.add_proc_environ(pid=cat.pid)
            cat.communicate(b"")
        self.assertIn("PATH=(custom, no user)", r["ProcEnviron"])

        # user paths
        with subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            env={"PATH": "/home/pitti:/usr/sbin:/usr/bin:/sbin:/bin"},
        ) as cat:
            time.sleep(0.1)
            r = apport.report.Report()
            r.add_proc_environ(pid=cat.pid)
            cat.communicate(b"")
        self.assertIn("PATH=(custom, user)", r["ProcEnviron"])

    def test_check_interpreted(self):
        """_check_interpreted()."""

        restore_root = False
        if os.getuid() == 0:
            # temporarily drop to normal user "mail"
            os.setresuid(8, 8, -1)
            restore_root = True

        try:
            # standard ELF binary
            with tempfile.NamedTemporaryFile() as f:
                pr = apport.report.Report()
                pr["ExecutablePath"] = "/usr/bin/gedit"
                pr["ProcStatus"] = "Name:\tgedit"
                pr["ProcCmdline"] = "gedit\0/" + f.name
                pr._check_interpreted()
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/gedit")
            self.assertNotIn("InterpreterPath", pr)

            # bogus argv[0]
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/bin/dash"
            pr["ProcStatus"] = "Name:\tznonexisting"
            pr["ProcCmdline"] = "nonexisting\0/foo"
            pr._check_interpreted()
            self.assertEqual(pr["ExecutablePath"], "/bin/dash")
            self.assertNotIn("InterpreterPath", pr)

            # standard sh script
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/bin/dash"
            pr["ProcStatus"] = "Name:\tzgrep"
            pr["ProcCmdline"] = "/bin/sh\0/bin/zgrep\0foo"
            pr._check_interpreted()
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/zgrep")
            self.assertEqual(pr["InterpreterPath"], "/bin/dash")

            # standard sh script when being called explicitly with interpreter
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/bin/dash"
            pr["ProcStatus"] = "Name:\tdash"
            pr["ProcCmdline"] = "/bin/sh\0/bin/zgrep\0foo"
            pr._check_interpreted()
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/zgrep")
            self.assertEqual(pr["InterpreterPath"], "/bin/dash")

            # special case mono scheme: beagled-helper (use zgrep to make the
            # test suite work if mono or beagle are not installed)
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/mono"
            pr["ProcStatus"] = "Name:\tzgrep"
            pr["ProcCmdline"] = "zgrep\0--debug\0/bin/zgrep"
            pr._check_interpreted()
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/zgrep")
            self.assertEqual(pr["InterpreterPath"], "/usr/bin/mono")

            # special case mono scheme: banshee (use zgrep to make the test
            # suite work if mono or beagle are not installed)
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/mono"
            pr["ProcStatus"] = "Name:\tzgrep"
            pr["ProcCmdline"] = "zgrep\0/bin/zgrep"
            pr._check_interpreted()
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/zgrep")
            self.assertEqual(pr["InterpreterPath"], "/usr/bin/mono")

            # fail on files we shouldn't have access to when name!=argv[0]
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/python"
            pr["ProcStatus"] = "Name:\tznonexisting"
            pr["ProcCmdline"] = "python\0/etc/shadow"
            pr._check_interpreted()
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/python")
            self.assertNotIn("InterpreterPath", pr)

            # succeed on files we should have access to when name!=argv[0]
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/python"
            pr["ProcStatus"] = "Name:\tznonexisting"
            pr["ProcCmdline"] = "python\0/etc/passwd"
            pr._check_interpreted()
            self.assertEqual(pr["InterpreterPath"], "/usr/bin/python")
            self.assertEqual(pr["ExecutablePath"], "/etc/passwd")

            # fail on files we shouldn't have access to when name==argv[0]
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/python"
            pr["ProcStatus"] = "Name:\tshadow"
            pr["ProcCmdline"] = "../etc/shadow"
            pr._check_interpreted()
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/python")
            self.assertNotIn("InterpreterPath", pr)

            # succeed on files we should have access to when name==argv[0]
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/python"
            pr["ProcStatus"] = "Name:\tpasswd"
            pr["ProcCmdline"] = "../../etc/passwd"
            pr._check_interpreted()
            self.assertEqual(pr["InterpreterPath"], "/usr/bin/python")
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/../../etc/passwd")

            # interactive python process
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/python"
            pr["ProcStatus"] = "Name:\tpython"
            pr["ProcCmdline"] = "python"
            pr._check_interpreted()
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/python")
            self.assertNotIn("InterpreterPath", pr)

            # python script (abuse /bin/bash since it must exist)
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/python"
            pr["ProcStatus"] = "Name:\tbash"
            pr["ProcCmdline"] = "python\0/bin/bash"
            pr._check_interpreted()
            self.assertEqual(pr["InterpreterPath"], "/usr/bin/python")
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/bash")

            # python script with options (abuse /bin/bash since it must exist)
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/python"
            pr["ProcStatus"] = "Name:\tbash"
            pr["ProcCmdline"] = "python\0-OO\0/bin/bash"
            pr._check_interpreted()
            self.assertEqual(pr["InterpreterPath"], "/usr/bin/python")
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/bash")

            # python script with a versioned interpreter
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/python2.7"
            pr["ProcStatus"] = "Name:\tbash"
            pr["ProcCmdline"] = "/usr/bin/python\0/bin/bash"
            pr._check_interpreted()
            self.assertEqual(pr["InterpreterPath"], "/usr/bin/python2.7")
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/bash")

            # python script through -m
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/python2.7"
            pr["ProcStatus"] = "Name:\tpython"
            pr["ProcCmdline"] = "python\0-tt\0-m\0apport.report\0-v"
            pr._check_interpreted()
            self.assertEqual(pr["InterpreterPath"], "/usr/bin/python2.7")
            self.assertIn("apport/report.py", pr["ExecutablePath"])

            # python script through -m, with dot separator; top-level module
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/python3"
            pr["ProcStatus"] = "Name:\tpython3"
            pr["ProcCmdline"] = "python\0-m\0re\0install"
            pr._check_interpreted()
            self.assertEqual(pr["InterpreterPath"], "/usr/bin/python3")
            self.assertIn("re.py", pr["ExecutablePath"])

            # python script through -m, with dot separator; sub-level module
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/python3"
            pr["ProcStatus"] = "Name:\tpython3"
            pr["ProcCmdline"] = "python\0-m\0distutils.cmd\0foo"
            pr._check_interpreted()
            self.assertEqual(pr["InterpreterPath"], "/usr/bin/python3")
            self.assertIn("distutils/cmd.py", pr["ExecutablePath"])

            # Python script through -m, non-existent module
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/python3"
            pr["ProcStatus"] = "Name:\tpython3"
            pr["ProcCmdline"] = "python3\0-m\0nonexistent"
            pr._check_interpreted()
            self.assertNotIn("InterpreterPath", pr)
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/python3")
            self.assertIn("UnreportableReason", pr)

            # Python script through -m, non-existent sub-level module
            pr = apport.report.Report()
            pr["ExecutablePath"] = "/usr/bin/python3"
            pr["ProcStatus"] = "Name:\tpython3"
            pr["ProcCmdline"] = "python3\0-m\0apport.fileutils.nonexistent"
            pr._check_interpreted()
            self.assertNotIn("InterpreterPath", pr)
            self.assertEqual(pr["ExecutablePath"], "/usr/bin/python3")
            self.assertIn("UnreportableReason", pr)
        finally:
            if restore_root:
                os.setresuid(0, 0, -1)

    def test_check_interpreted_no_exec(self):
        """_check_interpreted() does not run module code"""

        # python script through -m, with dot separator; top-level module
        pr = apport.report.Report()
        pr["ExecutablePath"] = "/usr/bin/python"
        pr["ProcStatus"] = "Name:\tpython"
        pr["ProcCmdline"] = "python\0-m\0unittest.__main__"
        orig_argv = sys.argv
        try:
            sys.argv = ["/usr/bin/python", "-m", "unittest.__main__"]
            pr._check_interpreted()
        finally:
            sys.argv = orig_argv
        self.assertTrue(
            pr["ExecutablePath"].endswith("unittest/__main__.py"),
            pr["ExecutablePath"],
        )
        self.assertEqual(pr["InterpreterPath"], "/usr/bin/python")
        self.assertNotIn("UnreportableReason", pr)

    @skip_if_command_is_missing("twistd")
    def test_check_interpreted_twistd(self):
        """_check_interpreted() for programs ran through twistd"""

        # LP#761374
        pr = apport.report.Report()
        pr["ExecutablePath"] = "/usr/bin/python2.7"
        pr["ProcStatus"] = "Name:\ttwistd"
        pr["ProcCmdline"] = (
            "/usr/bin/python\0/usr/bin/twistd\0--uid\0root\0--gid\0root"
            "\0--pidfile\0/var/run/nanny.pid\0-r\0glib2\0--logfile"
            "\0/var/log/nanny.log\0-y\0/usr/share/nanny/daemon/nanny.tap"
        )
        pr._check_interpreted()
        self.assertEqual(
            pr["ExecutablePath"], "/usr/share/nanny/daemon/nanny.tap"
        )
        self.assertEqual(pr["InterpreterPath"], "/usr/bin/twistd")

        # LP#625039
        pr = apport.report.Report()
        pr["ExecutablePath"] = "/usr/bin/python2.7"
        pr["ProcStatus"] = "Name:\ttwistd"
        pr["ProcCmdline"] = (
            "/usr/bin/python\0/usr/bin/twistd"
            "\0--pidfile=/var/run/apt-p2p//apt-p2p.pid"
            "\0--rundir=/var/run/apt-p2p/\0--python=/usr/sbin/apt-p2p"
            "\0--logfile=/var/log/apt-p2p.log\0--no_save"
        )
        pr._check_interpreted()
        self.assertEqual(pr["ExecutablePath"], "/usr/sbin/apt-p2p")
        self.assertEqual(pr["InterpreterPath"], "/usr/bin/twistd")

        # somewhere from LP#755025
        pr = apport.report.Report()
        pr["ExecutablePath"] = "/usr/bin/python2.7"
        pr["ProcStatus"] = "Name:\ttwistd"
        pr["ProcCmdline"] = (
            "/usr/bin/python\0/usr/bin/twistd\0-r\0gtk2\0--pidfile"
            "\0/tmp/vmc.pid\0-noy"
            "\0/usr/share/vodafone-mobile-connect/gtk-tap.py\0-l\0/dev/null"
        )
        pr._check_interpreted()
        self.assertEqual(
            pr["ExecutablePath"],
            "/usr/share/vodafone-mobile-connect/gtk-tap.py",
        )
        self.assertEqual(pr["InterpreterPath"], "/usr/bin/twistd")

        # LP#725383 -> not practical to determine file here
        pr = apport.report.Report()
        pr["ExecutablePath"] = "/usr/bin/python2.7"
        pr["ProcStatus"] = "Name:\ttwistd"
        pr["ProcCmdline"] = (
            "/usr/bin/python\0/usr/bin/twistd"
            "\0--pidfile=/var/run/poker-network-server.pid"
            "\0--logfile=/var/log/poker-network-server.log\0--no_save"
            "\0--reactor=poll\0pokerserver"
        )
        pr._check_interpreted()
        self.assertIn("ExecutablePath", pr)
        self.assertIn("UnreportableReason", pr)
        self.assertEqual(pr["InterpreterPath"], "/usr/bin/twistd")

    @classmethod
    def _generate_sigsegv_report(
        cls,
        file=None,
        signal="11",
        code="""
int f(int x) {
    int* p = 0; *p = x;
    return x+1;
}
int main() { return f(42); }
""",
        args=None,
        extra_gcc_args=None,
    ):
        """Create a test executable which will die with a SIGSEGV, generate a
        core dump for it, create a problem report with those two arguments
        (ExecutablePath and CoreDump) and call add_gdb_info().

        If file is given, the report is written into it. Return
        the apport.report.Report.
        """
        if not extra_gcc_args:
            extra_gcc_args = []

        workdir = None
        orig_cwd = os.getcwd()
        pr = apport.report.Report()
        try:
            workdir = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, workdir)
            os.chdir(workdir)

            # create a test executable
            with open("crash.c", "w", encoding="utf-8") as fd:
                fd.write(code)
            assert (
                subprocess.call(
                    ["gcc"] + extra_gcc_args + ["-g", "crash.c", "-o", "crash"]
                )
                == 0
            )
            assert os.path.exists("crash")

            # call it through gdb and dump core
            subprocess.run(
                [
                    "gdb",
                    "--batch",
                    "-iex",
                    "set debuginfod enable off",
                    "--ex",
                    f"run{' ' + ' '.join(args) if args else ''}",
                    "--ex",
                    "generate-core-file core",
                    "./crash",
                ],
                check=False,
                env={"HOME": workdir},
                stdout=subprocess.PIPE,
            )
            cls._validate_core("core")

            pr["ExecutablePath"] = os.path.join(workdir, "crash")
            pr["CoreDump"] = (os.path.join(workdir, "core"),)
            pr["Signal"] = signal

            pr.add_gdb_info()
            if file:
                pr.write(file)
                file.flush()
        finally:
            os.chdir(orig_cwd)

        return pr

    @staticmethod
    def _validate_core(core_path):
        subprocess.check_call(["sync"])
        count = 0
        while count < 21:
            if os.path.exists(core_path):
                break
            time.sleep(0.5)
            count += 1
        assert os.path.exists(core_path)
        subprocess.run(
            ["readelf", "-n", core_path], check=True, stdout=subprocess.PIPE
        )

    def _validate_gdb_fields(self, pr):
        self.assertIn("Stacktrace", pr)
        self.assertIn("ThreadStacktrace", pr)
        self.assertIn("StacktraceTop", pr)
        self.assertIn("Registers", pr)
        self.assertIn("Disassembly", pr)
        self.assertNotIn("(no debugging symbols found)", pr["Stacktrace"])
        self.assertNotIn("Core was generated by", pr["Stacktrace"])
        self.assertNotRegex(pr["Stacktrace"], r"(?s)(^|.*\n)#0  [^\n]+\n#0  ")
        self.assertIn("#0  ", pr["Stacktrace"])
        self.assertRegex(pr["Stacktrace"], r"#[123]  0x")
        self.assertIn("#0  ", pr["ThreadStacktrace"])
        self.assertRegex(pr["ThreadStacktrace"], r"#[123]  0x")
        self.assertIn("Thread 1 (", pr["ThreadStacktrace"])
        self.assertLessEqual(len(pr["StacktraceTop"].splitlines()), 5)

    def test_add_gdb_info(self):
        """add_gdb_info() with core dump file reference."""

        pr = apport.report.Report()
        # should not throw an exception for missing fields
        pr.add_gdb_info()

        # normal crash
        pr = self._generate_sigsegv_report()
        self._validate_gdb_fields(pr)
        self.assertEqual(
            pr["StacktraceTop"],
            "f (x=42) at crash.c:3\nmain () at crash.c:6",
            pr["StacktraceTop"],
        )
        self.assertNotIn("AssertionMessage", pr)

        # crash where gdb generates output on stderr
        pr = self._generate_sigsegv_report(
            code=textwrap.dedent(
                """\
                int main() {
                    void     (*function)(void);
                    function = 0;
                    function();
                }
                """
            )
        )
        self._validate_gdb_fields(pr)
        self.assertNotEqual(pr["Disassembly"], "")
        self.assertNotIn("AssertionMessage", pr)

    def test_add_gdb_info_load(self):
        """add_gdb_info() with inline core dump."""

        with tempfile.NamedTemporaryFile() as rep:
            self._generate_sigsegv_report(rep)
            rep.seek(0)

            pr = apport.report.Report()
            with open(rep.name, "rb") as f:
                pr.load(f)
        pr.add_gdb_info()

        self._validate_gdb_fields(pr)

    def test_add_gdb_info_damaged(self):
        """add_gdb_info() with damaged core dump"""

        pr = self._generate_sigsegv_report()
        del pr["Stacktrace"]
        del pr["StacktraceTop"]
        del pr["ThreadStacktrace"]
        del pr["Disassembly"]

        # truncate core file
        os.truncate(pr["CoreDump"][0], 10000)

        self.assertRaises(OSError, pr.add_gdb_info)

        self.assertNotIn("Stacktrace", pr)
        self.assertNotIn("StacktraceTop", pr)
        self.assertIn(
            "not a core dump: file format not recognized",
            pr["UnreportableReason"],
        )

    def test_add_gdb_info_short_core_file(self):
        """add_gdb_info() with damaged core dump in gzip file"""

        pr = self._generate_sigsegv_report()
        del pr["Stacktrace"]
        del pr["StacktraceTop"]
        del pr["ThreadStacktrace"]
        del pr["Disassembly"]

        core = pr["CoreDump"][0]
        os.truncate(core, 10000)
        with open(core, "rb") as f:
            pr["CoreDump"] = problem_report.CompressedValue(f.read())

        self.assertRaises(OSError, pr.add_gdb_info)

        self.assertNotIn("Stacktrace", pr)
        self.assertNotIn("StacktraceTop", pr)
        self.assertTrue(
            pr["UnreportableReason"].startswith("Invalid core dump")
        )

    @unittest.mock.patch("gzip.GzipFile.read")
    def test_add_gdb_info_damaged_gz_core(self, mock_gzread):
        """add_gdb_info() with damaged gzip file of core dump"""

        pr = self._generate_sigsegv_report()
        del pr["Stacktrace"]
        del pr["StacktraceTop"]
        del pr["ThreadStacktrace"]
        del pr["Disassembly"]

        core = pr["CoreDump"][0]
        with open(core, "rb") as f:
            pr["CoreDump"] = problem_report.CompressedValue(f.read())
        mock_gzread.side_effect = EOFError(
            "Compressed file ended before the "
            "end-of-stream marker was reached"
        )
        self.assertRaises(EOFError, pr.add_gdb_info)
        self.assertTrue(mock_gzread.called)

        self.assertNotIn("Stacktrace", pr)
        self.assertNotIn("StacktraceTop", pr)

    def test_add_gdb_info_exe_missing(self):
        """add_gdb_info() with missing executable"""

        pr = self._generate_sigsegv_report()
        # change it to something that doesn't exist
        pr["ExecutablePath"] = pr["ExecutablePath"].replace("crash", "gone")

        self.assertRaises(FileNotFoundError, pr.add_gdb_info)

    @unittest.mock.patch(
        "apport.hookutils._root_command_prefix",
        unittest.mock.MagicMock(return_value=[]),
    )
    def test_add_zz_parse_segv_details(self):
        """parse-segv produces sensible results"""
        with tempfile.NamedTemporaryFile() as rep:
            self._generate_sigsegv_report(rep)
            rep.seek(0)

            pr = apport.report.Report()
            with open(rep.name, "rb") as f:
                pr.load(f)
            pr["Signal"] = "1"
            pr.add_hooks_info("fake_ui")
            self.assertNotIn("SegvAnalysis", pr)

            pr = apport.report.Report()
            with open(rep.name, "rb") as f:
                pr.load(f)
        pr.add_hooks_info("fake_ui")
        self.assertIn(
            'Skipped: missing required field "Architecture"',
            pr["SegvAnalysis"],
        )

        pr.add_os_info()
        pr.add_hooks_info("fake_ui")
        self.assertIn(
            'Skipped: missing required field "ProcMaps"', pr["SegvAnalysis"]
        )

        pr.add_proc_info()
        pr.add_hooks_info("fake_ui")
        if pr["Architecture"] in ["amd64", "i386"]:
            # data/general-hooks/parse_segv.py only runs for x86 and x86_64
            self.assertIn(
                "not located in a known VMA region", pr["SegvAnalysis"]
            )

    def test_add_gdb_info_script(self):
        """add_gdb_info() with a script."""

        # This needs to handle different bash locations across releases
        # to get the core filename right
        shell = os.path.realpath("/bin/bash")

        with tempfile.TemporaryDirectory() as workdir:
            script = os.path.join(workdir, "self-killing-script")

            # create a test script which produces a core dump for us
            with open(script, "w", encoding="utf-8") as fd:
                fd.write(
                    textwrap.dedent(
                        f"""\
                        #!{shell}
                        cd `dirname $0`
                        ulimit -c unlimited
                        kill -SEGV $$
                        """
                    )
                )
            os.chmod(script, 0o755)

            core_path = os.path.join(workdir, "core")
            try:
                subprocess.check_call(
                    [
                        "gdb",
                        "--batch",
                        "-iex",
                        "set debuginfod enable off",
                        "--ex",
                        f"run {script}",
                        "--ex",
                        f"generate-core-file {core_path}",
                        shell,
                    ],
                    env={"HOME": workdir},
                    stdout=subprocess.PIPE,
                )
            except FileNotFoundError as error:
                self.skipTest(f"{error.filename} not available")

            self._validate_core(core_path)

            pr = apport.report.Report()
            pr["InterpreterPath"] = "/bin/bash"
            pr["ExecutablePath"] = script
            pr["CoreDump"] = (core_path,)
            pr.add_gdb_info()

            self._validate_gdb_fields(pr)
            self.assertIn("in kill_builtin", pr["Stacktrace"])

    def test_add_gdb_info_abort(self):
        """add_gdb_info() with SIGABRT/assert()

        If these come from an assert(), the report should have the assertion
        message. Otherwise it should be marked as not reportable.
        """

        # abort with assert
        pr = self._generate_sigsegv_report(
            code=textwrap.dedent(
                """\
                #include <assert.h>
                int main() { assert(1 < 0); }
                """
            )
        )
        self._validate_gdb_fields(pr)
        self.assertIn(
            "crash.c:2: main: Assertion `1 < 0' failed.",
            pr["AssertionMessage"],
        )
        self.assertFalse(
            pr["AssertionMessage"].startswith("$"), pr["AssertionMessage"]
        )
        self.assertNotIn("= 0x", pr["AssertionMessage"])
        self.assertFalse(
            pr["AssertionMessage"].endswith("\\n"), pr["AssertionMessage"]
        )

        # abort with internal error
        pr = self._generate_sigsegv_report(
            code=textwrap.dedent(
                """\
                #include <string.h>
                int main(int argc, char *argv[]) {
                    char buf[8];
                    strcpy(buf, argv[1]);
                    return 0;
                }
                """
            ),
            args=["aaaaaaaaaaaaaaaa"],
            extra_gcc_args=["-O2", "-D_FORTIFY_SOURCE=2"],
        )
        self._validate_gdb_fields(pr)
        self.assertIn(
            "** buffer overflow detected ***: terminated",
            pr["AssertionMessage"],
        )
        self.assertFalse(
            pr["AssertionMessage"].startswith("$"), pr["AssertionMessage"]
        )
        self.assertNotIn("= 0x", pr["AssertionMessage"])
        self.assertFalse(
            pr["AssertionMessage"].endswith("\\n"), pr["AssertionMessage"]
        )

        # abort without assertion
        pr = self._generate_sigsegv_report(
            code=textwrap.dedent(
                """\
                #include <stdlib.h>
                int main() { abort(); }
                """
            )
        )
        self._validate_gdb_fields(pr)
        self.assertNotIn("AssertionMessage", pr)

    # disabled: __glib_assert_msg symbol not available (LP: #1689344)
    def disabled_test_add_gdb_info_abort_glib(self):
        """add_gdb_info() with glib assertion"""
        (fd, script) = tempfile.mkstemp()
        assert not os.path.exists("core")
        try:
            os.close(fd)

            # create a test script which produces a core dump for us
            with open(script, "w", encoding="utf-8") as fd:
                fd.write(
                    textwrap.dedent(
                        """\
                        #!/bin/sh
                        gcc -o $0.bin -x c - \
                            `pkg-config --cflags --libs glib-2.0` <<EOF
                        #include <glib.h>
                        int main() { g_assert_cmpint(1, <, 0); }
                        EOF
                        ulimit -c unlimited
                        $0.bin 2>/dev/null
                        """
                    )
                )
            # call script and verify that it gives us a proper ELF core dump
            assert subprocess.call(["/bin/sh", script]) != 0
            self._validate_core("core")

            pr = apport.report.Report()
            pr["ExecutablePath"] = script + ".bin"
            pr["CoreDump"] = ("core",)
            pr.add_gdb_info()
        finally:
            os.unlink(script)
            os.unlink(script + ".bin")
            os.unlink("core")

        self._validate_gdb_fields(pr)
        self.assertTrue(
            pr["AssertionMessage"].startswith(
                "ERROR:crash.c:2:main: assertion failed (1 < 0):"
            ),
            pr["AssertionMessage"],
        )

    # disabled: __nih_abort_msg symbol not available (LP: #1580601)
    def disabled_test_add_gdb_info_abort_libnih(self):
        """add_gdb_info() with libnih assertion"""
        (fd, script) = tempfile.mkstemp()
        assert not os.path.exists("core")
        try:
            os.close(fd)

            # create a test script which produces a core dump for us
            with open(script, "w", encoding="utf-8") as fd:
                fd.write(
                    textwrap.dedent(
                        """\
                        #!/bin/sh
                        gcc -o $0.bin -x c - \
                            `pkg-config --cflags --libs libnih` <<EOF
                        #include <libnih.h>
                        int main() { nih_assert (1 < 0); }
                        EOF
                        ulimit -c unlimited
                        $0.bin 2>/dev/null
                        """
                    )
                )
            # call script and verify that it gives us a proper ELF core dump
            assert subprocess.call(["/bin/sh", script]) != 0
            self._validate_core("core")

            pr = apport.report.Report()
            pr["ExecutablePath"] = script + ".bin"
            pr["CoreDump"] = ("core",)
            pr.add_gdb_info()
        finally:
            os.unlink(script)
            os.unlink(script + ".bin")
            os.unlink("core")

        self._validate_gdb_fields(pr)
        self.assertIn(
            "Assertion failed in main: 1 < 0", pr["AssertionMessage"]
        )

    def test_search_bug_patterns(self):
        """search_bug_patterns()."""

        # create some test patterns
        patterns = textwrap.dedent(
            """\
            <?xml version="1.0"?>
            <patterns>
                <pattern url="http://bugtracker.net/bugs/1">
                    <re key="Package">^bash </re>
                    <re key="Foo">ba.*r</re>
                </pattern>
                <pattern url="http://bugtracker.net/bugs/2">
                    <re key="Package">^bash 1-2$</re>
                    <re key="Foo">write_(hello|goodbye)</re>
                </pattern>
                <pattern url="http://bugtracker.net/bugs/3">
                    <re key="Package">^coreutils </re>
                    <re key="Bar">^1$</re>
                </pattern>
                <pattern url="http://bugtracker.net/bugs/4">
                    <re key="Package">^coreutils </re>
                    <re></re>
                    <re key="Bar">*</re> <!-- invalid RE -->
                    <re key="broken">+[1^</re>
                </pattern>
                <pattern url="http://bugtracker.net/bugs/5">
                    <re key="SourcePackage">^bazaar$</re>
                    <re key="LogFile">AssertionError</re>
                </pattern>
                <pattern url="http://bugtracker.net/bugs/6">
                    <re key="Package">^update-notifier</re>
                    <re key="LogFile">AssertionError ‽</re>
                </pattern>
            </patterns>"""
        ).encode()

        # invalid XML
        invalid = b'<?xml version="1.0"?>\n</patterns>'

        # create some reports
        r_bash = apport.report.Report()
        r_bash["Package"] = "bash 1-2"
        r_bash["Foo"] = "bazaar"

        r_bazaar = apport.report.Report()
        r_bazaar["Package"] = "bazaar 2-1"
        r_bazaar["SourcePackage"] = "bazaar"
        r_bazaar["LogFile"] = "AssertionError"

        r_coreutils = apport.report.Report()
        r_coreutils["Package"] = "coreutils 1"
        r_coreutils["Bar"] = "1"

        r_invalid = apport.report.Report()
        r_invalid["Package"] = "invalid 1"

        r_unicode = apport.report.Report()
        r_unicode["Package"] = "update-notifier"
        r_unicode["LogFile"] = "AssertionError ‽"

        with tempfile.NamedTemporaryFile(prefix="apport-") as bug_pattern:
            bug_pattern.write(patterns)
            bug_pattern.flush()
            pattern_url = f"file://{bug_pattern.name}"

            # positive match cases
            self.assertEqual(
                r_bash.search_bug_patterns(pattern_url),
                "http://bugtracker.net/bugs/1",
            )
            r_bash["Foo"] = "write_goodbye"
            self.assertEqual(
                r_bash.search_bug_patterns(pattern_url),
                "http://bugtracker.net/bugs/2",
            )
            self.assertEqual(
                r_coreutils.search_bug_patterns(pattern_url),
                "http://bugtracker.net/bugs/3",
            )
            self.assertEqual(
                r_bazaar.search_bug_patterns(pattern_url),
                "http://bugtracker.net/bugs/5",
            )
            self.assertEqual(
                r_unicode.search_bug_patterns(pattern_url),
                "http://bugtracker.net/bugs/6",
            )

            # also works for CompressedValues
            r_bash_compressed = r_bash.copy()
            r_bash_compressed["Foo"] = problem_report.CompressedValue(
                b"bazaar"
            )
            self.assertEqual(
                r_bash_compressed.search_bug_patterns(pattern_url),
                "http://bugtracker.net/bugs/1",
            )

            # also works for binary values
            r_bash_utf8 = r_bash.copy()
            r_bash_utf8["Foo"] = b"bazaar"
            self.assertEqual(
                r_bash_utf8.search_bug_patterns(pattern_url),
                "http://bugtracker.net/bugs/1",
            )

            # negative match cases
            r_bash["Package"] = "bash-static 1-2"
            self.assertEqual(r_bash.search_bug_patterns(pattern_url), None)
            r_bash["Package"] = "bash 1-21"
            self.assertEqual(
                r_bash.search_bug_patterns(pattern_url),
                None,
                "does not match on wrong bash version",
            )
            r_bash["Foo"] = "zz"
            self.assertEqual(
                r_bash.search_bug_patterns(pattern_url),
                None,
                "does not match on wrong Foo value",
            )
            r_bash["Foo"] = b"zz"
            self.assertEqual(
                r_bash.search_bug_patterns(pattern_url),
                None,
                "does not match on wrong Foo UTF-8 value",
            )
            r_bash["Foo"] = b"\x01\xFF"
            self.assertEqual(
                r_bash.search_bug_patterns(pattern_url),
                None,
                "does not match on wrong Foo binary value",
            )
            r_coreutils["Bar"] = "11"
            self.assertEqual(
                r_coreutils.search_bug_patterns(pattern_url),
                None,
                "does not match on wrong Bar value",
            )
            r_bazaar["SourcePackage"] = "launchpad"
            self.assertEqual(
                r_bazaar.search_bug_patterns(pattern_url),
                None,
                "does not match on wrong source package",
            )
            r_bazaar["LogFile"] = ""
            self.assertEqual(
                r_bazaar.search_bug_patterns(pattern_url),
                None,
                "does not match on empty attribute",
            )

            # various errors to check for robustness (no exceptions, just None
            # return value)
            del r_coreutils["Bar"]
            self.assertEqual(
                r_coreutils.search_bug_patterns(pattern_url),
                None,
                "does not match on nonexisting key",
            )

        with tempfile.NamedTemporaryFile(prefix="apport-") as bug_pattern:
            bug_pattern.write(invalid)
            bug_pattern.flush()
            self.assertEqual(
                r_invalid.search_bug_patterns("file://" + bug_pattern.name),
                None,
                "gracefully handles invalid XML",
            )
        r_coreutils["Package"] = "other 2"
        self.assertEqual(
            r_bash.search_bug_patterns("file:///nonexisting/directory/"),
            None,
            "gracefully handles nonexisting base path",
        )
        # existing host, but no bug patterns
        self.assertEqual(
            r_bash.search_bug_patterns("http://security.ubuntu.com/"),
            None,
            "gracefully handles base path without bug patterns",
        )
        # nonexisting host
        self.assertEqual(
            r_bash.search_bug_patterns("http://nonexisting.domain/"),
            None,
            "gracefully handles nonexisting URL domain",
        )

    def test_add_hooks_info(self):
        """add_hooks_info()."""

        orig_general_hook_dir = apport.report.GENERAL_HOOK_DIR
        apport.report.GENERAL_HOOK_DIR = tempfile.mkdtemp()
        orig_package_hook_dir = apport.report.PACKAGE_HOOK_DIR
        apport.report.PACKAGE_HOOK_DIR = tempfile.mkdtemp()
        try:
            with open(
                os.path.join(apport.report.PACKAGE_HOOK_DIR, "foo.py"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write(
                    textwrap.dedent(
                        """\
                        import sys
                        def add_info(report):
                            report['Field1'] = 'Field 1'
                            report['Field2'] = 'Field 2\\nBla'
                            if 'Spethial' in report:
                                raise StopIteration
                        """
                    )
                )

            with open(
                os.path.join(apport.report.GENERAL_HOOK_DIR, "foo1.py"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write(
                    textwrap.dedent(
                        """\
                        def add_info(report):
                            report['CommonField1'] = 'CommonField 1'
                            if report['Package'] == 'commonspethial':
                                raise StopIteration
                        """
                    )
                )
            with open(
                os.path.join(apport.report.GENERAL_HOOK_DIR, "foo2.py"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write(
                    textwrap.dedent(
                        """\
                        def add_info(report):
                            report['CommonField2'] = 'CommonField 2'
                        """
                    )
                )
            with open(
                os.path.join(apport.report.GENERAL_HOOK_DIR, "foo3.py"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write(
                    textwrap.dedent(
                        """\
                        def add_info(report, ui):
                            report['CommonField3'] = str(ui)
                        """
                    )
                )

            # should only catch .py files
            with open(
                os.path.join(apport.report.GENERAL_HOOK_DIR, "notme"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write(
                    textwrap.dedent(
                        """\
                        def add_info(report):
                            report['BadField'] = 'XXX'
                        """
                    )
                )
            r = apport.report.Report()
            r["Package"] = "bar"
            # should not throw any exceptions
            self.assertEqual(r.add_hooks_info("fake_ui"), False)
            self.assertEqual(
                set(r.keys()),
                set(
                    [
                        "ProblemType",
                        "Date",
                        "Package",
                        "CommonField1",
                        "CommonField2",
                        "CommonField3",
                    ]
                ),
                "report has required fields",
            )

            r = apport.report.Report()
            r["Package"] = "baz 1.2-3"
            # should not throw any exceptions
            self.assertEqual(r.add_hooks_info("fake_ui"), False)
            self.assertEqual(
                set(r.keys()),
                set(
                    [
                        "ProblemType",
                        "Date",
                        "Package",
                        "CommonField1",
                        "CommonField2",
                        "CommonField3",
                    ]
                ),
                "report has required fields",
            )

            r = apport.report.Report()
            r["Package"] = "foo"
            self.assertEqual(r.add_hooks_info("fake_ui"), False)
            self.assertEqual(
                set(r.keys()),
                set(
                    [
                        "ProblemType",
                        "Date",
                        "Package",
                        "Field1",
                        "Field2",
                        "CommonField1",
                        "CommonField2",
                        "CommonField3",
                    ]
                ),
                "report has required fields",
            )
            self.assertEqual(r["Field1"], "Field 1")
            self.assertEqual(r["Field2"], "Field 2\nBla")
            self.assertEqual(r["CommonField1"], "CommonField 1")
            self.assertEqual(r["CommonField2"], "CommonField 2")
            self.assertEqual(r["CommonField3"], "fake_ui")

            r = apport.report.Report()
            r["Package"] = "foo 4.5-6"
            self.assertEqual(r.add_hooks_info("fake_ui"), False)
            self.assertEqual(
                set(r.keys()),
                set(
                    [
                        "ProblemType",
                        "Date",
                        "Package",
                        "Field1",
                        "Field2",
                        "CommonField1",
                        "CommonField2",
                        "CommonField3",
                    ]
                ),
                "report has required fields",
            )
            self.assertEqual(r["Field1"], "Field 1")
            self.assertEqual(r["Field2"], "Field 2\nBla")
            self.assertEqual(r["CommonField1"], "CommonField 1")
            self.assertEqual(r["CommonField2"], "CommonField 2")

            # test hook abort
            r["Spethial"] = "1"
            self.assertEqual(r.add_hooks_info("fake_ui"), True)
            r = apport.report.Report()
            r["Package"] = "commonspethial"
            self.assertEqual(r.add_hooks_info("fake_ui"), True)

            # source package hook
            with open(
                os.path.join(apport.report.PACKAGE_HOOK_DIR, "source_foo.py"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write(
                    textwrap.dedent(
                        """\
                        def add_info(report, ui):
                            report['Field1'] = 'Field 1'
                            report['Field2'] = 'Field 2\\nBla'
                            if report['Package'] == 'spethial':
                                raise StopIteration
                        """
                    )
                )
            r = apport.report.Report()
            r["SourcePackage"] = "foo"
            r["Package"] = "libfoo 3"
            self.assertEqual(r.add_hooks_info("fake_ui"), False)
            self.assertEqual(
                set(r.keys()),
                set(
                    [
                        "ProblemType",
                        "Date",
                        "Package",
                        "SourcePackage",
                        "Field1",
                        "Field2",
                        "CommonField1",
                        "CommonField2",
                        "CommonField3",
                    ]
                ),
                "report has required fields",
            )
            self.assertEqual(r["Field1"], "Field 1")
            self.assertEqual(r["Field2"], "Field 2\nBla")
            self.assertEqual(r["CommonField1"], "CommonField 1")
            self.assertEqual(r["CommonField2"], "CommonField 2")
            self.assertEqual(r["CommonField3"], "fake_ui")

            # test hook abort
            r["Package"] = "spethial"
            self.assertEqual(r.add_hooks_info("fake_ui"), True)

        finally:
            shutil.rmtree(apport.report.GENERAL_HOOK_DIR)
            shutil.rmtree(apport.report.PACKAGE_HOOK_DIR)
            apport.report.GENERAL_HOOK_DIR = orig_general_hook_dir
            apport.report.PACKAGE_HOOK_DIR = orig_package_hook_dir

    def test_add_hooks_info_opt(self):
        """add_hooks_info() for a package in /opt"""

        orig_general_hook_dir = apport.report.GENERAL_HOOK_DIR
        apport.report.GENERAL_HOOK_DIR = tempfile.mkdtemp()
        orig_package_hook_dir = apport.report.PACKAGE_HOOK_DIR
        apport.report.PACKAGE_HOOK_DIR = tempfile.mkdtemp()
        orig_opt_dir = apport.report._opt_dir
        apport.report._opt_dir = tempfile.mkdtemp()
        try:
            opt_hook_dir = os.path.join(
                apport.report._opt_dir,
                "foolabs.example.com",
                "foo",
                "share",
                "apport",
                "package-hooks",
            )
            os.makedirs(opt_hook_dir)
            with open(
                os.path.join(opt_hook_dir, "source_foo.py"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write(
                    textwrap.dedent(
                        """\
                        def add_info(report, ui):
                            report['SourceHook'] = '1'
                        """
                    )
                )
            with open(
                os.path.join(opt_hook_dir, "foo-bin.py"), "w", encoding="utf-8"
            ) as fd:
                fd.write(
                    textwrap.dedent(
                        """\
                        def add_info(report, ui):
                            report['BinHook'] = '1'
                        """
                    )
                )

            r = apport.report.Report()
            r["Package"] = "foo-bin 0.2"
            r["SourcePackage"] = "foo"
            r["ExecutablePath"] = (
                "%s/foolabs.example.com/foo/bin/frob" % apport.report._opt_dir
            )

            self.assertEqual(r.add_hooks_info("fake_ui"), False)
            self.assertEqual(r["SourceHook"], "1")
        finally:
            shutil.rmtree(apport.report.GENERAL_HOOK_DIR)
            shutil.rmtree(apport.report.PACKAGE_HOOK_DIR)
            shutil.rmtree(apport.report._opt_dir)
            apport.report.GENERAL_HOOK_DIR = orig_general_hook_dir
            apport.report.PACKAGE_HOOK_DIR = orig_package_hook_dir
            apport.report._opt_dir = orig_opt_dir

    @unittest.mock.patch("sys.stderr", new_callable=io.StringIO)
    def test_add_hooks_info_errors(self, stderr_mock):
        """add_hooks_info() with errors in hooks"""

        orig_general_hook_dir = apport.report.GENERAL_HOOK_DIR
        apport.report.GENERAL_HOOK_DIR = tempfile.mkdtemp()
        orig_package_hook_dir = apport.report.PACKAGE_HOOK_DIR
        apport.report.PACKAGE_HOOK_DIR = tempfile.mkdtemp()
        try:
            with open(
                os.path.join(apport.report.PACKAGE_HOOK_DIR, "fooprogs.py"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write(
                    textwrap.dedent(
                        """\
                        def add_info(report, ui):
                            report['BinHookBefore'] = '1'
                            1/0
                            report['BinHookAfter'] = '1'
                        """
                    )
                )
            with open(
                os.path.join(apport.report.PACKAGE_HOOK_DIR, "source_foo.py"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write(
                    textwrap.dedent(
                        """\
                        def add_info(report, ui):
                            report['SourceHookBefore'] = '1'
                            unknown()
                            report['SourceHookAfter'] = '1'
                        """
                    )
                )

            r = apport.report.Report()
            r["Package"] = "fooprogs 0.2"
            r["SourcePackage"] = "foo"
            r["ExecutablePath"] = "/bin/foo-cli"

            self.assertEqual(r.add_hooks_info("fake_ui"), False)

            # should have the data until the crash
            self.assertEqual(r["BinHookBefore"], "1")
            self.assertEqual(r["SourceHookBefore"], "1")

            # should print the exceptions to stderr
            err = stderr_mock.getvalue()
            self.assertIn("ZeroDivisionError:", err)
            self.assertIn("name 'unknown' is not defined", err)

            # should also add the exceptions to the report
            self.assertIn("NameError:", r["HookError_source_foo"])
            self.assertIn("line 3, in add_info", r["HookError_source_foo"])
            self.assertNotIn("ZeroDivisionError", r["HookError_source_foo"])

            self.assertIn("ZeroDivisionError:", r["HookError_fooprogs"])
            self.assertIn("line 3, in add_info", r["HookError_source_foo"])
            self.assertNotIn("NameError:", r["HookError_fooprogs"])
        finally:
            shutil.rmtree(apport.report.GENERAL_HOOK_DIR)
            shutil.rmtree(apport.report.PACKAGE_HOOK_DIR)
            apport.report.GENERAL_HOOK_DIR = orig_general_hook_dir
            apport.report.PACKAGE_HOOK_DIR = orig_package_hook_dir

    def test_ignoring(self):
        """mark_ignore() and check_ignored()."""

        orig_ignore_file = apport.report.apport.report._ignore_file
        workdir = tempfile.mkdtemp()
        apport.report.apport.report._ignore_file = os.path.join(
            workdir, "ignore.xml"
        )
        try:
            with open(
                os.path.join(workdir, "bash"), "w", encoding="utf-8"
            ) as fd:
                fd.write("bash")
            with open(
                os.path.join(workdir, "crap"), "w", encoding="utf-8"
            ) as fd:
                fd.write("crap")

            bash_rep = apport.report.Report()
            bash_rep["ExecutablePath"] = os.path.join(workdir, "bash")
            crap_rep = apport.report.Report()
            crap_rep["ExecutablePath"] = os.path.join(workdir, "crap")
            # must be able to deal with executables that do not exist any more
            cp_rep = apport.report.Report()
            cp_rep["ExecutablePath"] = os.path.join(workdir, "cp")

            # no ignores initially
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)
            self.assertEqual(cp_rep.check_ignored(), False)

            # ignore crap now
            crap_rep.mark_ignore()
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), True)
            self.assertEqual(cp_rep.check_ignored(), False)

            # ignore bash now
            bash_rep.mark_ignore()
            self.assertEqual(bash_rep.check_ignored(), True)
            self.assertEqual(crap_rep.check_ignored(), True)
            self.assertEqual(cp_rep.check_ignored(), False)

            # poke crap so that it has a newer timestamp
            time.sleep(1)
            with open(
                os.path.join(workdir, "crap"), "w", encoding="utf-8"
            ) as fd:
                fd.write("crapnew")
            self.assertEqual(bash_rep.check_ignored(), True)
            self.assertEqual(crap_rep.check_ignored(), False)
            self.assertEqual(cp_rep.check_ignored(), False)

            # do not complain about an empty ignore file
            with open(
                apport.report.apport.report._ignore_file, "w", encoding="utf-8"
            ) as fd:
                fd.write("")
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)
            self.assertEqual(cp_rep.check_ignored(), False)

            # does not crash if the executable went away under our feet
            crap_rep["ExecutablePath"] = "/non existing"
            crap_rep.mark_ignore()
            self.assertEqual(
                os.path.getsize(apport.report.apport.report._ignore_file), 0
            )
        finally:
            shutil.rmtree(workdir)
            apport.report.apport.report._ignore_file = orig_ignore_file

    def test_blacklisting(self):
        """check_ignored() for system-wise blacklist."""

        orig_blacklist_dir = apport.report._blacklist_dir
        apport.report._blacklist_dir = tempfile.mkdtemp()
        orig_ignore_file = apport.report._ignore_file
        apport.report._ignore_file = "/nonexistant"
        try:
            bash_rep = apport.report.Report()
            bash_rep["ExecutablePath"] = "/bin/bash"
            crap_rep = apport.report.Report()
            crap_rep["ExecutablePath"] = "/bin/crap"

            # no ignores initially
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)

            # should not stumble over comments
            with open(
                os.path.join(apport.report._blacklist_dir, "README"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write("# Ignore file\n#/bin/bash\n")

            # no ignores on nonmatching paths
            with open(
                os.path.join(apport.report._blacklist_dir, "bl1"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write("/bin/bas\n/bin/bashh\nbash\nbin/bash\n")
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)

            # ignore crap now
            with open(
                os.path.join(apport.report._blacklist_dir, "bl_2"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write("/bin/crap\n")
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), True)

            # ignore bash now
            with open(
                os.path.join(apport.report._blacklist_dir, "bl1"),
                "a",
                encoding="utf-8",
            ) as fd:
                fd.write("/bin/bash\n")
            self.assertEqual(bash_rep.check_ignored(), True)
            self.assertEqual(crap_rep.check_ignored(), True)
        finally:
            shutil.rmtree(apport.report._blacklist_dir)
            apport.report._blacklist_dir = orig_blacklist_dir
            apport.report._ignore_file = orig_ignore_file

    def test_whitelisting(self):
        """check_ignored() for system-wise whitelist."""

        orig_whitelist_dir = apport.report._whitelist_dir
        apport.report._whitelist_dir = tempfile.mkdtemp()
        orig_ignore_file = apport.report.apport.report._ignore_file
        apport.report.apport.report._ignore_file = "/nonexistant"
        try:
            bash_rep = apport.report.Report()
            bash_rep["ExecutablePath"] = "/bin/bash"
            crap_rep = apport.report.Report()
            crap_rep["ExecutablePath"] = "/bin/crap"

            # no ignores without any whitelist
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)

            # should not stumble over comments
            with open(
                os.path.join(apport.report._whitelist_dir, "README"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write("# Ignore file\n#/bin/bash\n")

            # accepts matching paths
            with open(
                os.path.join(apport.report._whitelist_dir, "wl1"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write("/bin/bash\n")
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), True)

            # also accept crap now
            with open(
                os.path.join(apport.report._whitelist_dir, "wl_2"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write("/bin/crap\n")
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)

            # only complete matches accepted
            with open(
                os.path.join(apport.report._whitelist_dir, "wl1"),
                "w",
                encoding="utf-8",
            ) as fd:
                fd.write("/bin/bas\n/bin/bashh\nbash\n")
            self.assertEqual(bash_rep.check_ignored(), True)
            self.assertEqual(crap_rep.check_ignored(), False)
        finally:
            shutil.rmtree(apport.report._whitelist_dir)
            apport.report._whitelist_dir = orig_whitelist_dir
            apport.report.apport.report._ignore_file = orig_ignore_file

    def test_obsolete_packages(self):
        """obsolete_packages()."""

        report = apport.report.Report()
        self.assertEqual(report.obsolete_packages(), [])

        # should work without Dependencies
        report["Package"] = "bash 0"
        self.assertEqual(report.obsolete_packages(), ["bash"])
        report["Package"] = "bash 0 [modified: /bin/bash]"
        self.assertEqual(report.obsolete_packages(), ["bash"])
        report["Package"] = "bash " + apport.packaging.get_available_version(
            "bash"
        )
        self.assertEqual(report.obsolete_packages(), [])

        report["Dependencies"] = "coreutils 0\ncron 0\n"
        self.assertEqual(report.obsolete_packages(), ["coreutils", "cron"])

        report["Dependencies"] = (
            "coreutils %s [modified: /bin/mount]\ncron 0\n"
            % apport.packaging.get_available_version("coreutils")
        )
        self.assertEqual(report.obsolete_packages(), ["cron"])

        report["Dependencies"] = "coreutils %s\ncron %s\n" % (
            apport.packaging.get_available_version("coreutils"),
            apport.packaging.get_available_version("cron"),
        )
        self.assertEqual(report.obsolete_packages(), [])

    def test_address_to_offset_live(self):
        """_address_to_offset() for current /proc/pid/maps"""

        # this primarily checks that the parser actually gets along with the
        # real /proc/pid/maps and not just with our static test case above
        pr = apport.report.Report()
        pr.add_proc_info()
        self.assertEqual(pr._address_to_offset(0), None)
        res = pr._address_to_offset(
            int(pr["ProcMaps"].split("-", 1)[0], 16) + 5
        )
        self.assertEqual(res.split("+", 1)[1], "5")
        self.assertIn("python", res.split("+", 1)[0])

    def test_get_logind_session(self):
        ret = apport.Report.get_logind_session(os.getpid())
        if ret is None:
            # ensure that we don't run under logind, and thus the None is
            # justified
            with open("/proc/self/cgroup", encoding="utf-8") as f:
                contents = f.read()
            sys.stdout.write("[not running under logind] ")
            sys.stdout.flush()
            self.assertNotIn("name=systemd:/user", contents)
            return

        (session, timestamp) = ret
        self.assertNotEqual(session, "")
        # session start must be >= 2014-01-01 and <= "now"
        self.assertLess(timestamp, time.time())
        self.assertGreater(
            timestamp, time.mktime(time.strptime("2014-01-01", "%Y-%m-%d"))
        )

    def test_get_logind_session_fd(self):
        proc_pid_fd = os.open(
            "/proc/%s" % os.getpid(), os.O_RDONLY | os.O_PATH | os.O_DIRECTORY
        )
        self.addCleanup(os.close, proc_pid_fd)
        ret = apport.Report.get_logind_session(proc_pid_fd=proc_pid_fd)
        if ret is None:
            # ensure that we don't run under logind, and thus the None is
            # justified
            with open("/proc/self/cgroup", encoding="utf-8") as f:
                contents = f.read()
            sys.stdout.write("[not running under logind] ")
            sys.stdout.flush()
            self.assertNotIn("name=systemd:/user", contents)
            return

        (session, timestamp) = ret
        self.assertNotEqual(session, "")
        # session start must be >= 2014-01-01 and <= "now"
        self.assertLess(timestamp, time.time())
        self.assertGreater(
            timestamp, time.mktime(time.strptime("2014-01-01", "%Y-%m-%d"))
        )

    def test_command_output_passes_env(self):
        fake_env = {"GCONV_PATH": "/tmp"}
        out = apport.report._command_output(["env"], env=fake_env)
        self.assertIn(b"GCONV_PATH", out)

    def test_extrapath_preferred(self):
        """if extrapath is passed it is preferred"""
        bin_true = apport.report._which_extrapath("true", None)
        # need something to be preferred
        os.symlink("/bin/true", "/tmp/true")
        tmp_true = apport.report._which_extrapath("true", "/tmp")
        os.unlink("/tmp/true")
        self.assertEqual(tmp_true, "/tmp/true")
        self.assertEqual(bin_true, "/usr/bin/true")
