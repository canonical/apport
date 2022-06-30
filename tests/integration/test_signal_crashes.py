# Copyright (C) 2007 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import array
import grp
import os
import resource
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

import psutil

import apport.fileutils
from tests.helper import pidof, read_shebang
from tests.paths import get_data_directory, local_test_environment

test_package = "coreutils"
test_source = "coreutils"

# (core ulimit (bytes), expect core file)
core_ulimit_table = [(1000, False), (10000000, True), (-1, True)]

required_fields = [
    "ProblemType",
    "CoreDump",
    "Date",
    "ExecutablePath",
    "ProcCmdline",
    "ProcEnviron",
    "ProcMaps",
    "Signal",
    "UserGroups",
]


class T(unittest.TestCase):
    TEST_EXECUTABLE = os.path.realpath("/bin/sleep")
    TEST_ARGS = ["86400"]

    @classmethod
    def setUpClass(cls):
        cls.orig_environ = os.environ.copy()
        os.environ |= local_test_environment()

        cls.apport_path = os.path.join(get_data_directory(), "apport")

        cls.orig_cwd = os.getcwd()
        cls.orig_core_dir = apport.fileutils.core_dir
        cls.orig_ignore_file = apport.report._ignore_file
        cls.orig_report_dir = apport.fileutils.report_dir

    @classmethod
    def tearDownClass(cls):
        os.environ.clear()
        os.environ.update(cls.orig_environ)
        apport.fileutils.core_dir = cls.orig_core_dir
        apport.report._ignore_file = cls.orig_ignore_file
        apport.fileutils.report_dir = cls.orig_report_dir
        os.chdir(cls.orig_cwd)

    def setUp(self):
        # use local report dir
        self.report_dir = tempfile.mkdtemp()
        os.environ["APPORT_REPORT_DIR"] = self.report_dir
        apport.fileutils.report_dir = self.report_dir

        self.workdir = tempfile.mkdtemp()

        apport.fileutils.core_dir = os.path.join(self.workdir, "coredump")
        os.mkdir(apport.fileutils.core_dir)
        os.environ["APPORT_COREDUMP_DIR"] = apport.fileutils.core_dir

        os.environ["APPORT_IGNORE_FILE"] = os.path.join(
            self.workdir, "apport-ignore.xml"
        )
        apport.report._ignore_file = os.environ["APPORT_IGNORE_FILE"]

        os.environ["APPORT_LOCK_FILE"] = os.path.join(
            self.workdir, "apport.lock"
        )

        # do not write core files by default
        resource.setrlimit(resource.RLIMIT_CORE, (0, -1))

        # that's the place where to put core dumps, etc.
        os.chdir("/tmp")

        # expected report name for test executable report
        self.test_report = os.path.join(
            apport.fileutils.report_dir,
            f"{self.TEST_EXECUTABLE.replace('/', '_')}.{os.getuid()}.crash",
        )

    def tearDown(self):
        shutil.rmtree(self.report_dir)
        shutil.rmtree(self.workdir)

        # permit tests to leave behind test_report, but nothing else
        if os.path.exists(self.test_report):
            apport.fileutils.delete_report(self.test_report)
        unexpected_reports = apport.fileutils.get_all_reports()
        for r in unexpected_reports:
            apport.fileutils.delete_report(r)
        self.assertEqual(unexpected_reports, [])

    def test_empty_core_dump(self):
        """empty core dumps do not generate a report"""

        test_proc = self.create_test_process()
        try:
            app = subprocess.Popen(
                [self.apport_path, str(test_proc), "42", "0", "1"],
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            app.stdin.close()
            assert app.wait() == 0, app.stderr.read()
            app.stderr.close()
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)

        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_crash_apport(self):
        """report generation with apport"""

        self.do_crash()

        # check crash report
        self.assertEqual(
            apport.fileutils.get_all_reports(), [self.test_report]
        )
        st = os.stat(self.test_report)
        self.assertEqual(
            stat.S_IMODE(st.st_mode), 0o640, "report has correct permissions"
        )
        self.assertEqual(st.st_uid, os.geteuid(), "report has correct owner")

        # a subsequent crash does not alter unseen report
        self.do_crash()
        st2 = os.stat(self.test_report)
        self.assertEqual(
            st, st2, "original unseen report did not get overwritten"
        )

        # a subsequent crash alters seen report
        apport.fileutils.mark_report_seen(self.test_report)
        self.do_crash()
        st2 = os.stat(self.test_report)
        self.assertNotEqual(st, st2, "original seen report gets overwritten")

        pr = apport.Report()
        with open(self.test_report, "rb") as f:
            pr.load(f)
        self.assertTrue(
            set(required_fields).issubset(set(pr.keys())),
            "report has required fields",
        )
        self.assertEqual(pr["ExecutablePath"], self.TEST_EXECUTABLE)
        self.assertEqual(
            pr["ProcCmdline"],
            " ".join([self.TEST_EXECUTABLE] + self.TEST_ARGS),
        )
        self.assertEqual(pr["Signal"], "%i" % signal.SIGSEGV)

        # check safe environment subset
        allowed_vars = [
            "SHELL",
            "PATH",
            "LANGUAGE",
            "LANG",
            "LC_CTYPE",
            "LC_COLLATE",
            "LC_TIME",
            "LC_NUMERIC",
            "LC_MONETARY",
            "LC_MESSAGES",
            "LC_PAPER",
            "LC_NAME",
            "LC_ADDRESS",
            "LC_TELEPHONE",
            "LC_MEASUREMENT",
            "LC_IDENTIFICATION",
            "LOCPATH",
            "TERM",
            "XDG_RUNTIME_DIR",
            "LD_PRELOAD",
        ]

        for line in pr["ProcEnviron"].splitlines():
            (k, v) = line.split("=", 1)
            self.assertIn(k, allowed_vars)

        # UserGroups only has system groups
        for g in pr["UserGroups"].split():
            if g == "N/A":
                continue
            self.assertLess(grp.getgrnam(g).gr_gid, 500)

        self.assertNotIn("root", pr["UserGroups"])

    @unittest.skip("fix test as multiple instances can be started within 30s")
    def test_parallel_crash(self):
        """only one apport instance is ran at a time"""

        test_proc = self.create_test_process()
        test_proc2 = self.create_test_process(False, "/bin/dd", args=[])
        try:
            app = subprocess.Popen(
                [self.apport_path, str(test_proc), "42", "0", "1"],
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            time.sleep(0.5)  # give it some time to grab the lock

            app2 = subprocess.Popen(
                [self.apport_path, str(test_proc2), "42", "0", "1"],
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # app should wait indefinitely for stdin, while app2 should
            # terminate immediately (give it 5 seconds)
            timeout = 50
            while timeout >= 0:
                if app2.poll():
                    break

                time.sleep(0.1)
                timeout -= 1

            self.assertGreater(
                timeout, 0, "second apport instance terminates immediately"
            )
            self.assertFalse(
                app.poll(), "first apport instance is still running"
            )

            # properly terminate app and app2
            app2.stdin.close()
            app2.stderr.close()
            app.stdin.write(b"boo")
            app.stdin.close()

            self.assertEqual(app.wait(), 0, app.stderr.read())
            app.stderr.close()
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)
            os.kill(test_proc2, 9)
            os.waitpid(test_proc2, 0)

    def test_unpackaged_binary(self):
        """unpackaged binaries do not create a report"""

        local_exe = os.path.join(self.workdir, "mybin")
        with open(local_exe, "wb") as dest:
            with open(self.TEST_EXECUTABLE, "rb") as src:
                dest.write(src.read())
        os.chmod(local_exe, 0o755)
        self.do_crash(command=local_exe)
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_unpackaged_script(self):
        """unpackaged scripts do not create a report"""

        local_exe = os.path.join(self.workdir, "myscript")
        with open(local_exe, "w") as f:
            f.write("#!/bin/sh\nkill -SEGV $$")
        os.chmod(local_exe, 0o755)
        self.do_crash(command=local_exe, args=[])

        # absolute path
        self.assertEqual(apport.fileutils.get_all_reports(), [])

        # relative path
        os.chdir(self.workdir)
        self.do_crash(command="./myscript", args=[])
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_unsupported_arguments_no_stderr(self):
        """Write failure to log file when stderr is missing

        The kernel calls apport with no stdout and stderr file
        descriptors set.
        """

        def close_stdin_and_stderr():
            """Close stdin and stderr"""
            os.close(sys.stdout.fileno())
            os.close(sys.stderr.fileno())

        log = os.path.join(self.workdir, "apport.log")
        env = os.environ.copy()
        env["APPORT_LOG_FILE"] = log
        app = subprocess.run(
            [self.apport_path],
            check=False,
            env=env,
            preexec_fn=close_stdin_and_stderr,
        )

        self.assertEqual(app.returncode, 2)
        with open(log) as log_file:
            logged = log_file.read()
        self.assertIn("usage", logged)
        self.assertIn("error: No process ID (PID) provided", logged)

    def test_ignore_sigquit(self):
        """apport ignores SIGQUIT"""

        self.do_crash(sig=signal.SIGQUIT)
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_leak_inaccessible_files(self):
        """existence of user-inaccessible files does not leak"""

        local_exe = os.path.join(self.workdir, "myscript")
        with open(local_exe, "w") as f:
            f.write(
                '#!/usr/bin/perl\nsystem("mv $0 $0.exe");\n'
                'system("ln -sf /etc/shadow $0");\n'
                '$0="..$0";\n'
                "sleep(10);\n"
            )
        os.chmod(local_exe, 0o755)
        self.do_crash(command=local_exe, args=[], sleep=2)

        leak = os.path.join(
            apport.fileutils.report_dir,
            "_usr_bin_perl.%i.crash" % (os.getuid()),
        )
        pr = apport.Report()
        with open(leak, "rb") as f:
            pr.load(f)
        # On a leak, no report is created since the executable path will be
        # replaced by the symlink path, and it doesn't belong to any package.
        self.assertEqual(pr["ExecutablePath"], "/usr/bin/perl")
        self.assertNotIn("InterpreterPath", pr)
        apport.fileutils.delete_report(leak)

    def test_flood_limit(self):
        """limitation of crash report flood"""

        count = 0
        while count < 7:
            sys.stderr.write("%i " % count)
            sys.stderr.flush()
            self.do_crash()
            reports = apport.fileutils.get_new_reports()
            if not reports:
                break
            apport.fileutils.mark_report_seen(self.test_report)
            count += 1
        self.assertGreater(count, 1, "gets at least 2 repeated crashes")
        self.assertLess(
            count, 7, "stops flooding after less than 7 repeated crashes"
        )

    @unittest.skipIf(os.geteuid() != 0, "this test needs to be run as root")
    def test_nonreadable_exe(self):
        """report generation for non-readable exe"""

        # CVE-2015-1324: if a user cannot read an executable, it behaves much
        # like a suid root binary in terms of writing a core dump

        # create a non-readable executable in a path we can modify which apport
        # regards as likely packaged
        (fd, myexe) = tempfile.mkstemp(dir="/var/tmp")
        self.addCleanup(os.unlink, myexe)
        with open(self.TEST_EXECUTABLE, "rb") as f:
            os.write(fd, f.read())
        os.close(fd)
        os.chmod(myexe, 0o111)

        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

        self.do_crash(
            command=myexe, expect_corefile=False, uid=8, suid_dumpable=2
        )

        # check crash report
        reports = apport.fileutils.get_new_system_reports()
        self.assertEqual(len(reports), 1)
        report = reports[0]
        st = os.stat(report)
        os.unlink(report)
        self.assertEqual(
            stat.S_IMODE(st.st_mode), 0o640, "report has correct permissions"
        )
        # this must be owned by root as it is an unreadable binary
        self.assertEqual(st.st_uid, 0, "report has correct owner")

        # no user reports
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_core_dump_packaged(self):
        """packaged executables create core dumps on proper ulimits"""

        # for SEGV and ABRT we expect reports and core files
        for sig in (signal.SIGSEGV, signal.SIGABRT):
            for (kb, exp_file) in core_ulimit_table:
                resource.setrlimit(resource.RLIMIT_CORE, (kb, -1))
                self.do_crash(
                    expect_corefile=exp_file,
                    expect_corefile_owner=os.geteuid(),
                    sig=sig,
                )
                self.assertEqual(
                    apport.fileutils.get_all_reports(), [self.test_report]
                )
                self.check_report_coredump(self.test_report)
                apport.fileutils.delete_report(self.test_report)

            # creates core file with existing crash report, too
            self.do_crash(expect_corefile=True)
            apport.fileutils.delete_report(self.test_report)

    def test_core_dump_packaged_sigquit(self):
        """packaged executables create core files, no report for SIGQUIT"""
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
        self.do_crash(expect_corefile=True, sig=signal.SIGQUIT)
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_core_dump_unpackaged(self):
        """unpackaged executables create core dumps on proper ulimits"""

        local_exe = os.path.join(self.workdir, "mybin")
        with open(local_exe, "wb") as dest:
            with open(self.TEST_EXECUTABLE, "rb") as src:
                dest.write(src.read())
        os.chmod(local_exe, 0o755)

        for sig in (signal.SIGSEGV, signal.SIGABRT, signal.SIGQUIT):
            for (kb, exp_file) in core_ulimit_table:
                resource.setrlimit(resource.RLIMIT_CORE, (kb, -1))
                self.do_crash(
                    expect_corefile=exp_file,
                    expect_corefile_owner=os.geteuid(),
                    command=local_exe,
                    sig=sig,
                )
                self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_core_file_injection(self):
        """cannot inject core file"""

        # CVE-2015-1325: ensure that apport does not re-open its .crash report,
        # as that allows us to intercept and replace the report and tinker with
        # the core dump

        with open(self.test_report + ".inject", "w") as f:
            # \x01pwned
            f.write(
                textwrap.dedent(
                    """\
                    ProblemType: Crash
                    CoreDump: base64
                     H4sICAAAAAAC/0NvcmVEdW1wAA==
                     Yywoz0tNAQBl1rhlBgAAAA==
                    """
                )
            )

        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

        def inject_bogus_report():
            read, write = os.pipe()
            pid = os.fork()
            if pid > 0:
                os.close(write)
                # Wait until the other child process is ready,
                # i.e. when it closes the pipe.
                os.read(read, 1)
                os.close(read)
                return
            os.close(read)
            os.close(write)

            # replace report with the crafted one above as soon as it exists
            # and becomes deletable for us; this is a busy loop, we need to be
            # really fast to intercept
            while True:
                try:
                    os.unlink(self.test_report)
                    break
                except OSError:
                    pass
            os.rename(self.test_report + ".inject", self.test_report)
            os._exit(os.EX_OK)

        # do_crash verifies that we get the original core, not the injected one
        self.do_crash(
            expect_corefile=True, hook_before_apport=inject_bogus_report
        )

    def test_ignore(self):
        """ignoring executables"""

        self.do_crash()

        reports = apport.fileutils.get_all_reports()
        self.assertEqual(len(reports), 1)

        pr = apport.Report()
        with open(reports[0], "rb") as f:
            pr.load(f)
        os.unlink(reports[0])

        pr.mark_ignore()

        self.do_crash()
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_modify_after_start(self):
        """ignores executables which got modified after process started"""

        # create executable in a path we can modify which apport regards as
        # likely packaged
        (fd, myexe) = tempfile.mkstemp(dir="/var/tmp")
        self.addCleanup(os.unlink, myexe)
        with open(self.TEST_EXECUTABLE, "rb") as f:
            os.write(fd, f.read())
        os.close(fd)
        os.chmod(myexe, 0o755)
        time.sleep(1)

        try:
            test_proc = self.create_test_process(command=myexe)

            # bump mtime of myexe to make it more recent than process start
            # time; ensure this works with file systems with only second
            # resolution
            time.sleep(1.1)
            os.utime(myexe, None)

            app = subprocess.Popen(
                [self.apport_path, str(test_proc), "42", "0", "1"],
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            err = app.communicate(b"foo")[1]
            self.assertEqual(app.returncode, 0, err)
            if os.getuid() > 0:
                self.assertIn(
                    b"executable was modified after program start", err
                )
            else:
                with open("/var/log/apport.log") as f:
                    lines = f.readlines()
                self.assertIn(
                    "executable was modified after program start", lines[-1]
                )
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)

        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_logging_file(self):
        """outputs to log file, if available"""

        test_proc = self.create_test_process()
        log = os.path.join(self.workdir, "apport.log")
        try:
            env = os.environ.copy()
            env["APPORT_LOG_FILE"] = log
            app = subprocess.Popen(
                [self.apport_path, str(test_proc), "42", "0", "1"],
                stdin=subprocess.PIPE,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            (out, err) = app.communicate(b"hel\x01lo")
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)

        if out != b"" or err != b"":
            self.fail(
                f"Apport wrote to stdout and/or stderr"
                f" (exit code {app.returncode})."
                f"\n*** stdout:\n{out.decode().strip()}"
                f"\n*** stderr:\n{err.decode().strip()}"
            )
        self.assertEqual(app.returncode, 0, err)
        with open(log) as f:
            logged = f.read()
        self.assertIn("called for pid", logged)
        self.assertIn("wrote report", logged)
        self.assertNotIn("Traceback", logged)

        reports = apport.fileutils.get_all_reports()
        self.assertEqual(len(reports), 1)

        pr = apport.Report()
        with open(reports[0], "rb") as f:
            pr.load(f)
        os.unlink(reports[0])

        self.assertEqual(pr["Signal"], "42")
        self.assertEqual(pr["ExecutablePath"], self.TEST_EXECUTABLE)
        self.assertEqual(pr["CoreDump"], b"hel\x01lo")

    def test_logging_stderr(self):
        """outputs to stderr if log is not available"""

        test_proc = self.create_test_process()
        try:
            env = os.environ.copy()
            env["APPORT_LOG_FILE"] = "/not/existing/apport.log"
            app = subprocess.Popen(
                [self.apport_path, str(test_proc), "42", "0", "1"],
                stdin=subprocess.PIPE,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            (out, err) = app.communicate(b"hel\x01lo")
            err = err.decode("UTF-8")
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)

        self.assertEqual(out, b"")
        self.assertEqual(app.returncode, 0, err)
        self.assertIn("called for pid", err)
        self.assertIn("wrote report", err)
        self.assertNotIn("Traceback", err)

        reports = apport.fileutils.get_all_reports()
        self.assertEqual(len(reports), 1)

        pr = apport.Report()
        with open(reports[0], "rb") as f:
            pr.load(f)
        os.unlink(reports[0])

        self.assertEqual(pr["Signal"], "42")
        self.assertEqual(pr["ExecutablePath"], self.TEST_EXECUTABLE)
        self.assertEqual(pr["CoreDump"], b"hel\x01lo")

    @unittest.skipIf(os.geteuid() != 0, "this test needs to be run as root")
    def test_crash_setuid_keep(self):
        """report generation for setuid program which stays root"""

        # create suid root executable in a path we can modify which apport
        # regards as likely packaged
        (fd, myexe) = tempfile.mkstemp(dir="/var/tmp")
        self.addCleanup(os.unlink, myexe)
        with open(self.TEST_EXECUTABLE, "rb") as f:
            os.write(fd, f.read())
        os.close(fd)
        os.chmod(myexe, 0o4755)

        # run test program in /run (which should only be writable to root)
        os.chdir("/run")

        # run test program as user "mail"
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

        # if a user can crash a suid root binary, it should not create
        # core files
        self.do_crash(command=myexe, uid=8, suid_dumpable=2)

        # check crash report
        reports = apport.fileutils.get_all_reports()
        self.assertEqual(len(reports), 1)
        report = reports[0]
        st = os.stat(report)
        os.unlink(report)
        self.assertEqual(
            stat.S_IMODE(st.st_mode), 0o640, "report has correct permissions"
        )
        # this must be owned by root as it is a setuid binary
        self.assertEqual(st.st_uid, 0, "report has correct owner")

    @unittest.skipUnless(
        os.path.exists("/bin/ping"), "this test needs /bin/ping"
    )
    @unittest.skipIf(os.geteuid() != 0, "this test needs to be run as root")
    def test_crash_setuid_drop(self):
        """report generation for setuid program which drops root"""

        # run ping as user "mail"
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

        # if a user can crash a suid root binary, it should not create
        # core files
        self.do_crash(
            command="/bin/ping", args=["127.0.0.1"], uid=8, suid_dumpable=2
        )

        # check crash report
        reports = apport.fileutils.get_all_reports()
        self.assertEqual(len(reports), 1)
        report = reports[0]
        st = os.stat(report)
        os.unlink(report)
        self.assertEqual(
            stat.S_IMODE(st.st_mode), 0o640, "report has correct permissions"
        )
        # this must be owned by root as it is a setuid binary
        self.assertEqual(st.st_uid, 0, "report has correct owner")

    @unittest.skipIf(os.geteuid() != 0, "this test needs to be run as root")
    def test_crash_setuid_unpackaged(self):
        """report generation for unpackaged setuid program"""

        # create suid root executable in a path we can modify which apport
        # regards as not packaged
        (fd, myexe) = tempfile.mkstemp(dir="/tmp")
        self.addCleanup(os.unlink, myexe)
        with open(self.TEST_EXECUTABLE, "rb") as f:
            os.write(fd, f.read())
        os.close(fd)
        os.chmod(myexe, 0o4755)

        # run test program as user "mail"
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

        # if a user can crash a suid root binary, it should not create
        # core files
        self.do_crash(
            command=myexe, expect_corefile=False, uid=8, suid_dumpable=2
        )

        # there should not be a crash report
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_coredump_from_socket(self):
        """forwarding of a core dump through socket

        This is being used in a container via systemd activation, where the
        core dump gets read from /run/apport.socket.
        """
        socket_path = os.path.join(self.workdir, "apport.socket")
        test_proc = self.create_test_process()
        try:
            # emulate apport on the host which forwards the crash to the apport
            # socket in the container
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(socket_path)
            server.listen(1)

            if os.fork() == 0:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(socket_path)
                with tempfile.TemporaryFile() as fd:
                    fd.write(b"hel\x01lo")
                    fd.flush()
                    fd.seek(0)
                    args = "%s 11 0 1" % test_proc
                    fd_msg = (
                        socket.SOL_SOCKET,
                        socket.SCM_RIGHTS,
                        array.array("i", [fd.fileno()]),
                    )
                    client.sendmsg([args.encode()], [fd_msg])
                os._exit(0)

            # call apport like systemd does via socket activation
            def child_setup():
                os.environ["LISTEN_FDNAMES"] = "connection"
                os.environ["LISTEN_FDS"] = "1"
                os.environ["LISTEN_PID"] = str(os.getpid())
                # socket from server becomes fd 3 (SD_LISTEN_FDS_START)
                conn = server.accept()[0]
                os.dup2(conn.fileno(), 3)

            app = subprocess.Popen(
                [self.apport_path],
                preexec_fn=child_setup,
                pass_fds=[3],
                stderr=subprocess.PIPE,
            )
            log = app.communicate()[1]
            self.assertEqual(app.returncode, 0, log)
            server.close()
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)

        reports = apport.fileutils.get_all_reports()
        self.assertEqual(len(reports), 1)
        pr = apport.Report()
        with open(reports[0], "rb") as f:
            pr.load(f)
        os.unlink(reports[0])
        self.assertEqual(pr["Signal"], "11")
        self.assertEqual(pr["ExecutablePath"], self.TEST_EXECUTABLE)
        self.assertEqual(pr["CoreDump"], b"hel\x01lo")

        # should not create report on the host
        self.assertEqual(apport.fileutils.get_all_system_reports(), [])

    #
    # Helper methods
    #

    def create_test_process(
        self, check_running=True, command=None, uid=None, args=None
    ):
        """Spawn test executable.

        Wait until it is fully running, and return its PID.
        """
        if command is None:
            command = self.TEST_EXECUTABLE
        if args is None:
            args = self.TEST_ARGS

        assert os.access(command, os.X_OK), command + " is not executable"
        if check_running:
            assert (
                pidof(command) == set()
            ), "no running test executable processes"

        env = os.environ.copy()
        # set UTF-8 environment variable, to check proper parsing in apport
        os.putenv("utf8trap", b"\xc3\xa0\xc3\xa4")
        # False positive, see https://github.com/PyCQA/pylint/issues/7092
        process = subprocess.Popen(  # pylint: disable=unexpected-keyword-arg
            [command] + args, env=env, stdout=subprocess.DEVNULL, user=uid
        )

        # wait until child process has execv()ed properly
        while True:
            with open("/proc/%i/cmdline" % process.pid) as f:
                cmdline = f.read()
            if "test_signal" in cmdline:
                time.sleep(0.1)
            else:
                break

        time.sleep(0.3)  # needs some more setup time
        return process.pid

    def do_crash(
        self,
        expect_corefile=False,
        sig=signal.SIGSEGV,
        sleep=0,
        command=None,
        uid=None,
        expect_corefile_owner=None,
        args=None,
        suid_dumpable: int = 1,
        hook_before_apport=None,
    ):
        """Generate a test crash.

        This runs command (by default TEST_EXECUTABLE) in cwd, lets it crash,
        and checks that it exits with the expected return code, leaving a core
        file behind if expect_corefile is set, and generating a crash report.

        Note: The arguments for the test program must not contain spaces.
        Since there was no need for it, the support was not implemented.
        """
        assert 0 <= suid_dumpable <= 2
        if command is None:
            command = self.TEST_EXECUTABLE
        if args is None:
            args = self.TEST_ARGS
        if not os.access(command, os.X_OK):
            self.skipTest(f"{command} is not executable")

        # Support calling scripts in GDB
        shebang = read_shebang(command)
        if shebang:
            args.insert(0, command)
            command = shebang

        gdb_core_file = os.path.join(self.workdir, "core")
        self.assertFalse(
            os.path.exists(gdb_core_file), f"{gdb_core_file} already exists"
        )

        # set UTF-8 environment variable, to check proper parsing in apport
        os.putenv("utf8trap", b"\xc3\xa0\xc3\xa4")

        try:
            gdb = subprocess.Popen(  # pylint: disable=consider-using-with
                self.gdb_command(command, args, gdb_core_file, uid),
                env={"HOME": self.workdir},
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,  # ping produces output!
            )
        except FileNotFoundError as error:
            self.skipTest(f"{error.filename} not available")
        except PermissionError:
            if os.geteuid() != 0:
                self.skipTest("needs to be run as root")
            raise

        try:
            command_process = self.wait_for_gdb_child_process(gdb.pid, command)

            if sleep > 0:
                time.sleep(sleep)

            os.kill(command_process.pid, sig)
            self.wait_for_core_file(gdb.pid, gdb_core_file)

            if hook_before_apport:
                hook_before_apport()

            cmd = [
                self.apport_path,
                f"-p{command_process.pid}",
                f"-s{sig}",
                f"-c{resource.getrlimit(resource.RLIMIT_CORE)[0]}",
                f"-d{suid_dumpable}",
                f"-P{command_process.pid}",
                f"-u{command_process.uids().real}",
                f"-g{command_process.gids().real}",
                "--",
                command.replace("/", "!"),
            ]
            with open(gdb_core_file, "rb") as core_fd:
                subprocess.check_call(cmd, stdin=core_fd)
            os.unlink(gdb_core_file)

            (core_name, core_path) = apport.fileutils.get_core_path(
                command_process.pid, command, command_process.uids().real
            )
        finally:
            gdb.kill()
            gdb.communicate()

        if expect_corefile:
            self.assertTrue(
                os.path.exists(core_path), "leaves wanted core file"
            )
            try:
                # check core file permissions
                st = os.stat(core_path)
                self.assertEqual(
                    stat.S_IMODE(st.st_mode),
                    0o400,
                    "core file has correct permissions",
                )
                if expect_corefile_owner is not None:
                    self.assertEqual(
                        st.st_uid,
                        expect_corefile_owner,
                        "core file has correct owner",
                    )

                # check that core file is valid
                self.assertGreater(st.st_size, 10000)
                gdb = subprocess.Popen(
                    ["gdb", "--batch", "--ex", "bt", command, core_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                (out, err) = gdb.communicate()
                self.assertEqual(gdb.returncode, 0)
                out = out.decode()
                err = err.decode().strip()
            finally:
                os.unlink(core_path)
        else:
            if os.path.exists(core_path):
                try:
                    os.unlink(core_path)
                except OSError as error:
                    sys.stderr.write(
                        "WARNING: cannot clean up core file %s: %s\n"
                        % (core_path, str(error))
                    )

                self.fail("leaves unexpected core file behind")

    def gdb_command(self, command, args, core_file, uid):
        """Construct GDB arguments to call the test executable.

        GDB must be executed as root for test executables that use setuid.
        If uid is specified, GDB will still be started by the current user
        (probably root). `setpriv` is called to change to the given uid.
        `sh` is called before executing the test executable for
        capabilities (e.g. used by `ping`).

        Note: The arguments for the command must not contain spaces.
        Since there was no need for it, the support was not implemented.
        """
        gdb_args = ["gdb", "--quiet"]

        args = " ".join(f" {a}" for a in args)
        if uid is not None:
            args = (
                f" --reuid={uid} --clear-groups "
                f"/bin/sh -c 'exec {command}{args}'"
            )
            command = "/usr/bin/setpriv"
            gdb_args += ["--ex", "set follow-fork-mode child"]

        gdb_args += [
            "--ex",
            f"run{args}",
            "--ex",
            f"generate-core-file {core_file}",
            command,
        ]
        return gdb_args

    def check_report_coredump(self, report_path):
        """Check that given report file has a valid core dump"""

        r = apport.Report()
        with open(report_path, "rb") as f:
            r.load(f)
        self.assertIn("CoreDump", r)
        self.assertGreater(len(r["CoreDump"]), 5000)
        r.add_gdb_info()
        self.assertIn("\n#2", r.get("Stacktrace"))

    def wait_for_core_file(self, gdb_pid: int, core_file: str) -> None:
        """Wait for GDB to finish generating the core file.

        wait_for_core_file() will wait until the GDB command
        generate-core-file has written and closed the core file. In
        case of an failure or timeout, let the test case fail.
        """
        timeout = 0
        while timeout < 5:
            if os.path.exists(core_file):
                break
            time.sleep(0.1)
            timeout += 0.1
        else:
            self.fail(
                f"Core file {core_file} not created "
                f"within {int(timeout)} seconds."
            )

        gdb_process = psutil.Process(gdb_pid)
        timeout = 0
        while timeout < 60:
            for open_file in gdb_process.open_files():
                if open_file.path == core_file:
                    break
            else:
                # Core file not opened by GDB any more.
                break
            time.sleep(0.1)
            timeout += 0.1
        else:
            self.fail(
                f"Corefile {core_file} not written by GDB "
                f"within {int(timeout)} seconds."
            )

    def wait_for_gdb_child_process(
        self, gdb_pid: int, command: str
    ) -> psutil.Process:
        """Wait until GDB execv()ed the child process."""
        gdb_process = psutil.Process(gdb_pid)
        command_name = os.path.basename(command)
        timeout = 0
        while timeout < 5:
            gdb_children = gdb_process.children()
            command_processes = [
                p for p in gdb_children if p.name() == command_name
            ]
            if command_processes:
                break
            time.sleep(0.1)
            timeout += 0.1
        else:
            self.fail(
                f"GDB child process {command} not started within "
                f"{int(timeout)} seconds. GDB children: {gdb_children!r}"
            )
        return command_processes.pop()
