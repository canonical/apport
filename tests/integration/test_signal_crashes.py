# Copyright (C) 2007 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Integration tests for data/apport."""

# pylint: disable=too-many-lines
# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import argparse
import collections
import contextlib
import datetime
import grp
import os
import pathlib
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
import typing
import unittest
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from unittest.mock import MagicMock

import psutil
import pytest

import apport.fileutils
from tests.helper import (
    import_module_from_file,
    read_shebang,
    run_test_executable,
    wait_for_sleeping_state,
)
from tests.paths import get_data_directory, local_test_environment

try:
    import systemd.journal

    assert systemd.journal.Reader
    SYSTEMD_IMPORT_ERROR = None
except ImportError as import_error:
    SYSTEMD_IMPORT_ERROR = import_error

APPORT_PATH = get_data_directory() / "apport"
apport_binary = import_module_from_file(APPORT_PATH)


@contextlib.contextmanager
def create_dropsuid() -> Iterator[str]:
    """Compiles a suid binary that immediately drops privilege then sleeps."""
    DROPSUID_SOURCE = """
        #include <unistd.h>
        #include <stdio.h>
        #include <errno.h>

        int main() {
            int euid = geteuid();
            int uid = getuid();

            // We need to be suid
            if (uid == euid) {
                fprintf(stderr, "uid: %d, euid: %d\\n", uid, euid);
                return 1;
            }
            // This call is supposed to succeed?!
            if (seteuid(uid)) {
                fprintf(stderr, "errno: %d\\n", errno);
                return 2;
            }
            // We actually check that it succeeded.
            if (geteuid() != uid)
                return 3;
            sleep(60);
            return 0;
        }
    """
    if not os.path.exists("/usr/bin/gcc"):
        pytest.skip("This test needs GCC available")
    with tempfile.TemporaryDirectory(dir="/var/tmp") as d:
        tempdir = Path(d)
        source = tempdir / "dropsuid.c"
        source.write_text(DROPSUID_SOURCE)
        binary = tempdir / "dropsuid"
        cmd = ["/usr/bin/gcc", "-g", str(source), "-o", str(binary)]
        subprocess.run(cmd, check=True)
        # Grant everyone read permission on the directory!
        os.chmod(tempdir, 0o755)
        os.chmod(binary, 0o4755)
        yield str(binary)


@contextlib.contextmanager
def create_suid(tmpdir: str = "/var/tmp") -> Iterator[str]:
    """Creates a `sleep` suid binary in a subdirectory of `tmpdir`."""
    src_bin = os.path.realpath("/bin/sleep")
    with tempfile.TemporaryDirectory(dir=tmpdir) as tempdir:
        binary = f"{tempdir}/sleep"
        shutil.copy(src_bin, binary)
        # Grant everyone read permission on the directory!
        os.chmod(tempdir, 0o755)
        os.chmod(binary, 0o4755)
        yield binary


MAIL_UID = 8
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
    # pylint: disable=missing-class-docstring,missing-function-docstring
    # pylint: disable=protected-access,too-many-public-methods
    TEST_EXECUTABLE = os.path.realpath("/bin/sleep")
    TEST_ARGS = ["86400"]
    maxDiff = None
    orig_core_dir: str
    orig_cwd: str
    orig_environ: dict[str, str]
    orig_ignore_file: str
    orig_report_dir: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.orig_environ = os.environ.copy()
        os.environ |= local_test_environment()

        cls.orig_cwd = os.getcwd()
        cls.orig_core_dir = apport.fileutils.core_dir
        cls.orig_ignore_file = apport.report._ignore_file
        cls.orig_report_dir = apport.fileutils.report_dir

    @classmethod
    def tearDownClass(cls) -> None:
        os.environ.clear()
        os.environ.update(cls.orig_environ)
        apport.fileutils.core_dir = cls.orig_core_dir
        apport.report._ignore_file = cls.orig_ignore_file
        apport.fileutils.report_dir = cls.orig_report_dir
        os.chdir(cls.orig_cwd)

    def setUp(self) -> None:
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

        os.environ["APPORT_LOCK_FILE"] = os.path.join(self.workdir, "apport.lock")

        # do not write core files by default
        resource.setrlimit(resource.RLIMIT_CORE, (0, -1))

        # that's the place where to put core dumps, etc.
        os.chdir("/tmp")

        # expected report name for test executable report
        self.test_report: str | None = None

    def tearDown(self) -> None:
        # permit tests to leave behind test_report, but nothing else
        if self.test_report and os.path.exists(self.test_report):
            apport.fileutils.delete_report(self.test_report)
        try:
            self.assertEqual(apport.fileutils.get_all_reports(), [])
        finally:
            shutil.rmtree(self.report_dir)
            shutil.rmtree(self.workdir)

    def test_empty_core_dump(self) -> None:
        """Empty core dumps do not generate a report."""
        test_proc = self.create_test_process()
        try:
            with subprocess.Popen(
                [
                    str(APPORT_PATH),
                    "-p",
                    str(test_proc.pid),
                    "-s",
                    "42",
                    "-c",
                    "0",
                    "-d",
                    "1",
                ],
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as app:
                assert app.stdin is not None and app.stderr is not None
                app.stdin.close()
                assert app.wait() == 0, app.stderr.read()
                app.stderr.close()
        finally:
            test_proc.kill()
            test_proc.wait()

        self._check_report(expect_report=False)

    def test_crash_apport(self) -> None:
        """Report generation with apport."""
        test_report = self.do_crash()
        st = os.stat(test_report)

        # a subsequent crash does not alter unseen report
        test_report = self.do_crash()
        st2 = os.stat(test_report)
        self.assertEqual(st, st2, "original unseen report did not get overwritten")

        # a subsequent crash alters seen report
        apport.fileutils.mark_report_seen(test_report)
        test_report = self.do_crash()
        st2 = os.stat(test_report)
        self.assertNotEqual(st, st2, "original seen report gets overwritten")

        pr = apport.Report()
        with open(test_report, "rb") as f:
            pr.load(f)
        self.assertTrue(
            set(required_fields).issubset(set(pr.keys())), "report has required fields"
        )
        self.assertEqual(pr["ExecutablePath"], self.TEST_EXECUTABLE)
        self.assertEqual(
            pr["ProcCmdline"], " ".join([self.TEST_EXECUTABLE] + self.TEST_ARGS)
        )
        self.assertEqual(pr["Signal"], f"{signal.SIGSEGV}")

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
            k = line.split("=", 1)[0]
            self.assertIn(k, allowed_vars)

        # UserGroups only has system groups
        sys_gid_max = apport.fileutils.get_sys_gid_max()
        for g in pr["UserGroups"].split():
            if g == "N/A":
                continue
            self.assertLessEqual(grp.getgrnam(g).gr_gid, sys_gid_max)

        self.assertNotIn("root", pr["UserGroups"])

    @unittest.skip("fix test as multiple instances can be started within 30s")
    def test_parallel_crash(self) -> None:
        """Only one apport instance is ran at a time."""
        test_proc = self.create_test_process()
        test_proc2 = self.create_test_process("/bin/dd", args=[])
        try:
            with subprocess.Popen(
                [
                    str(APPORT_PATH),
                    "-p",
                    str(test_proc.pid),
                    "-s",
                    "42",
                    "-c",
                    "0",
                    "-d",
                    "1",
                ],
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as app:
                assert app.stdin is not None and app.stderr is not None
                time.sleep(0.5)  # give it some time to grab the lock

                with subprocess.Popen(
                    [
                        str(APPORT_PATH),
                        "-p",
                        str(test_proc2.pid),
                        "-s",
                        "42",
                        "-c",
                        "0",
                        "-d",
                        "1",
                    ],
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ) as app2:
                    assert app2.stdin is not None and app2.stderr is not None
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
            test_proc.kill()
            test_proc2.kill()
            test_proc.wait()
            test_proc2.wait()

    def test_unpackaged_binary(self) -> None:
        """Unpackaged binaries do not create a report."""
        local_exe = os.path.join(self.workdir, "mybin")
        with open(local_exe, "wb") as dest:
            with open(self.TEST_EXECUTABLE, "rb") as src:
                dest.write(src.read())
        os.chmod(local_exe, 0o755)
        self.do_crash(command=local_exe, expect_report=False)

    def test_unpackaged_script(self) -> None:
        """Unpackaged scripts do not create a report."""
        local_exe = pathlib.Path(self.workdir) / "myscript"
        local_exe.write_bytes(b"#!/usr/bin/perl\nsleep(86400);\n")
        local_exe.chmod(0o755)

        # absolute path
        self.do_crash(command=str(local_exe), args=[], expect_report=False)

        self.do_crash(
            command="./myscript", args=[], expect_report=False, cwd=self.workdir
        )

    def test_unsupported_arguments_no_stderr(self) -> None:
        """Write failure to log file when stderr is missing.

        The kernel calls apport with no stdout and stderr file
        descriptors set.
        """

        def close_stdin_and_stderr() -> None:
            """Close stdin and stderr"""
            os.close(sys.stdout.fileno())
            os.close(sys.stderr.fileno())

        log = os.path.join(self.workdir, "apport.log")
        env = os.environ.copy()
        env["APPORT_LOG_FILE"] = log
        app = subprocess.run(
            [str(APPORT_PATH)], check=False, env=env, preexec_fn=close_stdin_and_stderr
        )

        self.assertEqual(app.returncode, 2)
        with open(log, encoding="utf-8") as log_file:
            logged = log_file.read()
        self.assertIn("usage", logged)
        self.assertIn("the following arguments are required: -p/--pid", logged)

    def test_ignore_sigquit(self) -> None:
        """Apport ignores SIGQUIT."""
        self.do_crash(sig=signal.SIGQUIT, expect_report=False)

    def test_ignore_sigxcpu(self) -> None:
        """Apport ignores CPU time limit exceeded (SIGXCPU)."""
        self.do_crash(sig=signal.SIGXCPU, expect_report=False)

    def test_leak_inaccessible_files(self) -> None:
        """Existence of user-inaccessible files do not leak."""
        local_exe = os.path.join(self.workdir, "myscript")
        with open(local_exe, "w", encoding="utf-8") as f:
            f.write(
                '#!/usr/bin/perl\nsystem("mv $0 $0.exe");\n'
                'system("ln -sf /etc/shadow $0");\n'
                '$0="..$0";\n'
                "sleep(10);\n"
            )
        os.chmod(local_exe, 0o755)
        self.do_crash(command=local_exe, args=[], expected_command=f"..{local_exe}")

        leak = os.path.join(
            apport.fileutils.report_dir, f"_usr_bin_perl.{os.getuid()}.crash"
        )
        pr = apport.Report()
        with open(leak, "rb") as f:
            pr.load(f)
        # On a leak, no report is created since the executable path will be
        # replaced by the symlink path, and it doesn't belong to any package.
        self.assertEqual(pr["ExecutablePath"], "/usr/bin/perl")
        self.assertNotIn("InterpreterPath", pr)
        apport.fileutils.delete_report(leak)

    def test_flood_limit(self) -> None:
        """Limitation of crash report flood."""
        count = 0
        while count < 7:
            sys.stderr.write(f"{count} ")
            sys.stderr.flush()
            test_report = self.do_crash()
            reports = apport.fileutils.get_new_reports()
            if not reports:
                break
            apport.fileutils.mark_report_seen(test_report)
            count += 1
        self.assertGreater(count, 1, "gets at least 2 repeated crashes")
        self.assertLess(count, 7, "stops flooding after less than 7 repeated crashes")

    @unittest.skipIf(os.geteuid() != 0, "this test needs to be run as root")
    def test_nonreadable_exe(self) -> None:
        """Report generation for non-readable executable."""
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

        self.do_crash(command=myexe, expect_corefile=False, uid=8, suid_dumpable=2)

    def test_core_dump_packaged(self) -> None:
        """Packaged executables create core dumps on proper ulimits."""
        # for SEGV and ABRT we expect reports and core files
        for sig in (signal.SIGSEGV, signal.SIGABRT):
            for kb, exp_file in core_ulimit_table:
                resource.setrlimit(resource.RLIMIT_CORE, (kb, -1))
                test_report = self.do_crash(
                    expect_corefile=exp_file,
                    expect_corefile_owner=os.geteuid(),
                    sig=sig,
                )
                self.check_report_coredump(test_report)
                apport.fileutils.delete_report(test_report)

            # creates core file with existing crash report, too
            test_report = self.do_crash(expect_corefile=True)
            apport.fileutils.delete_report(test_report)

    def test_core_dump_packaged_sigquit(self) -> None:
        """Packaged executables create core files, no report for SIGQUIT."""
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
        self.do_crash(expect_corefile=True, expect_report=False, sig=signal.SIGQUIT)

    def test_core_dump_unpackaged(self) -> None:
        """Unpackaged executables create core dumps on proper ulimits."""
        local_exe = os.path.join(self.workdir, "mybin")
        with open(local_exe, "wb") as dest:
            with open(self.TEST_EXECUTABLE, "rb") as src:
                dest.write(src.read())
        os.chmod(local_exe, 0o755)

        for sig in (signal.SIGSEGV, signal.SIGABRT, signal.SIGQUIT):
            for kb, exp_file in core_ulimit_table:
                resource.setrlimit(resource.RLIMIT_CORE, (kb, -1))
                self.do_crash(
                    expect_corefile=exp_file,
                    expect_corefile_owner=os.geteuid(),
                    expect_report=False,
                    command=local_exe,
                    sig=sig,
                )

    def test_core_file_injection(self) -> None:
        """Cannot inject core file."""
        # CVE-2015-1325: ensure that apport does not re-open its .crash report,
        # as that allows us to intercept and replace the report and tinker with
        # the core dump

        inject_report = f"{self.test_report}.inject"
        with open(inject_report, "w", encoding="utf-8") as f:
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
        os.chmod(inject_report, 0o640)

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
            os.rename(inject_report, self.test_report)
            os._exit(os.EX_OK)

        # do_crash verifies that we get the original core, not the injected one
        self.do_crash(expect_corefile=True, hook_before_apport=inject_bogus_report)

    def test_ignore(self) -> None:
        """Ignore executables."""
        test_report = self.do_crash()

        pr = apport.Report()
        with open(test_report, "rb") as f:
            pr.load(f)
        os.unlink(test_report)

        pr.mark_ignore()

        self.do_crash(expect_report=False)

    def test_modify_after_start(self) -> None:
        """Ignore executables which got modified after process started."""
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

            app = subprocess.run(
                [
                    str(APPORT_PATH),
                    "-p",
                    str(test_proc.pid),
                    "-s",
                    "42",
                    "-c",
                    "0",
                    "-d",
                    "1",
                ],
                check=False,
                input=b"foo",
                stderr=subprocess.PIPE,
            )
            err = app.stderr.decode()
            self.assertEqual(app.returncode, 0, err)
            if os.getuid() > 0:
                self.assertIn("executable was modified after program start", err)
            else:
                with open("/var/log/apport.log", encoding="utf-8") as f:
                    lines = f.readlines()
                self.assertIn("executable was modified after program start", lines[-1])
        finally:
            test_proc.kill()
            test_proc.wait()

        self._check_report(expect_report=False)

    def test_logging_file(self):
        """Output to log file, if available."""
        test_proc = self.create_test_process()
        log = os.path.join(self.workdir, "apport.log")
        try:
            env = os.environ.copy()
            env["APPORT_LOG_FILE"] = log
            app = subprocess.run(
                [
                    str(APPORT_PATH),
                    "-p",
                    str(test_proc.pid),
                    "-s",
                    "42",
                    "-c",
                    "0",
                    "-d",
                    "1",
                ],
                check=False,
                env=env,
                input="hel\x01lo",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        finally:
            test_proc.kill()
            test_proc.wait()

        self.assertEqual(
            app.stdout + app.stderr,
            "",
            msg=f"Apport wrote to stdout and/or stderr"
            f" (exit code {app.returncode})."
            f"\n*** stdout:\n{app.stdout.strip()}"
            f"\n*** stderr:\n{app.stderr.strip()}",
        )
        self.assertEqual(app.returncode, 0, app.stderr)
        with open(log, encoding="utf-8") as f:
            logged = f.read()
        self.assertIn("called for pid", logged)
        self.assertIn("wrote report", logged)
        self.assertNotIn("Traceback", logged)

        self._check_report()
        pr = apport.Report()
        with open(self.test_report, "rb") as f:
            pr.load(f)

        self.assertEqual(pr["Signal"], "42")
        self.assertEqual(pr["ExecutablePath"], self.TEST_EXECUTABLE)
        self.assertEqual(pr["CoreDump"], b"hel\x01lo")

    def test_logging_stderr(self):
        """Output to stderr if log is not available."""
        test_proc = self.create_test_process()
        try:
            env = os.environ.copy()
            env["APPORT_LOG_FILE"] = "/not/existing/apport.log"
            app = subprocess.run(
                [
                    str(APPORT_PATH),
                    "-p",
                    str(test_proc.pid),
                    "-s",
                    "42",
                    "-c",
                    "0",
                    "-d",
                    "1",
                ],
                check=False,
                encoding="UTF-8",
                env=env,
                input="hel\x01lo",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        finally:
            test_proc.kill()
            test_proc.wait()

        self.assertEqual(app.stdout, "")
        self.assertEqual(app.returncode, 0, app.stderr)
        self.assertIn("called for pid", app.stderr)
        self.assertIn("wrote report", app.stderr)
        self.assertNotIn("Traceback", app.stderr)

        self._check_report()
        pr = apport.Report()
        with open(self.test_report, "rb") as f:
            pr.load(f)

        self.assertEqual(pr["Signal"], "42")
        self.assertEqual(pr["ExecutablePath"], self.TEST_EXECUTABLE)
        self.assertEqual(pr["CoreDump"], b"hel\x01lo")

    @unittest.skipIf(os.geteuid() != 0, "this test needs to be run as root")
    def test_crash_setuid_keep(self) -> None:
        """Report generation for setuid program which stays root."""
        with create_suid() as suid:
            resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
            # if a user can crash a suid root binary, it should not create
            # core files
            # run test program in /run (which should only be writable to root)
            self.do_crash(command=suid, uid=MAIL_UID, suid_dumpable=2, cwd="/run")

    @unittest.skipIf(os.geteuid() != 0, "this test needs to be run as root")
    def test_crash_suid_dumpable_debug(self) -> None:
        """Report generation for setuid program with suid_dumpable set to 1."""
        # if a user can crash a suid root binary, it should not create
        # core files if /proc/sys/fs/suid_dumpable is set to 1 ("debug")
        with create_suid() as suid:
            resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
            self.do_crash(command=suid, uid=MAIL_UID, suid_dumpable=1)

    @unittest.skipIf(os.geteuid() != 0, "this test needs to be run as root")
    def test_crash_setuid_drop(self) -> None:
        """Report generation for setuid program which drops root."""
        with create_dropsuid() as dropsuid:
            resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
            # if a user can crash a suid root binary, it should not create
            # core files
            self.do_crash(command=dropsuid, uid=MAIL_UID, suid_dumpable=2)

    @unittest.skipIf(os.geteuid() != 0, "this test needs to be run as root")
    def test_crash_setuid_unpackaged(self) -> None:
        """Report generation for unpackaged setuid program."""
        # create suid root executable in a path we can modify which apport
        # regards as not packaged
        with create_suid(tmpdir="/tmp") as suid:
            resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
            # if a user can crash a suid root binary, it should not create
            # core files
            self.do_crash(
                command=suid,
                expect_corefile=False,
                expect_report=False,
                uid=MAIL_UID,
                suid_dumpable=2,
            )

    def test_coredump_from_socket(self) -> None:
        """Forward a core dump through a socket.

        This is being used in a container via systemd activation, where the
        core dump gets read from /run/apport.socket.
        """
        test_report = self.do_crash(via_socket=True)

        pr = apport.Report()
        with open(test_report, "rb") as f:
            pr.load(f)
        self.assertEqual(pr["Signal"], "11")
        self.assertEqual(pr["ExecutablePath"], self.TEST_EXECUTABLE)

    def test_core_dump_packaged_sigquit_via_socket(self) -> None:
        """Executable create core files via socket, no report for SIGQUIT."""
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
        self.do_crash(
            expect_corefile=True,
            expect_report=False,
            sig=signal.SIGQUIT,
            via_socket=True,
        )

    @unittest.skipIf(os.geteuid() != 0, "this test needs to be run as root")
    def test_crash_setuid_drop_via_socket(self) -> None:
        """Report generation via socket for setuid program which drops root."""
        with create_dropsuid() as dropsuid:
            resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
            test_report = self.do_crash(
                command=dropsuid, uid=MAIL_UID, suid_dumpable=2, via_socket=True
            )

            # check crash report
            report = apport.Report()
            with open(test_report, "rb") as report_file:
                report.load(report_file)
            self.assertEqual(report["Signal"], "11")
            self.assertEqual(report["ExecutablePath"], dropsuid)

    @unittest.mock.patch("os.readlink")
    def test_is_not_same_ns(self, readlink_mock: MagicMock) -> None:
        readlink_mock.side_effect = ["mnt:[1]", "mnt:[2]"]
        open_mock = unittest.mock.mock_open(read_data="0::/user.slice\n")
        command = [self.TEST_EXECUTABLE] + self.TEST_ARGS
        with (
            subprocess.Popen(command) as test_process,
            unittest.mock.patch("builtins.open", open_mock),
        ):
            try:
                same_ns = apport_binary.is_same_ns(test_process.pid, "mnt")
                self.assertFalse(same_ns)
            finally:
                test_process.kill()
        readlink_mock.assert_has_calls(
            [
                unittest.mock.call(f"/proc/{test_process.pid}/ns/mnt"),
                unittest.mock.call("/proc/self/ns/mnt"),
            ]
        )
        open_mock.assert_called_with(
            f"/proc/{test_process.pid}/cgroup", encoding="utf-8"
        )

    @unittest.skipIf(
        SYSTEMD_IMPORT_ERROR,
        f"systemd Python module not available: {SYSTEMD_IMPORT_ERROR}",
    )
    @unittest.mock.patch("systemd.journal.Reader.__iter__")
    def test_crash_apport_from_systemd_coredump(self, reader_mock: MagicMock) -> None:
        """Report generation with apport from systemd-coredump."""
        with tempfile.TemporaryDirectory() as tmpdir, run_test_executable() as pid:
            coredump_file = Path(tmpdir) / "core.zst"
            coredump_file.write_text("mocked core")

            now = datetime.datetime.now(tz=datetime.timezone.utc)
            expected_report = apport.report.Report(
                date=now.strftime("%a %b %e %H:%M:%S %Y")
            )
            expected_report.pid = pid
            expected_report.add_proc_info()
            expected_report.add_user_info()
            expected_report.add_os_info()
            expected_report.add_package_info()
            expected_report["Signal"] = "11"
            expected_report["SignalName"] = "SIGSEGV"
            expected_report["_HooksRun"] = "no"
            # systemd-coredump does not collect /proc/<pid>/attr/current
            expected_report.pop("ProcAttrCurrent", None)

            systemd_coredump = {
                "COREDUMP_CGROUP": "mocked cgroup",
                "COREDUMP_CMDLINE": expected_report["ProcCmdline"],
                "COREDUMP_COMM": self.TEST_EXECUTABLE,
                "COREDUMP_CWD": expected_report["ProcCwd"],
                "COREDUMP_ENVIRON": "".join(
                    f"{k}={v}\n" for k, v in os.environ.items()
                ),
                "COREDUMP_EXE": self.TEST_EXECUTABLE,
                "COREDUMP_FILENAME": str(coredump_file),
                "COREDUMP_GID": os.getgid(),
                "COREDUMP_HOSTNAME": "mocked hostname",
                "COREDUMP_OPEN_FDS": "mocked open file descriptors",
                "COREDUMP_OWNER_UID": os.getuid(),
                "COREDUMP_PACKAGE_JSON": '{"elfType":"coredump"}',
                "COREDUMP_PID": pid,
                "COREDUMP_PROC_AUXV": b"mocked /proc/<pid>/auxv",
                "COREDUMP_PROC_CGROUP": "mocked /proc/<pid>/cgroup",
                "COREDUMP_PROC_LIMITS": "mocked /proc/<pid>/limits",
                "COREDUMP_PROC_MAPS": expected_report["ProcMaps"],
                "COREDUMP_PROC_MOUNTINFO": "mocked /proc/<pid>/mountinfo",
                "COREDUMP_PROC_STATUS": expected_report["ProcStatus"],
                "COREDUMP_RLIMIT": "9223372036854775808",
                "COREDUMP_ROOT": "/",
                "COREDUMP_SIGNAL": 11,
                "COREDUMP_SIGNAL_NAME": "SIGSEGV",
                "COREDUMP_SLICE": "mocked slice",
                "COREDUMP_TIMESTAMP": now,
                "COREDUMP_UID": os.getuid(),
                "COREDUMP_UNIT": "mocked unit",
                "COREDUMP_USER_UNIT": "mocked user unit",
            }
            reader_mock.return_value = iter([systemd_coredump])
            self.test_report = self._get_report_filename(self.TEST_EXECUTABLE)

            exit_code = apport_binary.main(["--from-systemd-coredump", "37-23489-42"])

        self.assertEqual(exit_code, 0)
        reader_mock.assert_called_once_with()
        self._check_report()
        report = apport.Report()
        with open(self.test_report, "rb") as report_file:
            report.load(report_file, binary="compressed")
        self.assertEqual(report["CoreDump"].compressed_value, b"mocked core")
        del report["CoreDump"]
        self.assertEqual(dict(report), dict(expected_report))

    #
    # Helper methods
    #

    @staticmethod
    def _apport_args(process: psutil.Process, sig: int, dump_mode: int) -> list[str]:
        return [
            f"-p{process.pid}",
            f"-s{sig}",
            f"-c{resource.getrlimit(resource.RLIMIT_CORE)[0]}",
            f"-d{dump_mode}",
            f"-P{process.pid}",
            f"-u{process.uids().real}",
            f"-g{process.gids().real}",
            "--",
            process.exe().replace("/", "!"),
        ]

    def _call_apport(
        self, process: psutil.Process, sig: int, dump_mode: int, stdin: typing.IO
    ) -> None:
        cmd = [str(APPORT_PATH)] + self._apport_args(process, sig, dump_mode)
        subprocess.check_call(cmd, stdin=stdin)

    @staticmethod
    def _forward_crash_to_container(
        socket_path: str, args: argparse.Namespace, coredump_fd: int
    ) -> None:
        orig_os_open = os.open

        def _mocked_os_open(
            path: str | os.PathLike[str], flags: int, dir_fd: int | None = None
        ) -> int:
            if path == "root/run/apport.socket":
                return orig_os_open(socket_path, flags)
            return orig_os_open(path, flags, dir_fd=dir_fd)

        with unittest.mock.patch("os.open") as os_open_mock:
            os_open_mock.side_effect = _mocked_os_open
            apport_binary.forward_crash_to_container(args, coredump_fd, False)

    def _call_apport_via_socket(
        self, process: psutil.Process, sig: int, dump_mode: int, stdin: typing.IO
    ) -> None:
        socket_path = os.path.join(self.workdir, "apport.socket")

        # emulate apport on the host which forwards the crash to the apport
        # socket in the container
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(socket_path)
        server.listen(1)

        args = apport_binary.parse_arguments(self._apport_args(process, sig, dump_mode))
        with unittest.mock.patch("apport.fileutils.search_map") as search_map_mock:
            search_map_mock.return_value = True
            self._forward_crash_to_container(socket_path, args, stdin.fileno())
            search_map_mock.assert_called()

        # call apport like systemd does via socket activation
        def child_setup() -> None:
            os.environ["LISTEN_FDNAMES"] = "connection"
            os.environ["LISTEN_FDS"] = "1"
            os.environ["LISTEN_PID"] = str(os.getpid())
            # socket from server becomes fd 3 (SD_LISTEN_FDS_START)
            conn = server.accept()[0]
            os.dup2(conn.fileno(), 3)
            conn.close()

        try:
            subprocess.run(
                [str(APPORT_PATH)],
                check=True,
                preexec_fn=child_setup,
                pass_fds=[3],
                stdin=subprocess.DEVNULL,
            )
        finally:
            server.close()

    def _check_core_file_is_valid(self, core_path: str, command: str) -> None:
        st = os.stat(core_path)
        self.assertGreater(st.st_size, 10000)
        gdb = subprocess.run(
            [
                "gdb",
                "--batch",
                "-iex",
                "set debuginfod enable off",
                "--ex",
                "bt",
                command,
                core_path,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(gdb.stdout.strip(), "")

    def _check_report(self, expect_report=True, expected_owner=None):
        if not expect_report:
            self.assertEqual(apport.fileutils.get_all_reports(), [])
            return

        if expected_owner is None:
            expected_owner = os.geteuid()

        self.assertEqual(apport.fileutils.get_all_reports(), [self.test_report])
        st = os.stat(self.test_report)
        self.assertEqual(
            stat.S_IMODE(st.st_mode),
            0o640,
            f"{self.test_report} has correct permissions",
        )
        self.assertEqual(
            st.st_uid, expected_owner, f"{self.test_report} has correct owner"
        )

    def create_test_process(
        self,
        command: str | None = None,
        uid: int | None = None,
        args: list[str] | None = None,
    ) -> subprocess.Popen:
        """Spawn test executable.

        Wait until it is fully running, and return its process.
        """
        if command is None:
            command = self.TEST_EXECUTABLE
        if args is None:
            args = self.TEST_ARGS

        assert os.access(command, os.X_OK), f"{command} is not executable"
        self.test_report = self._get_report_filename(command, uid)

        env = os.environ.copy()
        # set UTF-8 environment variable, to check proper parsing in apport
        os.putenv("utf8trap", b"\xc3\xa0\xc3\xa4")
        # caller needs to call .wait(), pylint: disable=consider-using-with
        process = subprocess.Popen(
            [command] + args, env=env, stdout=subprocess.DEVNULL, user=uid
        )

        # wait until child process has execv()ed properly
        while True:
            with open(f"/proc/{process.pid}/cmdline", encoding="utf-8") as f:
                cmdline = f.read()
            if "test_signal" in cmdline:
                time.sleep(0.1)
            else:
                break

        # sleep command needs extra time to get into "sleeping" state
        if command == self.TEST_EXECUTABLE:
            wait_for_sleeping_state(process.pid)

        return process

    def test_create_test_sleep_process(self) -> None:
        """Test create_test_process() helper method with sleep process."""
        proc = self.create_test_process()
        try:
            self.assertEqual(psutil.Process(proc.pid).status(), "sleeping")
        finally:
            proc.kill()
            proc.wait()

    @unittest.mock.patch("tests.helper.wait_for_sleeping_state")
    def test_create_test_non_sleep_process(self, wait_sleep_mock: MagicMock) -> None:
        """Test create_test_process() helper method with non-sleep process."""
        with (
            unittest.mock.patch("os.access"),
            unittest.mock.patch("subprocess.Popen"),
            unittest.mock.patch("tests.integration.test_signal_crashes.open"),
        ):
            self.create_test_process(command="echo")

        wait_sleep_mock.assert_not_called()

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def do_crash(
        self,
        expect_corefile: bool = False,
        sig: int = signal.SIGSEGV,
        command: str | None = None,
        expected_command: str | None = None,
        uid: int | None = None,
        expect_corefile_owner: int | None = None,
        args: list[str] | None = None,
        suid_dumpable: int = 1,
        hook_before_apport: Callable | None = None,
        expect_report: bool = True,
        via_socket: bool = False,
        cwd: str | None = None,
        **kwargs: typing.Any,
    ) -> str:
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-locals,too-many-statements
        """Generate a test crash.

        This runs command (by default TEST_EXECUTABLE) in cwd, lets it crash,
        and checks that it exits with the expected return code, leaving a core
        file behind if expect_corefile is set, and generating a crash report.

        If via_socket is set to True, Apport will be called via a socket.
        The socket is being used in a container via systemd activation,
        where the core dump gets read from /run/apport.socket.

        If the specified program has file capability or is a
        set‐user‐ID/set-group-ID program, this method needs to be called
        as root to allow GDB to call the program.

        Note: The arguments for the test program must not contain spaces.
        Since there was no need for it, the support was not implemented.
        """
        assert 0 <= suid_dumpable <= 2
        if command is None:
            command = self.TEST_EXECUTABLE
        if args is None:
            args = self.TEST_ARGS
        if cwd:
            command_path = os.path.join(cwd, command)
        else:
            command_path = command
        assert os.access(command_path, os.X_OK)

        # Support calling scripts in GDB
        shebang = read_shebang(command_path)
        if shebang:
            args.insert(0, command)
            command = shebang

        self.test_report = self._get_report_filename(command, uid)

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
                cwd=cwd,
                **kwargs,
            )
        except FileNotFoundError as error:
            self.skipTest(f"{error.filename} not available")
        except PermissionError:
            if os.geteuid() != 0:
                self.skipTest("needs to be run as root")
            raise

        try:
            command_process = self.wait_for_gdb_sleeping_child_process(
                gdb.pid, expected_command or command
            )

            os.kill(command_process.pid, sig)
            self.wait_for_core_file(gdb.pid, gdb_core_file)

            if hook_before_apport:
                hook_before_apport()

            if via_socket:
                call_apport = self._call_apport_via_socket
            else:
                call_apport = self._call_apport
            with open(gdb_core_file, "rb") as core_fd:
                call_apport(command_process, sig, suid_dumpable, core_fd)
            os.unlink(gdb_core_file)

            core_path = apport.fileutils.get_core_path(
                command_process.pid, command, command_process.uids().real
            )[1]
        finally:
            gdb.kill()
            gdb.communicate()

        if expect_corefile:
            self.assertTrue(os.path.exists(core_path), "leaves wanted core file")
            try:
                # check core file permissions
                st = os.stat(core_path)
                self.assertEqual(
                    stat.S_IMODE(st.st_mode), 0o400, "core file has correct permissions"
                )
                if expect_corefile_owner is not None:
                    self.assertEqual(
                        st.st_uid, expect_corefile_owner, "core file has correct owner"
                    )

                self._check_core_file_is_valid(core_path, command)
            finally:
                os.unlink(core_path)
        elif os.path.exists(core_path):
            try:
                os.unlink(core_path)
            except OSError as error:
                sys.stderr.write(
                    f"WARNING: cannot clean up core file {core_path}: {str(error)}\n"
                )

            self.fail("leaves unexpected core file behind")

        self._check_report(
            expect_report=expect_report,
            expected_owner=0 if suid_dumpable == 2 else os.geteuid(),
        )
        return self.test_report

    @staticmethod
    def gdb_command(
        command: str, args: Iterable[str], core_file: str, uid: int | None
    ) -> list[str]:
        """Construct GDB arguments to call the test executable.

        GDB must be executed as root for test executables that use setuid.
        If uid is specified, GDB will still be started by the current user
        (probably root). `setpriv` is called to change to the given uid.
        `sh` is called before executing the test executable for
        capabilities (e.g. used by `ping`).

        Note: The arguments for the command must not contain spaces.
        Since there was no need for it, the support was not implemented.
        """
        gdb_args = ["gdb", "--quiet", "-iex", "set debuginfod enable off"]

        cmd_args = " ".join(f" {a}" for a in args)
        if uid is not None:
            cmd_args = (
                f" --reuid={uid} --clear-groups /bin/sh -c 'exec {command}{cmd_args}'"
            )
            command = "/usr/bin/setpriv"
            gdb_args += ["--ex", "set follow-fork-mode child"]

        gdb_args += [
            "--ex",
            f"run{cmd_args}",
            "--ex",
            f"generate-core-file {core_file}",
            command,
        ]
        return gdb_args

    @staticmethod
    def _get_report_filename(command: str, uid: int | None = None) -> str:
        if uid is None:
            uid = os.getuid()
        return os.path.join(
            apport.fileutils.report_dir,
            f"{os.path.realpath(command).replace('/', '_')}.{uid}.crash",
        )

    def check_report_coredump(self, report_path):
        """Check that given report file has a valid core dump."""
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
        timeout = 0.0
        while timeout < 5:
            if os.path.exists(core_file):
                break
            time.sleep(0.1)
            timeout += 0.1
        else:
            self.fail(
                f"Core file {core_file} not created within {int(timeout)} seconds."
            )

        gdb_process = psutil.Process(gdb_pid)
        timeout = 0.0
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

    @unittest.mock.patch("os.path.exists")
    @unittest.mock.patch("time.sleep")
    def test_wait_for_core_file_core_not_created(
        self, sleep_mock: MagicMock, exists_mock: MagicMock
    ) -> None:
        """Test wait_for_core_file() helper runs into timeout for core file."""
        exists_mock.return_value = False
        with self.assertRaises(AssertionError):
            self.wait_for_core_file(123456789, "core")
        sleep_mock.assert_called_with(0.1)
        self.assertEqual(sleep_mock.call_count, 51)

    @unittest.mock.patch("os.path.exists")
    @unittest.mock.patch("psutil.Process", spec=psutil.Process)
    @unittest.mock.patch("time.sleep")
    def test_wait_for_core_file_timeout(
        self, sleep_mock: MagicMock, process_mock: MagicMock, exists_mock: MagicMock
    ) -> None:
        """Test wait_for_core_file() helper runs into timeout."""
        popenfile = collections.namedtuple("popenfile", ["path"])
        exists_mock.return_value = True
        process_mock.return_value.open_files.return_value = [popenfile("core")]
        with unittest.mock.patch.object(self, "fail") as fail_mock:
            self.wait_for_core_file(123456789, "core")
        fail_mock.assert_called_once()
        sleep_mock.assert_called_with(0.1)
        self.assertEqual(sleep_mock.call_count, 600)

    # False positive return statement for unittest.TestCase.fail
    # See https://github.com/pylint-dev/pylint/issues/4167
    # pylint: disable-next=inconsistent-return-statements
    def wait_for_gdb_sleeping_child_process(
        self, gdb_pid: int, command: str
    ) -> psutil.Process:
        """Wait until GDB execv()ed the child process."""
        gdb_process = psutil.Process(gdb_pid)
        timeout = 0.0
        while timeout < 5:
            gdb_children = gdb_process.children()
            for process in gdb_children:
                try:
                    if process.status() != "sleeping":
                        continue
                    cmdline = process.cmdline()
                except psutil.NoSuchProcess:  # pragma: no cover
                    continue
                if cmdline and cmdline[0] == command:
                    return process

            time.sleep(0.1)
            timeout += 0.1

        self.fail(
            f"GDB child process {command} not started within "
            f"{int(timeout)} seconds. GDB children: {gdb_children!r}"
        )

    @unittest.mock.patch("time.sleep")
    def test_wait_for_gdb_sleeping_child_process(self, sleep_mock: MagicMock) -> None:
        """Test wait_for_gdb_sleeping_child_process() helper method."""
        child = MagicMock(spec=psutil.Process)
        child.status.side_effect = [
            "tracing-stop",  # child not yet started
            "running",  # shell wrapper running
            "sleeping",  # child ready
        ]
        child.cmdline.side_effect = [[self.TEST_EXECUTABLE] + self.TEST_ARGS]
        with unittest.mock.patch("psutil.Process", spec=psutil.Process) as process_mock:
            process_mock.return_value.children.side_effect = [
                [],  # gdb hasn't started the child process yet
                [child],  # child not started (tracing-stop)
                [child],  # shell wrapper running
                [child],  # child ready
            ]

            self.wait_for_gdb_sleeping_child_process(123456789, self.TEST_EXECUTABLE)

        sleep_mock.assert_called_with(0.1)
        self.assertEqual(sleep_mock.call_count, 3)
        self.assertEqual(child.status.call_count, 3)
        self.assertEqual(child.cmdline.call_count, 1)

    @unittest.mock.patch("psutil.Process", spec=psutil.Process)
    @unittest.mock.patch("time.sleep")
    def test_wait_for_gdb_sleeping_child_process_timeout(
        self, sleep_mock: MagicMock, process_mock: MagicMock
    ) -> None:
        """Test wait_for_gdb_sleeping_child_process() helper runs into timeout."""
        process_mock.return_value.children.return_value = []
        with unittest.mock.patch.object(self, "fail") as fail_mock:
            self.wait_for_gdb_sleeping_child_process(123456789, self.TEST_EXECUTABLE)
        fail_mock.assert_called_once()
        sleep_mock.assert_called_with(0.1)
        self.assertEqual(sleep_mock.call_count, 51)
