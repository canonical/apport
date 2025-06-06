"""System tests for data/apport."""

import errno
import os
import pathlib
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import psutil

import apport.fileutils
import apport.report
from tests.helper import (
    get_gnu_coreutils_cmd,
    get_init_system,
    pids_of,
    skip_if_command_is_missing,
    wait_for_process_to_appear,
    wait_for_sleeping_state,
)
from tests.paths import (
    get_data_directory,
    is_local_source_directory,
    local_test_environment,
)


class T(unittest.TestCase):
    # pylint: disable=missing-class-docstring,missing-function-docstring
    # pylint: disable=protected-access
    TEST_EXECUTABLE = get_gnu_coreutils_cmd("sleep")
    TEST_ARGS = ["86400"]
    apport_path: pathlib.Path | str | None
    all_reports: list[str]
    ifpath: str
    orig_environ: dict[str, str]
    orig_core_dir: str
    orig_cwd: str
    orig_ignore_file: str
    orig_report_dir: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.orig_environ = os.environ.copy()
        os.environ |= local_test_environment()

        with open("/proc/sys/kernel/core_pattern", encoding="utf-8") as f:
            core_pattern = f.read().strip()
        if core_pattern[0] == "|":
            cls.apport_path = core_pattern[1:].split()[0]
        else:
            cls.apport_path = None
        if is_local_source_directory():
            cls.apport_path = get_data_directory() / "apport"

        cls.all_reports = apport.fileutils.get_all_reports()

        # ensure we don't inherit an ignored SIGQUIT
        signal.signal(signal.SIGQUIT, signal.SIG_DFL)

        orig_home = os.getenv("HOME")
        if orig_home is not None:
            del os.environ["HOME"]
        cls.ifpath = os.path.expanduser(apport.report._ignore_file)
        if orig_home is not None:
            os.environ["HOME"] = orig_home

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
        if self.apport_path is None:
            self.skipTest(
                "kernel crash dump helper is not active; please enable"
                " before running this test"
            )

        if self.all_reports:
            self.skipTest(
                "Please remove all crash reports from /var/crash/ for this"
                " test suite:\n  %s\n" % "\n  ".join(self.all_reports)
            )

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

        # move aside current ignore file
        if os.path.exists(self.ifpath):
            os.rename(self.ifpath, f"{self.ifpath}.apporttest")

        # do not write core files by default
        resource.setrlimit(resource.RLIMIT_CORE, (0, -1))

        # that's the place where to put core dumps, etc.
        os.chdir("/tmp")

        # expected report name for test executable report
        self.test_report = os.path.join(
            apport.fileutils.report_dir,
            f"{self.TEST_EXECUTABLE.replace('/', '_')}.{os.getuid()}.crash",
        )

        self.running_test_executables = pids_of(self.TEST_EXECUTABLE)

    def tearDown(self) -> None:
        shutil.rmtree(self.report_dir)
        shutil.rmtree(self.workdir)

        # clean up our ignore file
        if os.path.exists(self.ifpath):
            os.unlink(self.ifpath)
        orig_ignore_file = f"{self.ifpath}.apporttest"
        if os.path.exists(orig_ignore_file):
            os.rename(orig_ignore_file, self.ifpath)

        # permit tests to leave behind test_report, but nothing else
        if os.path.exists(self.test_report):
            apport.fileutils.delete_report(self.test_report)
        unexpected_reports = apport.fileutils.get_all_reports()
        for r in unexpected_reports:
            apport.fileutils.delete_report(r)
        self.assertEqual(unexpected_reports, [])

    def test_limit_size(self) -> None:
        """Core dumps are capped on available memory size."""
        assert self.apport_path is not None
        # determine how much data we have to pump into apport in order to make
        # sure that it will refuse the core dump
        r = apport.report.Report()
        with open("/proc/meminfo", "rb") as f:
            r.load(f)
        totalmb = int(r["MemFree"].split()[0]) + int(r["Cached"].split()[0])
        totalmb = int(totalmb / 1024)
        del r

        test_proc = self.create_test_process()
        try:
            with subprocess.Popen(
                [
                    self.apport_path,
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
                assert app.stdin is not None
                # pipe an entire total memory size worth of spaces into it,
                # which must be bigger than the 'usable' memory size. apport
                # should digest that and the report should not have a core
                # dump; NB that this should error out with a SIGPIPE when
                # apport aborts reading from stdin
                onemb = b" " * 1048576
                while totalmb > 0:
                    if totalmb & 255 == 0:
                        # Print a dot every 256 MiB
                        sys.stderr.write(".")
                        sys.stderr.flush()
                    try:
                        app.stdin.write(onemb)
                    except OSError as error:
                        if error.errno == errno.EPIPE:
                            break
                        raise
                    totalmb -= 1
                err = app.communicate()[1]
            self.assertEqual(app.returncode, 0, err)
            del onemb
        finally:
            test_proc.kill()
            test_proc.wait()

        reports = apport.fileutils.get_all_reports()
        self.assertEqual(reports, [self.test_report])

        pr = apport.report.Report()
        with open(reports[0], "rb") as f:
            pr.load(f)
        os.unlink(reports[0])

        self.assertEqual(pr["Signal"], "42")
        self.assertEqual(pr["ExecutablePath"], self.TEST_EXECUTABLE)
        self.assertNotIn("CoreDump", pr)
        # FIXME: sometimes this is empty!?
        if err:
            self.assertRegex(
                err.decode(),
                f"core dump exceeded.*dropped from .*"
                f"{os.path.basename(self.TEST_EXECUTABLE)}\\..*\\.crash",
            )

    @unittest.skipIf(
        get_init_system() != "systemd", "running init system is not systemd"
    )
    @skip_if_command_is_missing("systemd-run")
    @unittest.skipIf(os.geteuid() != 0, "this test needs to be run as root")
    def test_crash_system_slice(self) -> None:
        """Report generation for a protected process running in the system
        slice"""
        apport.fileutils.report_dir = self.orig_report_dir
        self.test_report = os.path.join(
            apport.fileutils.report_dir,
            f"{self.TEST_EXECUTABLE.replace('/', '_')}.{os.getuid()}.crash",
        )

        system_run = self.create_test_process(
            command="/usr/bin/systemd-run",
            args=[
                "-t",
                "-q",
                "--slice=system.slice",
                "-p",
                "ProtectSystem=true",
                self.TEST_EXECUTABLE,
            ]
            + self.TEST_ARGS,
        )
        try:
            sleep_pid = wait_for_process_to_appear(
                self.TEST_EXECUTABLE, self.running_test_executables
            )
            wait_for_sleeping_state(sleep_pid)
            os.kill(sleep_pid, signal.SIGSEGV)

            self.wait_for_no_instance_running(self.TEST_EXECUTABLE)
            self.wait_for_apport_to_finish()
        finally:
            system_run.kill()
            system_run.wait()

        # check crash report
        with open("/var/log/apport.log", encoding="utf-8") as logfile:
            apport_log = logfile.read().strip()
        reports = apport.fileutils.get_all_reports()
        self.assertEqual(reports, [self.test_report], f"Apport log:\n{apport_log}")
        self.assertEqual(
            reports[0], f"/var/crash/{self.TEST_EXECUTABLE.replace('/', '_')}.0.crash"
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

    @patch("tests.helper.wait_for_sleeping_state")
    def test_create_test_non_sleep_process(self, wait_sleep_mock: MagicMock) -> None:
        """Test create_test_process() helper method with non-sleep process."""
        with (
            patch("os.access"),
            patch("subprocess.Popen"),
            patch("tests.system.test_signal_crashes.open"),
        ):
            self.create_test_process(command="echo")

        wait_sleep_mock.assert_not_called()

    def wait_for_apport_to_finish(self, timeout_sec: float = 10.0) -> None:
        assert self.apport_path is not None
        self.wait_for_no_instance_running(self.apport_path, timeout_sec)

    def wait_for_no_instance_running(
        self, program: pathlib.Path | str, timeout_sec: float = 10.0
    ) -> None:
        while timeout_sec > 0:
            if not pids_of(str(program)) - self.running_test_executables:
                break
            time.sleep(0.2)
            timeout_sec -= 0.2
        else:
            self.fail(f"Timeout exceeded, but {program} is still running.")
