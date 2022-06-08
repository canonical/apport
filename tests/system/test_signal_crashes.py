import errno
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

import apport.fileutils
from tests.helper import pidof
from tests.paths import (
    get_data_directory,
    is_local_source_directory,
    local_test_environment,
)

test_executable = '/usr/bin/yes'


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.orig_environ = os.environ.copy()
        os.environ |= local_test_environment()

        with open('/proc/sys/kernel/core_pattern') as f:
            core_pattern = f.read().strip()
        if core_pattern[0] == '|':
            cls.apport_path = core_pattern[1:].split()[0]
        else:
            cls.apport_path = None
        if is_local_source_directory():
            cls.apport_path = os.path.join(get_data_directory(), "apport")

        cls.all_reports = apport.fileutils.get_all_reports()

        # ensure we don't inherit an ignored SIGQUIT
        signal.signal(signal.SIGQUIT, signal.SIG_DFL)

        orig_home = os.getenv('HOME')
        if orig_home is not None:
            del os.environ['HOME']
        cls.ifpath = os.path.expanduser(apport.report._ignore_file)
        if orig_home is not None:
            os.environ['HOME'] = orig_home

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
        if self.apport_path is None:
            self.skipTest('kernel crash dump helper is not active; please enable before running this test')

        if self.all_reports:
            self.skipTest('Please remove all crash reports from /var/crash/ for this test suite:\n  %s\n' %
                          '\n  '.join(self.all_reports))

        # use local report dir
        self.report_dir = tempfile.mkdtemp()
        os.environ['APPORT_REPORT_DIR'] = self.report_dir
        apport.fileutils.report_dir = self.report_dir

        self.workdir = tempfile.mkdtemp()

        apport.fileutils.core_dir = os.path.join(self.workdir, "coredump")
        os.mkdir(apport.fileutils.core_dir)
        os.environ['APPORT_COREDUMP_DIR'] = apport.fileutils.core_dir

        os.environ['APPORT_IGNORE_FILE'] = os.path.join(
            self.workdir, "apport-ignore.xml"
        )
        apport.report._ignore_file = os.environ['APPORT_IGNORE_FILE']

        os.environ['APPORT_LOCK_FILE'] = os.path.join(
            self.workdir, "apport.lock"
        )

        # move aside current ignore file
        if os.path.exists(self.ifpath):
            os.rename(self.ifpath, self.ifpath + '.apporttest')

        # do not write core files by default
        resource.setrlimit(resource.RLIMIT_CORE, (0, -1))

        # that's the place where to put core dumps, etc.
        os.chdir('/tmp')

        # expected report name for test executable report
        self.test_report = os.path.join(
            apport.fileutils.report_dir, '%s.%i.crash' %
            (test_executable.replace('/', '_'), os.getuid()))

    def tearDown(self):
        shutil.rmtree(self.report_dir)
        shutil.rmtree(self.workdir)

        # clean up our ignore file
        if os.path.exists(self.ifpath):
            os.unlink(self.ifpath)
        orig_ignore_file = self.ifpath + '.apporttest'
        if os.path.exists(orig_ignore_file):
            os.rename(orig_ignore_file, self.ifpath)

        # permit tests to leave behind test_report, but nothing else
        if os.path.exists(self.test_report):
            apport.fileutils.delete_report(self.test_report)
        unexpected_reports = apport.fileutils.get_all_reports()
        for r in unexpected_reports:
            apport.fileutils.delete_report(r)
        self.assertEqual(unexpected_reports, [])

    def test_limit_size(self):
        '''core dumps are capped on available memory size'''

        # determine how much data we have to pump into apport in order to make sure
        # that it will refuse the core dump
        r = apport.Report()
        with open('/proc/meminfo', 'rb') as f:
            r.load(f)
        totalmb = int(r['MemFree'].split()[0]) + int(r['Cached'].split()[0])
        totalmb = int(totalmb / 1024)
        r = None

        test_proc = self.create_test_process()
        try:
            app = subprocess.Popen([self.apport_path, str(test_proc), '42', '0', '1'],
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            # pipe an entire total memory size worth of spaces into it, which must be
            # bigger than the 'usable' memory size. apport should digest that and the
            # report should not have a core dump; NB that this should error out
            # with a SIGPIPE when apport aborts reading from stdin
            onemb = b' ' * 1048576
            while totalmb > 0:
                if totalmb & 31 == 0:
                    sys.stderr.write('.')
                    sys.stderr.flush()
                try:
                    app.stdin.write(onemb)
                except IOError as e:
                    if e.errno == errno.EPIPE:
                        break
                    else:
                        raise
                totalmb -= 1
            (out, err) = app.communicate()
            self.assertEqual(app.returncode, 0, err)
            onemb = None
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)

        reports = apport.fileutils.get_all_reports()
        self.assertEqual(len(reports), 1)

        pr = apport.Report()
        with open(reports[0], 'rb') as f:
            pr.load(f)
        os.unlink(reports[0])

        self.assertEqual(pr['Signal'], '42')
        self.assertEqual(pr['ExecutablePath'], test_executable)
        self.assertFalse('CoreDump' in pr)
        # FIXME: sometimes this is empty!?
        if err:
            self.assertRegex(
                err, b'core dump exceeded.*dropped from .*yes\\..*\\.crash')

    @unittest.skipIf(shutil.which('systemd-run') is None, 'systemd-run not installed')
    @unittest.skipIf(os.geteuid() != 0, 'this test needs to be run as root')
    def test_crash_system_slice(self):
        '''report generation for a protected process running in the system slice'''
        apport.fileutils.report_dir = self.orig_report_dir
        self.test_report = os.path.join(
            apport.fileutils.report_dir, '%s.%i.crash' %
            (test_executable.replace('/', '_'), os.getuid()))

        self.assertEqual(pidof(test_executable), set(), 'no running test executable processes')
        self.create_test_process(command='/usr/bin/systemd-run',
                                 check_running=False,
                                 args=['-t', '-q', '--slice=system.slice',
                                       '-p', 'ProtectSystem=true',
                                       test_executable])
        yes_pids = pidof(test_executable)
        self.assertEqual(len(yes_pids), 1)
        os.kill(yes_pids.pop(), signal.SIGSEGV)

        self.wait_for_no_instance_running(test_executable)
        self.wait_for_apport_to_finish()

        # check crash report
        reports = apport.fileutils.get_all_reports()
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0], '/var/crash/_usr_bin_yes.0.crash')

    @classmethod
    def create_test_process(klass, check_running=True, command=test_executable,
                            uid=None, args=[]):
        '''Spawn test_executable.

        Wait until it is fully running, and return its PID.
        '''
        assert os.access(command, os.X_OK), command + ' is not executable'
        if check_running:
            assert pidof(command) == set(), 'no running test executable processes'

        env = os.environ.copy()
        # set UTF-8 environment variable, to check proper parsing in apport
        os.putenv('utf8trap', b'\xc3\xa0\xc3\xa4')
        process = subprocess.Popen(
            [command] + args, env=env, stdout=subprocess.DEVNULL, user=uid
        )

        # wait until child process has execv()ed properly
        while True:
            with open('/proc/%i/cmdline' % process.pid) as f:
                cmdline = f.read()
            if 'test_signal' in cmdline:
                time.sleep(0.1)
            else:
                break

        time.sleep(0.3)  # needs some more setup time
        return process.pid

    def wait_for_apport_to_finish(self, timeout_sec=10.0):
        self.wait_for_no_instance_running(self.apport_path, timeout_sec)

    def wait_for_no_instance_running(self, program, timeout_sec=10.0):
        while timeout_sec > 0:
            if not pidof(program):
                break
            time.sleep(0.2)
            timeout_sec -= 0.2
        else:
            self.fail(f"Timeout exceeded, but {program} is still running.")
