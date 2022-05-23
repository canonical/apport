# Copyright (C) 2007 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import tempfile, shutil, os, subprocess, signal, time, stat, sys
import resource, errno, grp, unittest, socket, array, pwd
import apport.fileutils

from tests.helper import pidof

test_executable = '/usr/bin/yes'
test_package = 'coreutils'
test_source = 'coreutils'

# (core ulimit (bytes), expect core signal, expect core file, expect report)
core_ulimit_table = [(1, False, False, False),
                     (1000, True, False, True),
                     (10000000, True, True, True),
                     (-1, True, True, True)]

required_fields = ['ProblemType', 'CoreDump', 'Date', 'ExecutablePath',
                   'ProcCmdline', 'ProcEnviron', 'ProcMaps', 'Signal',
                   'UserGroups']


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open('/proc/sys/kernel/core_pattern') as f:
            core_pattern = f.read().strip()
        if core_pattern[0] == '|':
            cls.apport_path = core_pattern[1:].split()[0]
        else:
            cls.apport_path = None

        cls.all_reports = apport.fileutils.get_all_reports()

        # ensure we don't inherit an ignored SIGQUIT
        signal.signal(signal.SIGQUIT, signal.SIG_DFL)

        orig_home = os.getenv('HOME')
        if orig_home is not None:
            del os.environ['HOME']
        cls.ifpath = os.path.expanduser(apport.report._ignore_file)
        if orig_home is not None:
            os.environ['HOME'] = orig_home

        # did we enable suid_dumpable?
        cls.suid_dumpable = False
        try:
            with open('/proc/sys/fs/suid_dumpable') as f:
                if f.read().strip() != '0':
                    cls.suid_dumpable = True
        except IOError:
            pass

    def setUp(self):
        if self.apport_path is None:
            self.skipTest('kernel crash dump helper is not active; please enable before running this test')

        if self.all_reports:
            self.skipTest('Please remove all crash reports from /var/crash/ for this test suite:\n  %s\n' %
                          '\n  '.join(self.all_reports))

        # use local report dir
        self.report_dir = tempfile.mkdtemp()
        os.environ['APPORT_REPORT_DIR'] = self.report_dir

        self.workdir = tempfile.mkdtemp()

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

    def test_empty_core_dump(self):
        '''empty core dumps do not generate a report'''

        test_proc = self.create_test_process()
        try:
            app = subprocess.Popen([self.apport_path, str(test_proc), '42', '0', '1'],
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            app.stdin.close()
            assert app.wait() == 0, app.stderr.read()
            app.stderr.close()
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)

        self.assertEqual(self.get_temp_all_reports(), [])

    def test_crash_apport(self):
        '''report generation with apport'''

        self.do_crash()

        # check crash report
        self.assertEqual(apport.fileutils.get_all_reports(), [self.test_report])
        st = os.stat(self.test_report)
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o640, 'report has correct permissions')
        self.assertEqual(st.st_uid, os.geteuid(), 'report has correct owner')

        # a subsequent crash does not alter unseen report
        self.do_crash()
        st2 = os.stat(self.test_report)
        self.assertEqual(st, st2, 'original unseen report did not get overwritten')

        # a subsequent crash alters seen report
        apport.fileutils.mark_report_seen(self.test_report)
        self.do_crash()
        st2 = os.stat(self.test_report)
        self.assertNotEqual(st, st2, 'original seen report gets overwritten')

        pr = apport.Report()
        with open(self.test_report, 'rb') as f:
            pr.load(f)
        self.assertTrue(set(required_fields).issubset(set(pr.keys())),
                        'report has required fields')
        self.assertEqual(pr['ExecutablePath'], test_executable)
        self.assertEqual(pr['ProcCmdline'], test_executable)
        self.assertEqual(pr['Signal'], '%i' % signal.SIGSEGV)

        # check safe environment subset
        allowed_vars = ['SHELL', 'PATH', 'LANGUAGE', 'LANG', 'LC_CTYPE',
                        'LC_COLLATE', 'LC_TIME', 'LC_NUMERIC', 'LC_MONETARY',
                        'LC_MESSAGES', 'LC_PAPER', 'LC_NAME', 'LC_ADDRESS',
                        'LC_TELEPHONE', 'LC_MEASUREMENT', 'LC_IDENTIFICATION',
                        'LOCPATH', 'TERM', 'XDG_RUNTIME_DIR', 'LD_PRELOAD']

        for line in pr['ProcEnviron'].splitlines():
            (k, v) = line.split('=', 1)
            self.assertTrue(k in allowed_vars,
                            'report contains sensitive environment variable %s' % k)

        # UserGroups only has system groups
        for g in pr['UserGroups'].split():
            if g == 'N/A':
                continue
            self.assertLess(grp.getgrnam(g).gr_gid, 500)

        self.assertFalse('root' in pr['UserGroups'],
                         'collected system groups are not those from root')

    @unittest.skip('fix test as multiple instances can be started within 30s')
    def test_parallel_crash(self):
        '''only one apport instance is ran at a time'''

        test_proc = self.create_test_process()
        test_proc2 = self.create_test_process(False, '/bin/dd')
        try:
            app = subprocess.Popen([self.apport_path, str(test_proc), '42', '0', '1'],
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE)

            time.sleep(0.5)  # give it some time to grab the lock

            app2 = subprocess.Popen([self.apport_path, str(test_proc2), '42', '0', '1'],
                                    stdin=subprocess.PIPE, stderr=subprocess.PIPE)

            # app should wait indefinitely for stdin, while app2 should terminate
            # immediately (give it 5 seconds)
            timeout = 50
            while timeout >= 0:
                if app2.poll():
                    break

                time.sleep(0.1)
                timeout -= 1

            self.assertGreater(timeout, 0, 'second apport instance terminates immediately')
            self.assertFalse(app.poll(), 'first apport instance is still running')

            # properly terminate app and app2
            app2.stdin.close()
            app2.stderr.close()
            app.stdin.write(b'boo')
            app.stdin.close()

            self.assertEqual(app.wait(), 0, app.stderr.read())
            app.stderr.close()
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)
            os.kill(test_proc2, 9)
            os.waitpid(test_proc2, 0)

    def test_unpackaged_binary(self):
        '''unpackaged binaries do not create a report'''

        local_exe = os.path.join(self.workdir, 'mybin')
        with open(local_exe, 'wb') as dest:
            with open(test_executable, 'rb') as src:
                dest.write(src.read())
        os.chmod(local_exe, 0o755)
        self.do_crash(command=local_exe)
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_unpackaged_script(self):
        '''unpackaged scripts do not create a report'''

        local_exe = os.path.join(self.workdir, 'myscript')
        with open(local_exe, 'w') as f:
            f.write('#!/bin/sh\nkill -SEGV $$')
        os.chmod(local_exe, 0o755)
        self.do_crash(command=local_exe)

        # absolute path
        self.assertEqual(apport.fileutils.get_all_reports(), [])

        # relative path
        os.chdir(self.workdir)
        self.do_crash(command='./myscript')
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_ignore_sigquit(self):
        '''apport ignores SIGQUIT'''

        self.do_crash(sig=signal.SIGQUIT)
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_leak_inaccessible_files(self):
        '''existence of user-inaccessible files does not leak'''

        local_exe = os.path.join(self.workdir, 'myscript')
        with open(local_exe, 'w') as f:
            f.write('#!/usr/bin/perl\nsystem("mv $0 $0.exe");\nsystem("ln -sf /etc/shadow $0");\n$0="..$0";\nsleep(10);\n')
        os.chmod(local_exe, 0o755)
        self.do_crash(check_running=False, command=local_exe, sleep=2)

        leak = os.path.join(apport.fileutils.report_dir, '_usr_bin_perl.%i.crash' %
                            (os.getuid()))
        pr = apport.Report()
        with open(leak, 'rb') as f:
            pr.load(f)
        # On a leak, no report is created since the executable path will be replaced
        # by the symlink path, and it doesn't belong to any package.
        self.assertEqual(pr['ExecutablePath'], '/usr/bin/perl')
        self.assertFalse('InterpreterPath' in pr)
        apport.fileutils.delete_report(leak)

    def test_flood_limit(self):
        '''limitation of crash report flood'''

        count = 0
        while count < 7:
            sys.stderr.write('%i ' % count)
            sys.stderr.flush()
            self.do_crash()
            reports = apport.fileutils.get_new_reports()
            if not reports:
                break
            apport.fileutils.mark_report_seen(self.test_report)
            count += 1
        self.assertGreater(count, 1, 'gets at least 2 repeated crashes')
        self.assertLess(count, 7, 'stops flooding after less than 7 repeated crashes')

    @unittest.skipIf(os.access('/run', os.W_OK), 'this test needs to be run as user')
    def test_nonwritable_cwd(self):
        '''core dump works for non-writable cwd'''

        os.chdir('/run')
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
        self.do_crash()
        pr = apport.Report()
        self.assertTrue(os.path.exists(self.test_report))
        self.assertFalse(os.path.exists('/run/core'))
        with open(self.test_report, 'rb') as f:
            pr.load(f)
        assert set(required_fields).issubset(set(pr.keys()))

    @unittest.skipIf(os.access('/run', os.W_OK), 'this test needs to be run as user')
    def test_nonwritable_cwd_nonreadable_exe(self):
        '''no core file for non-readable exe in non-writable cwd'''

        # CVE-2015-1324: if a user cannot read an executable, it behaves much
        # like a suid root binary in terms of writing a core dump

        # create a non-readable executable in a path we can modify which apport
        # regards as likely packaged
        (fd, myexe) = tempfile.mkstemp(dir='/var/tmp')
        self.addCleanup(os.unlink, myexe)
        with open(test_executable, 'rb') as f:
            os.write(fd, f.read())
        os.close(fd)
        os.chmod(myexe, 0o111)

        os.chdir('/run')
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

        if self.suid_dumpable:
            self.do_crash(True, command=myexe, expect_corefile=False)

            # check crash report
            reports = apport.fileutils.get_new_system_reports()
            self.assertEqual(len(reports), 1)
            report = reports[0]
            st = os.stat(report)
            # FIXME: we would like to clean up this, but don't have privileges for that
            # os.unlink(report)
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o640, 'report has correct permissions')
            # this must be owned by root as it is an unreadable binary
            self.assertEqual(st.st_uid, 0, 'report has correct owner')

            # no user reports
            self.assertEqual(apport.fileutils.get_all_reports(), [])
        else:
            # no cores/dump if suid_dumpable == 0
            self.do_crash(False, command=myexe, expect_corefile=False)
            self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_core_dump_packaged(self):
        '''packaged executables create core dumps on proper ulimits'''

        # for SEGV and ABRT we expect reports and core files
        for sig in (signal.SIGSEGV, signal.SIGABRT):
            for (kb, exp_sig, exp_file, exp_report) in core_ulimit_table:
                resource.setrlimit(resource.RLIMIT_CORE, (kb, -1))
                self.do_crash(expect_coredump=exp_sig,
                              expect_corefile=exp_file,
                              expect_corefile_owner=os.geteuid(),
                              sig=sig)
                if exp_report:
                    self.assertEqual(apport.fileutils.get_all_reports(), [self.test_report])
                    self.check_report_coredump(self.test_report)
                    apport.fileutils.delete_report(self.test_report)
                else:
                    self.assertEqual(apport.fileutils.get_all_reports(), [])

            # creates core file with existing crash report, too
            self.do_crash(expect_corefile=True)
            apport.fileutils.delete_report(self.test_report)

        # for SIGQUIT we only expect core files, no report
        resource.setrlimit(resource.RLIMIT_CORE, (1000000, -1))
        self.do_crash(expect_corefile=True, sig=signal.SIGQUIT)
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_core_dump_unpackaged(self):
        '''unpackaged executables create core dumps on proper ulimits'''

        local_exe = os.path.join(self.workdir, 'mybin')
        with open(local_exe, 'wb') as dest:
            with open(test_executable, 'rb') as src:
                dest.write(src.read())
        os.chmod(local_exe, 0o755)

        for sig in (signal.SIGSEGV, signal.SIGABRT, signal.SIGQUIT):
            for (kb, exp_sig, exp_file, exp_report) in core_ulimit_table:
                resource.setrlimit(resource.RLIMIT_CORE, (kb, -1))
                self.do_crash(expect_coredump=exp_sig,
                              expect_corefile=exp_file,
                              expect_corefile_owner=os.geteuid(),
                              command=local_exe,
                              sig=sig)
                self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_core_file_injection(self):
        '''cannot inject core file'''

        # CVE-2015-1325: ensure that apport does not re-open its .crash report,
        # as that allows us to intercept and replace the report and tinker with
        # the core dump

        with open(self.test_report + '.inject', 'w') as f:
            # \x01pwned
            f.write('''ProblemType: Crash
CoreDump: base64
 H4sICAAAAAAC/0NvcmVEdW1wAA==
 Yywoz0tNAQBl1rhlBgAAAA==
''')

        # crash our test process and let it write a core file
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
        pid = self.create_test_process()

        # get the name of the core file
        (core_name, core_path) = apport.fileutils.get_core_path(pid,
                                                                test_executable)

        os.kill(pid, signal.SIGSEGV)

        # replace report with the crafted one above as soon as it exists and
        # becomes deletable for us; this is a busy loop, we need to be really
        # fast to intercept
        while True:
            try:
                os.unlink(self.test_report)
                break
            except OSError:
                pass
        os.rename(self.test_report + '.inject', self.test_report)

        os.waitpid(pid, 0)
        time.sleep(0.5)
        os.sync()

        # verify that we get the original core, not the injected one
        with open(core_path, 'rb') as f:
            core = f.read()
        self.assertNotIn(b'pwned', core)
        self.assertGreater(len(core), 10000)

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

        reports = self.get_temp_all_reports()
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

    def test_ignore(self):
        '''ignoring executables'''

        self.do_crash()

        reports = apport.fileutils.get_all_reports()
        self.assertEqual(len(reports), 1)

        pr = apport.Report()
        with open(reports[0], 'rb') as f:
            pr.load(f)
        os.unlink(reports[0])

        pr.mark_ignore()

        self.do_crash()
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_modify_after_start(self):
        '''ignores executables which got modified after process started'''

        # create executable in a path we can modify which apport regards as
        # likely packaged
        (fd, myexe) = tempfile.mkstemp(dir='/var/tmp')
        self.addCleanup(os.unlink, myexe)
        with open(test_executable, 'rb') as f:
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

            app = subprocess.Popen([self.apport_path, str(test_proc), '42', '0', '1'],
                                   stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            err = app.communicate(b'foo')[1]
            self.assertEqual(app.returncode, 0, err)
            if os.getuid() > 0:
                self.assertIn(b'executable was modified after program start', err)
            else:
                with open('/var/log/apport.log') as f:
                    lines = f.readlines()
                self.assertIn('executable was modified after program start', lines[-1])
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)

        self.assertEqual(self.get_temp_all_reports(), [])

    def test_logging_file(self):
        '''outputs to log file, if available'''

        test_proc = self.create_test_process()
        log = os.path.join(self.workdir, 'apport.log')
        try:
            env = os.environ.copy()
            env['APPORT_LOG_FILE'] = log
            app = subprocess.Popen([self.apport_path, str(test_proc), '42', '0', '1'],
                                   stdin=subprocess.PIPE, env=env,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            (out, err) = app.communicate(b'hel\x01lo')
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)

        self.assertEqual(out, b'')
        self.assertEqual(err, b'')
        self.assertEqual(app.returncode, 0, err)
        with open(log) as f:
            logged = f.read()
        self.assertTrue('called for pid' in logged, logged)
        self.assertTrue('wrote report' in logged, logged)
        self.assertFalse('Traceback' in logged, logged)

        reports = self.get_temp_all_reports()
        self.assertEqual(len(reports), 1)

        pr = apport.Report()
        with open(reports[0], 'rb') as f:
            pr.load(f)
        os.unlink(reports[0])

        self.assertEqual(pr['Signal'], '42')
        self.assertEqual(pr['ExecutablePath'], test_executable)
        self.assertEqual(pr['CoreDump'], b'hel\x01lo')

    def test_logging_stderr(self):
        '''outputs to stderr if log is not available'''

        test_proc = self.create_test_process()
        try:
            env = os.environ.copy()
            env['APPORT_LOG_FILE'] = '/not/existing/apport.log'
            app = subprocess.Popen([self.apport_path, str(test_proc), '42', '0', '1'],
                                   stdin=subprocess.PIPE, env=env,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            (out, err) = app.communicate(b'hel\x01lo')
            err = err.decode('UTF-8')
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)

        self.assertEqual(out, b'')
        self.assertEqual(app.returncode, 0, err)
        self.assertTrue('called for pid' in err, err)
        self.assertTrue('wrote report' in err, err)
        self.assertFalse('Traceback' in err, err)

        reports = self.get_temp_all_reports()
        self.assertEqual(len(reports), 1)

        pr = apport.Report()
        with open(reports[0], 'rb') as f:
            pr.load(f)
        os.unlink(reports[0])

        self.assertEqual(pr['Signal'], '42')
        self.assertEqual(pr['ExecutablePath'], test_executable)
        self.assertEqual(pr['CoreDump'], b'hel\x01lo')

    @unittest.skipIf(os.geteuid() != 0, 'this test needs to be run as root')
    def test_crash_setuid_keep(self):
        '''report generation for setuid program which stays root'''

        # create suid root executable in a path we can modify which apport
        # regards as likely packaged
        (fd, myexe) = tempfile.mkstemp(dir='/var/tmp')
        self.addCleanup(os.unlink, myexe)
        with open(test_executable, 'rb') as f:
            os.write(fd, f.read())
        os.close(fd)
        os.chmod(myexe, 0o4755)

        # run test program as user "mail"
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

        if self.suid_dumpable:
            # if a user can crash a suid root binary, it should not create core files
            self.do_crash(command=myexe, uid=8)

            # check crash report
            reports = apport.fileutils.get_all_reports()
            self.assertEqual(len(reports), 1)
            report = reports[0]
            st = os.stat(report)
            os.unlink(report)
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o640, 'report has correct permissions')
            # this must be owned by root as it is a setuid binary
            self.assertEqual(st.st_uid, 0, 'report has correct owner')
        else:
            # no cores/dump if suid_dumpable == 0
            self.do_crash(False, command=myexe, expect_corefile=False, uid=8)
            self.assertEqual(apport.fileutils.get_all_reports(), [])

    @unittest.skipIf(os.geteuid() != 0, 'this test needs to be run as root')
    def test_crash_system_slice(self):
        '''report generation for a protected process running in the system slice'''

        self.create_test_process(command='/usr/bin/systemd-run',
                                 args=['-t', '-q', '--slice=system.slice',
                                       '-p', 'ProtectSystem=true',
                                       '/usr/bin/yes'])
        yes_pids = pidof('/usr/bin/yes')
        self.assertEqual(len(yes_pids), 1)
        os.kill(yes_pids.pop(), signal.SIGSEGV)

        self.wait_for_apport_to_finish()

        # check crash report
        reports = apport.fileutils.get_all_reports()
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0], '/var/crash/_usr_bin_yes.0.crash')

    @unittest.skipUnless(os.path.exists('/bin/ping'), 'this test needs /bin/ping')
    @unittest.skipIf(os.geteuid() != 0, 'this test needs to be run as root')
    def test_crash_setuid_drop(self):
        '''report generation for setuid program which drops root'''

        # run ping as user "mail"
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

        if self.suid_dumpable:
            # if a user can crash a suid root binary, it should not create core files
            self.do_crash(command='/bin/ping', args=['127.0.0.1'], uid=8)

            # check crash report
            reports = apport.fileutils.get_all_reports()
            self.assertEqual(len(reports), 1)
            report = reports[0]
            st = os.stat(report)
            os.unlink(report)
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o640, 'report has correct permissions')
            # this must be owned by root as it is a setuid binary
            self.assertEqual(st.st_uid, 0, 'report has correct owner')
        else:
            # no cores/dump if suid_dumpable == 0
            self.do_crash(False, command='/bin/ping', args=['127.0.0.1'],
                          uid=8)
            self.assertEqual(apport.fileutils.get_all_reports(), [])

    @unittest.skipUnless(os.path.exists('/bin/ping'), 'this test needs /bin/ping')
    @unittest.skipIf(os.geteuid() != 0, 'this test needs to be run as root')
    def test_crash_setuid_drop_and_kill(self):
        '''process started by root as another user, killed by that user no core'''
        # override expected report file name
        self.test_report = os.path.join(
            apport.fileutils.report_dir, '%s.%i.crash' %
            ('_usr_bin_crontab', os.getuid()))
        # edit crontab as user "mail"
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

        if self.suid_dumpable:
            user = pwd.getpwuid(8)
            # if a user can crash a suid root binary, it should not create core files
            orig_editor = os.getenv('EDITOR')
            os.environ['EDITOR'] = '/usr/bin/yes'
            self.do_crash(command='/usr/bin/crontab', args=['-e', '-u', user[0]],
                          expect_corefile=False, core_location='/var/spool/cron/',
                          killer_id=8)
            if orig_editor is not None:
                os.environ['EDITOR'] = orig_editor

            # check crash report
            reports = apport.fileutils.get_all_reports()
            self.assertEqual(len(reports), 1)
            report = reports[0]
            st = os.stat(report)
            os.unlink(report)
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o640, 'report has correct permissions')
            # this must be owned by root as it is a setuid binary
            self.assertEqual(st.st_uid, 0, 'report has correct owner')
        else:
            # no cores/dump if suid_dumpable == 0
            self.do_crash(False, command='/bin/ping', args=['127.0.0.1'],
                          uid=8)
            self.assertEqual(apport.fileutils.get_all_reports(), [])

    @unittest.skipIf(os.geteuid() != 0, 'this test needs to be run as root')
    def test_crash_setuid_unpackaged(self):
        '''report generation for unpackaged setuid program'''

        # create suid root executable in a path we can modify which apport
        # regards as not packaged
        (fd, myexe) = tempfile.mkstemp(dir='/tmp')
        self.addCleanup(os.unlink, myexe)
        with open(test_executable, 'rb') as f:
            os.write(fd, f.read())
        os.close(fd)
        os.chmod(myexe, 0o4755)

        # run test program as user "mail"
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

        if self.suid_dumpable:
            # if a user can crash a suid root binary, it should not create core files
            self.do_crash(command=myexe, expect_corefile=False, uid=8)
        else:
            # no cores/dump if suid_dumpable == 0
            self.do_crash(False, command=myexe, expect_corefile=False, uid=8)

        # there should not be a crash report
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    @unittest.skipIf(os.geteuid() != 0, 'this test needs to be run as root')
    def test_crash_setuid_nonwritable_cwd(self):
        '''report generation and core dump for setuid program, non-writable cwd'''

        # create suid root executable in a path we can modify which apport
        # regards as likely packaged
        (fd, myexe) = tempfile.mkstemp(dir='/var/tmp')
        self.addCleanup(os.unlink, myexe)
        with open(test_executable, 'rb') as f:
            os.write(fd, f.read())
        os.close(fd)
        os.chmod(myexe, 0o4755)

        # run test program as user "mail" in /run (which should only be
        # writable to root)
        os.chdir('/run')
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

        if self.suid_dumpable:
            # we expect a report, but no core file
            self.do_crash(command=myexe, expect_corefile=False, uid=8)

            # check crash report
            reports = apport.fileutils.get_all_reports()
            self.assertEqual(len(reports), 1)
            report = reports[0]
            st = os.stat(report)
            os.unlink(report)
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o640, 'report has correct permissions')
            # this must be owned by root as it is a setuid binary
            self.assertEqual(st.st_uid, 0, 'report has correct owner')
        else:
            # no core/report if suid_dumpable == 0
            self.do_crash(False, command=myexe, expect_corefile=False, uid=8)
            self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_coredump_from_socket(self):
        '''forwarding of a core dump through socket

        This is being used in a container via systemd activation, where the
        core dump gets read from /run/apport.socket.
        '''
        socket_path = os.path.join(self.workdir, 'apport.socket')
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
                    fd.write(b'hel\x01lo')
                    fd.flush()
                    fd.seek(0)
                    args = '%s 11 0 1' % test_proc
                    fd_msg = (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd.fileno()]))
                    client.sendmsg([args.encode()], [fd_msg])
                os._exit(0)

            # call apport like systemd does via socket activation
            def child_setup():
                os.environ['LISTEN_FDNAMES'] = 'connection'
                os.environ['LISTEN_FDS'] = '1'
                os.environ['LISTEN_PID'] = str(os.getpid())
                # socket from server becomes fd 3 (SD_LISTEN_FDS_START)
                conn = server.accept()[0]
                os.dup2(conn.fileno(), 3)

            app = subprocess.Popen([self.apport_path], preexec_fn=child_setup,
                                   pass_fds=[3], stderr=subprocess.PIPE)
            log = app.communicate()[1]
            self.assertEqual(app.returncode, 0, log)
            server.close()
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)

        reports = self.get_temp_all_reports()
        self.assertEqual(len(reports), 1)
        pr = apport.Report()
        with open(reports[0], 'rb') as f:
            pr.load(f)
        os.unlink(reports[0])
        self.assertEqual(pr['Signal'], '11')
        self.assertEqual(pr['ExecutablePath'], test_executable)
        self.assertEqual(pr['CoreDump'], b'hel\x01lo')

        # should not create report on the host
        self.assertEqual(apport.fileutils.get_all_system_reports(), [])

    #
    # Helper methods
    #

    @classmethod
    def create_test_process(klass, check_running=True, command=test_executable,
                            uid=None, args=[]):
        '''Spawn test_executable.

        Wait until it is fully running, and return its PID.
        '''
        assert os.access(command, os.X_OK), command + ' is not executable'
        if check_running:
            assert pidof(command) == set(), 'no running test executable processes'
        pid = os.fork()
        if pid == 0:
            if uid is not None:
                os.setuid(uid)
            # set UTF-8 environment variable, to check proper parsing in apport
            os.putenv('utf8trap', b'\xc3\xa0\xc3\xa4')
            os.dup2(os.open('/dev/null', os.O_WRONLY), sys.stdout.fileno())
            sys.stdin.close()
            os.setsid()
            os.execv(command, [command] + args)
            assert False, 'Could not execute ' + command

        # wait until child process has execv()ed properly
        while True:
            with open('/proc/%i/cmdline' % pid) as f:
                cmdline = f.read()
            if 'test_signal' in cmdline:
                time.sleep(0.1)
            else:
                break

        time.sleep(0.3)  # needs some more setup time
        return pid

    def do_crash(self, expect_coredump=True, expect_corefile=False,
                 sig=signal.SIGSEGV, check_running=True, sleep=0,
                 command=test_executable, uid=None,
                 expect_corefile_owner=None,
                 core_location=None,
                 killer_id=False, args=[]):
        '''Generate a test crash.

        This runs command (by default test_executable) in cwd, lets it crash,
        and checks that it exits with the expected return code, leaving a core
        file behind if expect_corefile is set, and generating a crash report if
        expect_coredump is set.

        If check_running is set (default), this will abort if test_process is
        already running.
        '''
        self.assertFalse(os.path.exists('core'), '%s/core already exists, please clean up first' % os.getcwd())
        pid = self.create_test_process(check_running, command, uid=uid, args=args)

        (core_name, core_path) = apport.fileutils.get_core_path(pid,
                                                                command,
                                                                uid)

        if sleep > 0:
            time.sleep(sleep)
        if killer_id:
            user = pwd.getpwuid(killer_id)
            # testing different editors via VISUAL= didn't help
            kill = subprocess.Popen(['sudo', '-s', '/bin/bash', '-c',
                                     "/bin/kill -s %i %s" % (sig, pid),
                                     '-u', user[0]])  # 'mail'])
            kill.communicate()
            # need to clean up system state
            if command == '/usr/bin/crontab':
                os.system('stty sane')
            if kill.returncode != 0:
                self.fail("Couldn't kill process %s as user %s." %
                          (pid, user[0]))
        else:
            os.kill(pid, sig)
        # wait max 5 seconds for the process to die
        timeout = 50
        while timeout >= 0:
            (p, result) = os.waitpid(pid, os.WNOHANG)
            if p != 0:
                break
            time.sleep(0.1)
            timeout -= 1
        else:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            self.fail('test process does not die on signal %i' % sig)
        if command == '/usr/bin/crontab':
            subprocess.Popen(['sudo', '-s', '/bin/bash', '-c',
                              "/usr/bin/pkill -9 -f crontab",
                              '-u', 'mail'])
        self.assertFalse(os.WIFEXITED(result), 'test process did not exit normally')
        self.assertTrue(os.WIFSIGNALED(result), 'test process died due to signal')
        self.assertEqual(os.WCOREDUMP(result), expect_coredump)
        self.assertEqual(os.WSTOPSIG(result), 0, 'test process was not signaled to stop')
        self.assertEqual(os.WTERMSIG(result), sig, 'test process died due to proper signal')

        self.wait_for_apport_to_finish()
        if check_running:
            self.assertEqual(pidof(command), set(),
                             'no running test executable processes')

        if core_location:
            core_path = '%s/core' % core_location

        if expect_corefile:
            self.assertTrue(os.path.exists(core_path), 'leaves wanted core file')
            try:
                # check core file permissions
                st = os.stat(core_path)
                self.assertEqual(stat.S_IMODE(st.st_mode), 0o400, 'core file has correct permissions')
                if expect_corefile_owner is not None:
                    self.assertEqual(st.st_uid, expect_corefile_owner, 'core file has correct owner')

                # check that core file is valid
                gdb = subprocess.Popen(['gdb', '--batch', '--ex', 'bt',
                                        command, core_path],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
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
                except OSError as e:
                    sys.stderr.write(
                        'WARNING: cannot clean up core file %s: %s\n' %
                        (core_path, str(e)))

                self.fail('leaves unexpected core file behind')

    def get_temp_all_reports(self):
        '''Call apport.fileutils.get_all_reports() for our temp dir'''

        old_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = self.report_dir
        reports = apport.fileutils.get_all_reports()
        apport.fileutils.report_dir = old_dir
        return reports

    def check_report_coredump(self, report_path):
        '''Check that given report file has a valid core dump'''

        r = apport.Report()
        with open(report_path, 'rb') as f:
            r.load(f)
        self.assertTrue('CoreDump' in r)
        self.assertGreater(len(r['CoreDump']), 5000)
        r.add_gdb_info()
        self.assertTrue('\n#2' in r.get('Stacktrace', ''),
                        r.get('Stacktrace', 'no Stacktrace field'))

    def wait_for_apport_to_finish(self, timeout_sec=10.0):
        self.wait_for_no_instance_running('apport', timeout_sec)

    def wait_for_no_instance_running(self, program, timeout_sec=10.0):
        while timeout_sec > 0:
            if not pidof(program):
                break
            time.sleep(0.2)
            timeout_sec -= 0.2
        else:
            self.fail(f"Timeout exceeded, but {program} is still running.")


#
# main
#

if __name__ == "__main__":
    unittest.main()
