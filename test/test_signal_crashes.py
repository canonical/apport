# Copyright (C) 2007 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import tempfile, shutil, os, subprocess, signal, time, stat, sys
import resource, errno, grp, unittest
import apport.fileutils

test_executable = '/usr/bin/yes'
test_package = 'coreutils'
test_source = 'coreutils'

required_fields = ['ProblemType', 'CoreDump', 'Date', 'ExecutablePath',
    'ProcCmdline', 'ProcEnviron', 'ProcMaps', 'Signal', 'UserGroups']

ifpath = os.path.expanduser(apport.report._ignore_file)


class T(unittest.TestCase):
    def setUp(self):
        # use local report dir
        self.report_dir = tempfile.mkdtemp()
        os.environ['APPORT_REPORT_DIR'] = self.report_dir

        self.workdir = tempfile.mkdtemp()

        # move aside current ignore file
        if os.path.exists(ifpath):
            os.rename(ifpath, ifpath + '.apporttest')

        # do not write core files by default
        resource.setrlimit(resource.RLIMIT_CORE, (0, -1))

        # that's the place where to put core dumps, etc.
        os.chdir('/tmp')

        # expected report name for test executable report
        self.test_report = os.path.join(apport.fileutils.report_dir,
                '%s.%i.crash' % (test_executable.replace('/', '_'), os.getuid()))

    def tearDown(self):
        shutil.rmtree(self.report_dir)
        shutil.rmtree(self.workdir)

        # clean up our ignore file
        if os.path.exists(ifpath):
            os.unlink(ifpath)
        orig_ignore_file = ifpath + '.apporttest'
        if os.path.exists(orig_ignore_file):
            os.rename(orig_ignore_file, ifpath)

        # permit tests to leave behind test_report, but nothing else
        if os.path.exists(self.test_report):
            apport.fileutils.delete_report(self.test_report)
        self.assertEqual(apport.fileutils.get_all_reports(), [])

    def test_empty_core_dump(self):
        '''empty core dumps do not generate a report'''

        test_proc = self.create_test_process()
        try:
            app = subprocess.Popen([apport_path, str(test_proc), '42', '0'],
                close_fds=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            app.stdin.close()
            assert app.wait() == 0, app.stderr.read()
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
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o640,
                'report has correct permissions')

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
            'LC_COLLATE', 'LC_TIME', 'LC_NUMERIC', 'LC_MONETARY', 'LC_MESSAGES',
            'LC_PAPER', 'LC_NAME', 'LC_ADDRESS', 'LC_TELEPHONE', 'LC_MEASUREMENT',
            'LC_IDENTIFICATION', 'LOCPATH', 'TERM']

        for l in pr['ProcEnviron'].splitlines():
            (k, v) = l.split('=', 1)
            self.assertTrue(k in allowed_vars,
                    'report contains sensitive environment variable %s' % k)

        # UserGroups only has system groups
        for g in pr['UserGroups'].split():
            self.assertLess(grp.getgrnam(g).gr_gid, 500)

        self.assertFalse('root' in pr['UserGroups'],
                'collected system groups are not those from root')

    def test_parallel_crash(self):
        '''only one apport instance is ran at a time'''

        test_proc = self.create_test_process()
        test_proc2 = self.create_test_process(False, '/bin/dd')
        try:
            app = subprocess.Popen([apport_path, str(test_proc), '42', '0'],
                close_fds=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)

            time.sleep(0.5)  # give it some time to grab the lock

            app2 = subprocess.Popen([apport_path, str(test_proc2), '42', '0'],
                close_fds=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)

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
            app.stdin.write(b'boo')
            app.stdin.close()

            self.assertEqual(app.wait(), 0, app.stderr.read())
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)
            os.kill(test_proc2, 9)
            os.waitpid(test_proc2, 0)

    def test_lock_symlink(self):
        '''existing .lock file as dangling symlink does not create the file

        This would be a vulnerability, as users could overwrite system files.
        '''
        # prepare a symlink trap
        lockpath = os.path.join(self.report_dir, '.lock')
        trappath = os.path.join(self.report_dir, '0wned')
        os.symlink(trappath, lockpath)

        # now call apport
        test_proc = self.create_test_process()

        try:
            app = subprocess.Popen([apport_path, str(test_proc), '42', '0'],
                close_fds=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            app.stdin.write(b'boo')
            app.stdin.close()

            self.assertNotEqual(app.wait(), 0, app.stderr.read())
        finally:
            os.kill(test_proc, 9)
            os.waitpid(test_proc, 0)

        self.assertEqual(self.get_temp_all_reports(), [])
        self.assertFalse(os.path.exists(trappath))

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

    def test_nonwritable_cwd(self):
        '''core dump works for non-writable cwd'''

        os.chdir('/')
        self.do_crash()
        pr = apport.Report()
        self.assertTrue(os.path.exists(self.test_report))
        with open(self.test_report, 'rb') as f:
            pr.load(f)
        assert set(required_fields).issubset(set(pr.keys()))

    def test_core_dump_packaged(self):
        '''packaged executables create core dumps on proper ulimits'''

        # for SIGSEGV
        resource.setrlimit(resource.RLIMIT_CORE, (1, -1))
        self.do_crash(expect_coredump=False, expect_corefile=False)
        self.assertEqual(apport.fileutils.get_all_reports(), [])
        resource.setrlimit(resource.RLIMIT_CORE, (10, -1))
        self.do_crash(expect_corefile=False)
        self.assertEqual(apport.fileutils.get_all_reports(), [])
        apport.fileutils.delete_report(self.test_report)
        resource.setrlimit(resource.RLIMIT_CORE, (10000, -1))
        self.do_crash(expect_corefile=True)
        self.assertEqual(apport.fileutils.get_all_reports(), [self.test_report])
        apport.fileutils.delete_report(self.test_report)
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
        self.do_crash(expect_corefile=True)
        self.assertEqual(apport.fileutils.get_all_reports(), [self.test_report])
        apport.fileutils.delete_report(self.test_report)

        # for SIGABRT
        resource.setrlimit(resource.RLIMIT_CORE, (1, -1))
        self.do_crash(expect_coredump=False, expect_corefile=False, sig=signal.SIGABRT)
        apport.fileutils.delete_report(self.test_report)
        resource.setrlimit(resource.RLIMIT_CORE, (10, -1))
        self.do_crash(expect_corefile=False, sig=signal.SIGABRT)
        apport.fileutils.delete_report(self.test_report)
        resource.setrlimit(resource.RLIMIT_CORE, (10000, -1))
        self.do_crash(expect_corefile=True, sig=signal.SIGABRT)
        apport.fileutils.delete_report(self.test_report)
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
        self.do_crash(expect_corefile=True, sig=signal.SIGABRT)
        apport.fileutils.delete_report(self.test_report)

        # creates core file with existing crash report, too
        self.do_crash(expect_corefile=True)

    def test_core_dump_unpackaged(self):
        '''unpackaged executables create core dumps on proper ulimits'''

        local_exe = os.path.join(self.workdir, 'mybin')
        with open(local_exe, 'wb') as dest:
            with open(test_executable, 'rb') as src:
                dest.write(src.read())
        os.chmod(local_exe, 0o755)

        # for SIGSEGV
        resource.setrlimit(resource.RLIMIT_CORE, (1, -1))
        self.do_crash(expect_coredump=False, expect_corefile=False, command=local_exe)
        self.assertEqual(apport.fileutils.get_all_reports(), [])
        resource.setrlimit(resource.RLIMIT_CORE, (10, -1))
        self.assertEqual(apport.fileutils.get_all_reports(), [])
        resource.setrlimit(resource.RLIMIT_CORE, (10000, -1))
        self.do_crash(expect_corefile=True, command=local_exe)
        self.assertEqual(apport.fileutils.get_all_reports(), [])
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
        self.do_crash(expect_corefile=True, command=local_exe)
        self.assertEqual(apport.fileutils.get_all_reports(), [])

        # for SIGABRT
        resource.setrlimit(resource.RLIMIT_CORE, (1, -1))
        self.do_crash(expect_coredump=False, expect_corefile=False, command=local_exe, sig=signal.SIGABRT)
        self.assertEqual(apport.fileutils.get_all_reports(), [])
        resource.setrlimit(resource.RLIMIT_CORE, (10, -1))
        self.do_crash(expect_corefile=False, command=local_exe, sig=signal.SIGABRT)
        self.assertEqual(apport.fileutils.get_all_reports(), [])
        resource.setrlimit(resource.RLIMIT_CORE, (10000, -1))
        self.do_crash(expect_corefile=True, command=local_exe, sig=signal.SIGABRT)
        self.assertEqual(apport.fileutils.get_all_reports(), [])
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
        self.do_crash(expect_corefile=True, command=local_exe, sig=signal.SIGABRT)
        self.assertEqual(apport.fileutils.get_all_reports(), [])

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
            app = subprocess.Popen([apport_path, str(test_proc), '42', '0'],
                close_fds=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
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
            app.stdin.close()
            self.assertEqual(app.wait(), 0, app.stderr.read())
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
        try:
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

                app = subprocess.Popen([apport_path, str(test_proc), '42', '0'],
                    close_fds=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
                app.stdin.write(b'boo')
                app.stdin.close()
                err = app.stderr.read().decode()
                self.assertNotEqual(app.wait(), 0, err)
            finally:
                os.kill(test_proc, 9)
                os.waitpid(test_proc, 0)

            self.assertEqual(self.get_temp_all_reports(), [])
        finally:
            os.unlink(myexe)

    #
    # Helper methods
    #

    @classmethod
    def create_test_process(klass, check_running=True, command=test_executable):
        '''Spawn test_executable.

        Wait until it is fully running, and return its PID.
        '''
        assert os.access(command, os.X_OK), command + ' is not executable'
        if check_running:
            assert subprocess.call(['pidof', command]) == 1, 'no running test executable processes'
        pid = os.fork()
        if pid == 0:
            os.dup2(os.open('/dev/null', os.O_WRONLY), sys.stdout.fileno())
            sys.stdin.close()
            os.setsid()
            os.execv(command, [command])
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
                 command=test_executable):
        '''Generate a test crash.

        This runs command (by default test_executable) in /tmp, lets it crash,
        and checks that it exits with the expected return code, leaving a core
        file behind if expect_corefile is set, and generating a crash report if
        expect_coredump is set.

        If check_running is set (default), this will abort if test_process is
        already running.
        '''
        self.assertFalse(os.path.exists('core'), '/tmp/core already exists, please clean up first')
        pid = self.create_test_process(check_running, command)
        if sleep > 0:
            time.sleep(sleep)
        os.kill(pid, sig)
        result = os.waitpid(pid, 0)[1]
        self.assertFalse(os.WIFEXITED(result), 'test process did not exit normally')
        self.assertTrue(os.WIFSIGNALED(result), 'test process died due to signal')
        self.assertEqual(os.WCOREDUMP(result), expect_coredump)
        self.assertEqual(os.WSTOPSIG(result), 0, 'test process was not signaled to stop')
        self.assertEqual(os.WTERMSIG(result), sig, 'test process died due to proper signal')

        # wait max 10 seconds for apport to finish
        timeout = 50
        while timeout >= 0:
            if subprocess.call(['pidof', '-x', 'apport'], stdout=subprocess.PIPE) != 0:
                break
            time.sleep(0.2)
            timeout -= 1
        self.assertGreater(timeout, 0)
        if check_running:
            self.assertEqual(subprocess.call(['pidof', command]), 1,
                    'no running test executable processes')

        if expect_corefile:
            self.assertTrue(os.path.exists('/tmp/core'), 'leaves wanted core file')
            try:
                # check that core file is valid
                gdb = subprocess.Popen(['gdb', '--batch', '--ex', 'bt',
                    command, '/tmp/core'], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
                (out, err) = gdb.communicate()
                self.assertEqual(gdb.returncode, 0)
                out = out.decode()
                err = err.decode().strip()
                self.assertTrue(err == '' or err.startswith('warning'), err)
            finally:
                os.unlink('/tmp/core')
        else:
            self.assertFalse(os.path.exists('/tmp/core'), 'leaves unexpected core file behind')

    def get_temp_all_reports(self):
        '''Call apport.fileutils.get_all_reports() for our temp dir'''

        old_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = self.report_dir
        reports = apport.fileutils.get_all_reports()
        apport.fileutils.report_dir = old_dir
        return reports

#
# main
#

with open('/proc/sys/kernel/core_pattern') as f:
    core_pattern = f.read().strip()
if core_pattern[0] != '|':
    sys.stderr.write('kernel crash dump helper is not active; please enable before running this test.\n')
    sys.exit(0)
apport_path = core_pattern[1:].split()[0]

if apport.fileutils.get_all_reports():
    sys.stderr.write('Please remove all crash reports from /var/crash/ for this test suite\n')
    sys.exit(1)

unittest.main()
