# coding: UTF-8
import unittest, shutil, time, tempfile, os, subprocess, grp, atexit, re

import apport.report
import problem_report
import apport.packaging


class T(unittest.TestCase):
    def test_add_package_info(self):
        '''add_package_info().'''

        # determine bash version
        bashversion = apport.packaging.get_version('bash')

        pr = apport.report.Report()
        self.assertRaises(ValueError, pr.add_package_info, 'nonexistant_package')

        pr.add_package_info('bash')
        self.assertEqual(pr['Package'], 'bash ' + bashversion.strip())
        self.assertEqual(pr['SourcePackage'], 'bash')
        self.assertTrue('libc' in pr['Dependencies'])

        # test without specifying a package, but with ExecutablePath
        pr = apport.report.Report()
        self.assertRaises(KeyError, pr.add_package_info)
        pr['ExecutablePath'] = '/bin/bash'
        pr.add_package_info()
        self.assertEqual(pr['Package'], 'bash ' + bashversion.strip())
        self.assertEqual(pr['SourcePackage'], 'bash')
        self.assertTrue('libc' in pr['Dependencies'])
        # check for stray empty lines
        self.assertTrue('\n\n' not in pr['Dependencies'])
        self.assertTrue('PackageArchitecture' in pr)

        pr = apport.report.Report()
        pr['ExecutablePath'] = '/nonexisting'
        pr.add_package_info()
        self.assertTrue('Package' not in pr)

    def test_add_os_info(self):
        '''add_os_info().'''

        pr = apport.report.Report()
        pr.add_os_info()
        self.assertTrue(pr['Uname'].startswith('Linux'))
        self.assertTrue(hasattr(pr['DistroRelease'], 'startswith'))
        self.assertGreater(len(pr['DistroRelease']), 5)
        self.assertTrue(pr['Architecture'])

    def test_add_user_info(self):
        '''add_user_info().'''

        pr = apport.report.Report()
        pr.add_user_info()
        self.assertTrue('UserGroups' in pr)

        # double-check that user group names are removed
        for g in pr['UserGroups'].split():
            self.assertTrue(grp.getgrnam(g).gr_gid < 1000)
        self.assertTrue(grp.getgrgid(os.getgid()).gr_name not in pr['UserGroups'])

    def test_add_proc_info(self):
        '''add_proc_info().'''

        # set test environment
        assert 'LANG' in os.environ, 'please set $LANG for this test'

        # check without additional safe environment variables
        pr = apport.report.Report()
        self.assertEqual(pr.pid, None)
        pr.add_proc_info()
        self.assertEqual(pr.pid, os.getpid())
        self.assertTrue(set(['ProcEnviron', 'ProcMaps', 'ProcCmdline',
            'ProcMaps']).issubset(set(pr.keys())), 'report has required fields')
        self.assertTrue('LANG=' + os.environ['LANG'] in pr['ProcEnviron'])
        self.assertTrue('USER' not in pr['ProcEnviron'])
        self.assertTrue('PWD' not in pr['ProcEnviron'])
        self.assertTrue('report.py' in pr['ExecutablePath'])
        self.assertEqual(int(pr['ExecutableTimestamp']),
                int(os.stat(__file__).st_mtime))

        # check with one additional safe environment variable
        pr = apport.report.Report()
        pr.add_proc_info(extraenv=['PWD'])
        self.assertTrue('USER' not in pr['ProcEnviron'])
        if 'PWD' in os.environ:
            self.assertTrue('PWD=' + os.environ['PWD'] in pr['ProcEnviron'])

        # check process from other user
        restore_root = False
        if os.getuid() == 0:
            # temporarily drop to normal user "mail"
            os.setresuid(8, 8, -1)
            restore_root = True
        pr = apport.report.Report()
        self.assertRaises(OSError, pr.add_proc_info, 1)  # EPERM for init process
        if restore_root:
            os.setresuid(0, 0, -1)

        self.assertEqual(pr.pid, 1)
        self.assertTrue('init' in pr['ProcStatus'], pr['ProcStatus'])
        self.assertTrue(pr['ProcEnviron'].startswith('Error:'), pr['ProcEnviron'])
        self.assertTrue('InterpreterPath' not in pr)

        # check escaping of ProcCmdline
        p = subprocess.Popen(['cat', '/foo bar', '\\h', '\\ \\', '-'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True)
        assert p.pid
        # wait until /proc/pid/cmdline exists
        while True:
            with open('/proc/%i/cmdline' % p.pid) as fd:
                if fd.read():
                    break
                time.sleep(0.1)
        pr = apport.report.Report()
        pr.add_proc_info(pid=p.pid)
        self.assertEqual(pr.pid, p.pid)
        p.communicate(b'\n')
        self.assertEqual(pr['ProcCmdline'], 'cat /foo\ bar \\\\h \\\\\\ \\\\ -')
        self.assertEqual(pr['ExecutablePath'], '/bin/cat')
        self.assertTrue('InterpreterPath' not in pr)
        self.assertTrue('/bin/cat' in pr['ProcMaps'])
        self.assertTrue('[stack]' in pr['ProcMaps'])

        # check correct handling of executable symlinks
        assert os.path.islink('/bin/sh'), '/bin/sh needs to be a symlink for this test'
        p = subprocess.Popen(['sh'], stdin=subprocess.PIPE,
            close_fds=True)
        assert p.pid
        # wait until /proc/pid/cmdline exists
        while True:
            with open('/proc/%i/cmdline' % p.pid) as fd:
                if fd.read():
                    break
                time.sleep(0.1)
        pr = apport.report.Report()
        pr.pid = p.pid
        pr.add_proc_info()
        p.communicate(b'exit\n')
        self.assertFalse('InterpreterPath' in pr, pr.get('InterpreterPath'))
        self.assertEqual(pr['ExecutablePath'], os.path.realpath('/bin/sh'))
        self.assertEqual(int(pr['ExecutableTimestamp']),
                int(os.stat(os.path.realpath('/bin/sh')).st_mtime))

        # check correct handling of interpreted executables: shell
        p = subprocess.Popen(['zgrep', 'foo'], stdin=subprocess.PIPE,
            close_fds=True)
        assert p.pid
        # wait until /proc/pid/cmdline exists
        while True:
            with open('/proc/%i/cmdline' % p.pid) as fd:
                if fd.read():
                    break
                time.sleep(0.1)
        pr = apport.report.Report()
        pr.add_proc_info(pid=p.pid)
        p.communicate(b'\n')
        self.assertTrue(pr['ExecutablePath'].endswith('bin/zgrep'))
        with open(pr['ExecutablePath']) as fd:
            self.assertEqual(pr['InterpreterPath'],
                os.path.realpath(fd.readline().strip()[2:]))
        self.assertEqual(int(pr['ExecutableTimestamp']),
                int(os.stat(pr['ExecutablePath']).st_mtime))
        self.assertTrue('[stack]' in pr['ProcMaps'])

        # check correct handling of interpreted executables: python
        (fd, testscript) = tempfile.mkstemp()
        os.write(fd, ('''#!/usr/bin/%s
import sys
sys.stdin.readline()
''' % os.getenv('PYTHON', 'python3')).encode('ascii'))
        os.close(fd)
        os.chmod(testscript, 0o755)
        p = subprocess.Popen([testscript], stdin=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True)
        assert p.pid
        # wait until /proc/pid/cmdline exists
        while True:
            with open('/proc/%i/cmdline' % p.pid) as fd:
                if fd.read():
                    break
                time.sleep(0.1)
        pr = apport.report.Report()
        pr.add_proc_info(pid=p.pid)
        p.communicate(b'\n')
        self.assertEqual(pr['ExecutablePath'], testscript)
        self.assertEqual(int(pr['ExecutableTimestamp']),
                int(os.stat(testscript).st_mtime))
        os.unlink(testscript)
        self.assertTrue('python' in pr['InterpreterPath'])
        self.assertTrue('python' in pr['ProcMaps'])
        self.assertTrue('[stack]' in pr['ProcMaps'])

        # test process is gone, should complain about nonexisting PID
        self.assertRaises(ValueError, pr.add_proc_info, p.pid)

    def test_add_path_classification(self):
        '''classification of $PATH.'''

        # system default
        p = subprocess.Popen(['cat'], stdin=subprocess.PIPE,
            env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games'})
        time.sleep(0.1)
        r = apport.report.Report()
        r.add_proc_environ(pid=p.pid)
        p.communicate(b'')
        self.assertFalse('PATH' in r['ProcEnviron'],
            'system default $PATH should be filtered out')

        # no user paths
        p = subprocess.Popen(['cat'], stdin=subprocess.PIPE,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
        time.sleep(0.1)
        r = apport.report.Report()
        r.add_proc_environ(pid=p.pid)
        p.communicate(b'')
        self.assertTrue('PATH=(custom, no user)' in r['ProcEnviron'],
            'PATH is customized without user paths')

        # user paths
        p = subprocess.Popen(['cat'], stdin=subprocess.PIPE,
            env={'PATH': '/home/pitti:/usr/sbin:/usr/bin:/sbin:/bin'})
        time.sleep(0.1)
        r = apport.report.Report()
        r.add_proc_environ(pid=p.pid)
        p.communicate(b'')
        self.assertTrue('PATH=(custom, user)' in r['ProcEnviron'],
            'PATH is customized with user paths')

    def test_check_interpreted(self):
        '''_check_interpreted().'''

        restore_root = False
        if os.getuid() == 0:
            # temporarily drop to normal user "mail"
            os.setresuid(8, 8, -1)
            restore_root = True

        try:
            # standard ELF binary
            f = tempfile.NamedTemporaryFile()
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/usr/bin/gedit'
            pr['ProcStatus'] = 'Name:\tgedit'
            pr['ProcCmdline'] = 'gedit\0/' + f.name
            pr._check_interpreted()
            self.assertEqual(pr['ExecutablePath'], '/usr/bin/gedit')
            self.assertFalse('InterpreterPath' in pr)
            f.close()

            # bogus argv[0]
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/bin/dash'
            pr['ProcStatus'] = 'Name:\tznonexisting'
            pr['ProcCmdline'] = 'nonexisting\0/foo'
            pr._check_interpreted()
            self.assertEqual(pr['ExecutablePath'], '/bin/dash')
            self.assertFalse('InterpreterPath' in pr)

            # standard sh script
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/bin/dash'
            pr['ProcStatus'] = 'Name:\tzgrep'
            pr['ProcCmdline'] = '/bin/sh\0/bin/zgrep\0foo'
            pr._check_interpreted()
            self.assertEqual(pr['ExecutablePath'], '/bin/zgrep')
            self.assertEqual(pr['InterpreterPath'], '/bin/dash')

            # standard sh script when being called explicitly with interpreter
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/bin/dash'
            pr['ProcStatus'] = 'Name:\tdash'
            pr['ProcCmdline'] = '/bin/sh\0/bin/zgrep\0foo'
            pr._check_interpreted()
            self.assertEqual(pr['ExecutablePath'], '/bin/zgrep')
            self.assertEqual(pr['InterpreterPath'], '/bin/dash')

            # special case mono scheme: beagled-helper (use zgrep to make the test
            # suite work if mono or beagle are not installed)
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/usr/bin/mono'
            pr['ProcStatus'] = 'Name:\tzgrep'
            pr['ProcCmdline'] = 'zgrep\0--debug\0/bin/zgrep'
            pr._check_interpreted()
            self.assertEqual(pr['ExecutablePath'], '/bin/zgrep')
            self.assertEqual(pr['InterpreterPath'], '/usr/bin/mono')

            # special case mono scheme: banshee (use zgrep to make the test
            # suite work if mono or beagle are not installed)
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/usr/bin/mono'
            pr['ProcStatus'] = 'Name:\tzgrep'
            pr['ProcCmdline'] = 'zgrep\0/bin/zgrep'
            pr._check_interpreted()
            self.assertEqual(pr['ExecutablePath'], '/bin/zgrep')
            self.assertEqual(pr['InterpreterPath'], '/usr/bin/mono')

            # fail on files we shouldn't have access to when name!=argv[0]
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/usr/bin/python'
            pr['ProcStatus'] = 'Name:\tznonexisting'
            pr['ProcCmdline'] = 'python\0/etc/shadow'
            pr._check_interpreted()
            self.assertEqual(pr['ExecutablePath'], '/usr/bin/python')
            self.assertFalse('InterpreterPath' in pr)

            # succeed on files we should have access to when name!=argv[0]
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/usr/bin/python'
            pr['ProcStatus'] = 'Name:\tznonexisting'
            pr['ProcCmdline'] = 'python\0/etc/passwd'
            pr._check_interpreted()
            self.assertEqual(pr['InterpreterPath'], '/usr/bin/python')
            self.assertEqual(pr['ExecutablePath'], '/etc/passwd')

            # fail on files we shouldn't have access to when name==argv[0]
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/usr/bin/python'
            pr['ProcStatus'] = 'Name:\tshadow'
            pr['ProcCmdline'] = '../etc/shadow'
            pr._check_interpreted()
            self.assertEqual(pr['ExecutablePath'], '/usr/bin/python')
            self.assertFalse('InterpreterPath' in pr)

            # succeed on files we should have access to when name==argv[0]
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/usr/bin/python'
            pr['ProcStatus'] = 'Name:\tpasswd'
            pr['ProcCmdline'] = '../etc/passwd'
            pr._check_interpreted()
            self.assertEqual(pr['InterpreterPath'], '/usr/bin/python')
            self.assertEqual(pr['ExecutablePath'], '/bin/../etc/passwd')

            # interactive python process
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/usr/bin/python'
            pr['ProcStatus'] = 'Name:\tpython'
            pr['ProcCmdline'] = 'python'
            pr._check_interpreted()
            self.assertEqual(pr['ExecutablePath'], '/usr/bin/python')
            self.assertFalse('InterpreterPath' in pr)

            # python script (abuse /bin/bash since it must exist)
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/usr/bin/python'
            pr['ProcStatus'] = 'Name:\tbash'
            pr['ProcCmdline'] = 'python\0/bin/bash'
            pr._check_interpreted()
            self.assertEqual(pr['InterpreterPath'], '/usr/bin/python')
            self.assertEqual(pr['ExecutablePath'], '/bin/bash')

            # python script with options (abuse /bin/bash since it must exist)
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/usr/bin/python'
            pr['ProcStatus'] = 'Name:\tbash'
            pr['ProcCmdline'] = 'python\0-OO\0/bin/bash'
            pr._check_interpreted()
            self.assertEqual(pr['InterpreterPath'], '/usr/bin/python')
            self.assertEqual(pr['ExecutablePath'], '/bin/bash')

            # python script with a versioned interpreter
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/usr/bin/python2.7'
            pr['ProcStatus'] = 'Name:\tbash'
            pr['ProcCmdline'] = '/usr/bin/python\0/bin/bash'
            pr._check_interpreted()
            self.assertEqual(pr['InterpreterPath'], '/usr/bin/python2.7')
            self.assertEqual(pr['ExecutablePath'], '/bin/bash')

            # python script through -m
            pr = apport.report.Report()
            pr['ExecutablePath'] = '/usr/bin/python2.7'
            pr['ProcStatus'] = 'Name:\tpython'
            pr['ProcCmdline'] = 'python\0-tt\0-m\0apport/report\0-v'
            pr._check_interpreted()
            self.assertEqual(pr['InterpreterPath'], '/usr/bin/python2.7')
            self.assertTrue('report' in pr['ExecutablePath'],
                'expecting "report" in ExecutablePath "%s"' % pr['ExecutablePath'])
        finally:
            if restore_root:
                os.setresuid(0, 0, -1)

    def test_check_interpreted_twistd(self):
        '''_check_interpreted() for programs ran through twistd'''

        # LP#761374
        pr = apport.report.Report()
        pr['ExecutablePath'] = '/usr/bin/python2.7'
        pr['ProcStatus'] = 'Name:\ttwistd'
        pr['ProcCmdline'] = '/usr/bin/python\0/usr/bin/twistd\0--uid\0root\0--gid\0root\0--pidfile\0/var/run/nanny.pid\0-r\0glib2\0--logfile\0/var/log/nanny.log\0-y\0/usr/share/nanny/daemon/nanny.tap'
        pr._check_interpreted()
        self.assertEqual(pr['ExecutablePath'], '/usr/share/nanny/daemon/nanny.tap')
        self.assertEqual(pr['InterpreterPath'], '/usr/bin/twistd')

        # LP#625039
        pr = apport.report.Report()
        pr['ExecutablePath'] = '/usr/bin/python2.7'
        pr['ProcStatus'] = 'Name:\ttwistd'
        pr['ProcCmdline'] = '/usr/bin/python\0/usr/bin/twistd\0--pidfile=/var/run/apt-p2p//apt-p2p.pid\0--rundir=/var/run/apt-p2p/\0--python=/usr/sbin/apt-p2p\0--logfile=/var/log/apt-p2p.log\0--no_save'
        pr._check_interpreted()
        self.assertEqual(pr['ExecutablePath'], '/usr/sbin/apt-p2p')
        self.assertEqual(pr['InterpreterPath'], '/usr/bin/twistd')

        # somewhere from LP#755025
        pr = apport.report.Report()
        pr['ExecutablePath'] = '/usr/bin/python2.7'
        pr['ProcStatus'] = 'Name:\ttwistd'
        pr['ProcCmdline'] = '/usr/bin/python\0/usr/bin/twistd\0-r\0gtk2\0--pidfile\0/tmp/vmc.pid\0-noy\0/usr/share/vodafone-mobile-connect/gtk-tap.py\0-l\0/dev/null'
        pr._check_interpreted()
        self.assertEqual(pr['ExecutablePath'], '/usr/share/vodafone-mobile-connect/gtk-tap.py')
        self.assertEqual(pr['InterpreterPath'], '/usr/bin/twistd')

        # LP#725383 -> not practical to determine file here
        pr = apport.report.Report()
        pr['ExecutablePath'] = '/usr/bin/python2.7'
        pr['ProcStatus'] = 'Name:\ttwistd'
        pr['ProcCmdline'] = '/usr/bin/python\0/usr/bin/twistd\0--pidfile=/var/run/poker-network-server.pid\0--logfile=/var/log/poker-network-server.log\0--no_save\0--reactor=poll\0pokerserver'
        pr._check_interpreted()
        self.assertTrue('ExecutablePath' in pr)
        self.assertTrue('UnreportableReason' in pr)
        self.assertEqual(pr['InterpreterPath'], '/usr/bin/twistd')

    @classmethod
    def _generate_sigsegv_report(klass, file=None, signal='11', code='''
int f(x) {
    int* p = 0; *p = x;
    return x+1;
}
int main() { return f(42); }
'''):
        '''Create a test executable which will die with a SIGSEGV, generate a
        core dump for it, create a problem report with those two arguments
        (ExecutablePath and CoreDump) and call add_gdb_info().

        If file is given, the report is written into it. Return the apport.report.Report.'''

        workdir = None
        orig_cwd = os.getcwd()
        pr = apport.report.Report()
        try:
            workdir = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, workdir)
            os.chdir(workdir)

            # create a test executable
            with open('crash.c', 'w') as fd:
                fd.write(code)
            assert subprocess.call(['gcc', '-g', 'crash.c', '-o', 'crash']) == 0
            assert os.path.exists('crash')

            # call it through gdb and dump core
            subprocess.call(['gdb', '--batch', '--ex', 'run', '--ex',
                'generate-core-file core', './crash'], stdout=subprocess.PIPE)
            assert os.path.exists('core')
            assert subprocess.call(['readelf', '-n', 'core'],
                stdout=subprocess.PIPE) == 0

            pr['ExecutablePath'] = os.path.join(workdir, 'crash')
            pr['CoreDump'] = (os.path.join(workdir, 'core'),)
            pr['Signal'] = signal

            pr.add_gdb_info()
            if file:
                pr.write(file)
                file.flush()
        finally:
            os.chdir(orig_cwd)

        return pr

    def _validate_gdb_fields(self, pr):
        self.assertTrue('Stacktrace' in pr)
        self.assertTrue('ThreadStacktrace' in pr)
        self.assertTrue('StacktraceTop' in pr)
        self.assertTrue('Registers' in pr)
        self.assertTrue('Disassembly' in pr)
        self.assertTrue('(no debugging symbols found)' not in pr['Stacktrace'])
        self.assertTrue('Core was generated by' not in pr['Stacktrace'], pr['Stacktrace'])
        self.assertTrue(not re.match(r'(?s)(^|.*\n)#0  [^\n]+\n#0  ',
                                  pr['Stacktrace']))
        self.assertTrue('#0  0x' in pr['Stacktrace'])
        self.assertTrue('#1  0x' in pr['Stacktrace'])
        self.assertTrue('#0  0x' in pr['ThreadStacktrace'])
        self.assertTrue('#1  0x' in pr['ThreadStacktrace'])
        self.assertTrue('Thread 1 (' in pr['ThreadStacktrace'])
        self.assertTrue(len(pr['StacktraceTop'].splitlines()) <= 5)

    def test_add_gdb_info(self):
        '''add_gdb_info() with core dump file reference.'''

        pr = apport.report.Report()
        # should not throw an exception for missing fields
        pr.add_gdb_info()

        # normal crash
        pr = self._generate_sigsegv_report()
        self._validate_gdb_fields(pr)
        self.assertEqual(pr['StacktraceTop'], 'f (x=42) at crash.c:3\nmain () at crash.c:6', pr['StacktraceTop'])
        self.assertFalse('AssertionMessage' in pr)

        # crash where gdb generates output on stderr
        pr = self._generate_sigsegv_report(code='''
int main() {
    void     (*function)(void);
    function = 0;
    function();
}
''')
        self._validate_gdb_fields(pr)
        self.assertTrue('Cannot access memory at address 0x0' in pr['Disassembly'], pr['Disassembly'])
        self.assertFalse('AssertionMessage' in pr)

    def test_add_gdb_info_load(self):
        '''add_gdb_info() with inline core dump.'''

        rep = tempfile.NamedTemporaryFile()
        self._generate_sigsegv_report(rep)
        rep.seek(0)

        pr = apport.report.Report()
        with open(rep.name, 'rb') as f:
            pr.load(f)
        pr.add_gdb_info()

        self._validate_gdb_fields(pr)

    def test_add_zz_parse_segv_details(self):
        '''parse-segv produces sensible results'''
        rep = tempfile.NamedTemporaryFile()
        self._generate_sigsegv_report(rep)
        rep.seek(0)

        pr = apport.report.Report()
        with open(rep.name, 'rb') as f:
            pr.load(f)
        pr['Signal'] = '1'
        pr.add_hooks_info('fake_ui')
        self.assertTrue('SegvAnalysis' not in pr.keys())

        pr = apport.report.Report()
        with open(rep.name, 'rb') as f:
            pr.load(f)
        pr.add_hooks_info('fake_ui')
        self.assertTrue('Skipped: missing required field "Architecture"' in pr['SegvAnalysis'],
                     pr['SegvAnalysis'])

        pr.add_os_info()
        pr.add_hooks_info('fake_ui')
        self.assertTrue('Skipped: missing required field "ProcMaps"' in pr['SegvAnalysis'],
                     pr['SegvAnalysis'])

        pr.add_proc_info()
        pr.add_hooks_info('fake_ui')
        self.assertTrue('not located in a known VMA region' in pr['SegvAnalysis'],
                     pr['SegvAnalysis'])

    def test_add_gdb_info_script(self):
        '''add_gdb_info() with a script.'''

        (fd, script) = tempfile.mkstemp()
        coredump = os.path.join(os.path.dirname(script), 'core')
        assert not os.path.exists(coredump)
        try:
            os.close(fd)

            # create a test script which produces a core dump for us
            with open(script, 'w') as fd:
                fd.write('''#!/bin/bash
cd `dirname $0`
ulimit -c unlimited
kill -SEGV $$
''')
            os.chmod(script, 0o755)

            # call script and verify that it gives us a proper ELF core dump
            assert subprocess.call([script]) != 0
            time.sleep(1)
            assert subprocess.call(['readelf', '-n', coredump],
                stdout=subprocess.PIPE) == 0

            pr = apport.report.Report()
            pr['InterpreterPath'] = '/bin/bash'
            pr['ExecutablePath'] = script
            pr['CoreDump'] = (coredump,)
            pr.add_gdb_info()
        finally:
            os.unlink(coredump)
            os.unlink(script)

        self._validate_gdb_fields(pr)
        self.assertTrue('libc.so' in pr['Stacktrace'] or 'in execute_command' in pr['Stacktrace'])

    def test_add_gdb_info_abort(self):
        '''add_gdb_info() with SIGABRT/assert()

        If these come from an assert(), the report should have the assertion
        message. Otherwise it should be marked as not reportable.
        '''
        # abort with assert
        (fd, script) = tempfile.mkstemp()
        assert not os.path.exists('core')
        try:
            os.close(fd)

            # create a test script which produces a core dump for us
            with open(script, 'w') as fd:
                fd.write('''#!/bin/sh
gcc -o $0.bin -x c - <<EOF
#include <assert.h>
int main() { assert(1 < 0); }
EOF
ulimit -c unlimited
$0.bin 2>/dev/null
''')
            os.chmod(script, 0o755)

            # call script and verify that it gives us a proper ELF core dump
            assert subprocess.call([script]) != 0
            time.sleep(1)
            assert subprocess.call(['readelf', '-n', 'core'],
                stdout=subprocess.PIPE) == 0

            pr = apport.report.Report()
            pr['ExecutablePath'] = script + '.bin'
            pr['CoreDump'] = ('core',)
            pr.add_gdb_info()
        finally:
            os.unlink(script)
            os.unlink(script + '.bin')
            os.unlink('core')

        self._validate_gdb_fields(pr)
        self.assertTrue("<stdin>:2: main: Assertion `1 < 0' failed." in
                pr['AssertionMessage'], pr['AssertionMessage'])
        self.assertFalse(pr['AssertionMessage'].startswith('$'), pr['AssertionMessage'])
        self.assertFalse('= 0x' in pr['AssertionMessage'], pr['AssertionMessage'])
        self.assertFalse(pr['AssertionMessage'].endswith('\\n'), pr['AssertionMessage'])

        # abort with internal error
        (fd, script) = tempfile.mkstemp()
        assert not os.path.exists('core')
        try:
            os.close(fd)

            # create a test script which produces a core dump for us
            with open(script, 'w') as fd:
                fd.write('''#!/bin/sh
gcc -O2 -D_FORTIFY_SOURCE=2 -o $0.bin -x c - <<EOF
#include <string.h>
int main(int argc, char *argv[]) {
    char buf[8];
    strcpy(buf, argv[1]);
    return 0;
}
EOF
ulimit -c unlimited
LIBC_FATAL_STDERR_=1 $0.bin aaaaaaaaaaaaaaaa 2>/dev/null
''')
            os.chmod(script, 0o755)

            # call script and verify that it gives us a proper ELF core dump
            assert subprocess.call([script]) != 0
            assert subprocess.call(['readelf', '-n', 'core'],
                stdout=subprocess.PIPE) == 0

            pr = apport.report.Report()
            pr['ExecutablePath'] = script + '.bin'
            pr['CoreDump'] = ('core',)
            pr.add_gdb_info()
        finally:
            os.unlink(script)
            os.unlink(script + '.bin')
            os.unlink('core')

        self._validate_gdb_fields(pr)
        self.assertTrue("** buffer overflow detected ***: %s.bin terminated" % (script) in
                pr['AssertionMessage'], pr['AssertionMessage'])
        self.assertFalse(pr['AssertionMessage'].startswith('$'), pr['AssertionMessage'])
        self.assertFalse('= 0x' in pr['AssertionMessage'], pr['AssertionMessage'])
        self.assertFalse(pr['AssertionMessage'].endswith('\\n'), pr['AssertionMessage'])

        # abort without assertion
        (fd, script) = tempfile.mkstemp()
        assert not os.path.exists('core')
        try:
            os.close(fd)

            # create a test script which produces a core dump for us
            with open(script, 'w') as fd:
                fd.write('''#!/bin/sh
gcc -o $0.bin -x c - <<EOF
#include <stdlib.h>
int main() { abort(); }
EOF
ulimit -c unlimited
$0.bin 2>/dev/null
''')
            os.chmod(script, 0o755)

            # call script and verify that it gives us a proper ELF core dump
            assert subprocess.call([script]) != 0
            assert subprocess.call(['readelf', '-n', 'core'],
                stdout=subprocess.PIPE) == 0

            pr = apport.report.Report()
            pr['ExecutablePath'] = script + '.bin'
            pr['CoreDump'] = ('core',)
            pr.add_gdb_info()
        finally:
            os.unlink(script)
            os.unlink(script + '.bin')
            os.unlink('core')

        self._validate_gdb_fields(pr)
        self.assertFalse('AssertionMessage' in pr, pr.get('AssertionMessage'))

    def test_search_bug_patterns(self):
        '''search_bug_patterns().'''

        patterns = tempfile.NamedTemporaryFile(prefix='apport-')
        # create some test patterns
        patterns.write(b'''<?xml version="1.0"?>
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
</patterns>''')
        patterns.flush()

        # invalid XML
        invalid = tempfile.NamedTemporaryFile(prefix='apport-')
        invalid.write(b'''<?xml version="1.0"?>
</patterns>''')
        invalid.flush()

        # create some reports
        r_bash = apport.report.Report()
        r_bash['Package'] = 'bash 1-2'
        r_bash['Foo'] = 'bazaar'

        r_bazaar = apport.report.Report()
        r_bazaar['Package'] = 'bazaar 2-1'
        r_bazaar['SourcePackage'] = 'bazaar'
        r_bazaar['LogFile'] = 'AssertionError'

        r_coreutils = apport.report.Report()
        r_coreutils['Package'] = 'coreutils 1'
        r_coreutils['Bar'] = '1'

        r_invalid = apport.report.Report()
        r_invalid['Package'] = 'invalid 1'

        pattern_url = 'file://' + patterns.name

        # positive match cases
        self.assertEqual(r_bash.search_bug_patterns(pattern_url),
                'http://bugtracker.net/bugs/1')
        r_bash['Foo'] = 'write_goodbye'
        self.assertEqual(r_bash.search_bug_patterns(pattern_url),
                'http://bugtracker.net/bugs/2')
        self.assertEqual(r_coreutils.search_bug_patterns(pattern_url),
                'http://bugtracker.net/bugs/3')
        self.assertEqual(r_bazaar.search_bug_patterns(pattern_url),
                'http://bugtracker.net/bugs/5')

        # also works for CompressedValues
        r_bash_compressed = r_bash.copy()
        r_bash_compressed['Foo'] = problem_report.CompressedValue(b'bazaar')
        self.assertEqual(r_bash_compressed.search_bug_patterns(pattern_url),
                'http://bugtracker.net/bugs/1')

        # negative match cases
        r_bash['Package'] = 'bash-static 1-2'
        self.assertEqual(r_bash.search_bug_patterns(pattern_url), None)
        r_bash['Package'] = 'bash 1-21'
        self.assertEqual(r_bash.search_bug_patterns(pattern_url), None,
            'does not match on wrong bash version')
        r_bash['Foo'] = 'zz'
        self.assertEqual(r_bash.search_bug_patterns(pattern_url), None,
            'does not match on wrong Foo value')
        r_coreutils['Bar'] = '11'
        self.assertEqual(r_coreutils.search_bug_patterns(pattern_url), None,
            'does not match on wrong Bar value')
        r_bazaar['SourcePackage'] = 'launchpad'
        self.assertEqual(r_bazaar.search_bug_patterns(pattern_url), None,
            'does not match on wrong source package')
        r_bazaar['LogFile'] = ''
        self.assertEqual(r_bazaar.search_bug_patterns(pattern_url), None,
            'does not match on empty attribute')

        # various errors to check for robustness (no exceptions, just None
        # return value)
        del r_coreutils['Bar']
        self.assertEqual(r_coreutils.search_bug_patterns(pattern_url), None,
            'does not match on nonexisting key')
        self.assertEqual(r_invalid.search_bug_patterns('file://' + invalid.name), None,
            'gracefully handles invalid XML')
        r_coreutils['Package'] = 'other 2'
        self.assertEqual(r_bash.search_bug_patterns('file:///nonexisting/directory/'), None,
            'gracefully handles nonexisting base path')
        # existing host, but no bug patterns
        self.assertEqual(r_bash.search_bug_patterns('http://security.ubuntu.com/'), None,
            'gracefully handles base path without bug patterns')
        # nonexisting host
        self.assertEqual(r_bash.search_bug_patterns('http://nonexisting.domain/'), None,
            'gracefully handles nonexisting URL domain')

    def test_add_hooks_info(self):
        '''add_hooks_info().'''

        orig_hook_dir = apport.report._hook_dir
        apport.report._hook_dir = tempfile.mkdtemp()
        orig_common_hook_dir = apport.report._common_hook_dir
        apport.report._common_hook_dir = tempfile.mkdtemp()
        try:
            with open(os.path.join(apport.report._hook_dir, 'foo.py'), 'w') as fd:
                fd.write('''
import sys
def add_info(report):
    report['Field1'] = 'Field 1'
    report['Field2'] = 'Field 2\\nBla'
    if 'Spethial' in report:
        raise StopIteration
''')

            with open(os.path.join(apport.report._common_hook_dir, 'foo1.py'), 'w') as fd:
                fd.write('''
def add_info(report):
    report['CommonField1'] = 'CommonField 1'
    if report['Package'] == 'commonspethial':
        raise StopIteration
''')
            with open(os.path.join(apport.report._common_hook_dir, 'foo2.py'), 'w') as fd:
                fd.write('''
def add_info(report):
    report['CommonField2'] = 'CommonField 2'
''')
            with open(os.path.join(apport.report._common_hook_dir, 'foo3.py'), 'w') as fd:
                fd.write('''
def add_info(report, ui):
    report['CommonField3'] = str(ui)
''')

            # should only catch .py files
            with open(os.path.join(apport.report._common_hook_dir, 'notme'), 'w') as fd:
                fd.write('''
def add_info(report):
    report['BadField'] = 'XXX'
''')
            r = apport.report.Report()
            r['Package'] = 'bar'
            # should not throw any exceptions
            self.assertEqual(r.add_hooks_info('fake_ui'), False)
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package', 'CommonField1', 'CommonField2', 'CommonField3']),
                'report has required fields')

            r = apport.report.Report()
            r['Package'] = 'baz 1.2-3'
            # should not throw any exceptions
            self.assertEqual(r.add_hooks_info('fake_ui'), False)
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package', 'CommonField1', 'CommonField2', 'CommonField3']),
                'report has required fields')

            r = apport.report.Report()
            r['Package'] = 'foo'
            self.assertEqual(r.add_hooks_info('fake_ui'), False)
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package', 'Field1', 'Field2', 'CommonField1',
                'CommonField2', 'CommonField3']), 'report has required fields')
            self.assertEqual(r['Field1'], 'Field 1')
            self.assertEqual(r['Field2'], 'Field 2\nBla')
            self.assertEqual(r['CommonField1'], 'CommonField 1')
            self.assertEqual(r['CommonField2'], 'CommonField 2')
            self.assertEqual(r['CommonField3'], 'fake_ui')

            r = apport.report.Report()
            r['Package'] = 'foo 4.5-6'
            self.assertEqual(r.add_hooks_info('fake_ui'), False)
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package', 'Field1', 'Field2', 'CommonField1',
                'CommonField2', 'CommonField3']), 'report has required fields')
            self.assertEqual(r['Field1'], 'Field 1')
            self.assertEqual(r['Field2'], 'Field 2\nBla')
            self.assertEqual(r['CommonField1'], 'CommonField 1')
            self.assertEqual(r['CommonField2'], 'CommonField 2')

            # test hook abort
            r['Spethial'] = '1'
            self.assertEqual(r.add_hooks_info('fake_ui'), True)
            r = apport.report.Report()
            r['Package'] = 'commonspethial'
            self.assertEqual(r.add_hooks_info('fake_ui'), True)

            # source package hook
            with open(os.path.join(apport.report._hook_dir, 'source_foo.py'), 'w') as fd:
                fd.write('''
def add_info(report, ui):
    report['Field1'] = 'Field 1'
    report['Field2'] = 'Field 2\\nBla'
    if report['Package'] == 'spethial':
        raise StopIteration
''')
            r = apport.report.Report()
            r['SourcePackage'] = 'foo'
            r['Package'] = 'libfoo 3'
            self.assertEqual(r.add_hooks_info('fake_ui'), False)
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package', 'SourcePackage', 'Field1', 'Field2', 'CommonField1',
                'CommonField2', 'CommonField3']), 'report has required fields')
            self.assertEqual(r['Field1'], 'Field 1')
            self.assertEqual(r['Field2'], 'Field 2\nBla')
            self.assertEqual(r['CommonField1'], 'CommonField 1')
            self.assertEqual(r['CommonField2'], 'CommonField 2')
            self.assertEqual(r['CommonField3'], 'fake_ui')

            # test hook abort
            r['Package'] = 'spethial'
            self.assertEqual(r.add_hooks_info('fake_ui'), True)

        finally:
            shutil.rmtree(apport.report._hook_dir)
            shutil.rmtree(apport.report._common_hook_dir)
            apport.report._hook_dir = orig_hook_dir
            apport.report._common_hook_dir = orig_common_hook_dir

    def test_ignoring(self):
        '''mark_ignore() and check_ignored().'''

        orig_ignore_file = apport.report.apport.report._ignore_file
        workdir = tempfile.mkdtemp()
        apport.report.apport.report._ignore_file = os.path.join(workdir, 'ignore.xml')
        try:
            with open(os.path.join(workdir, 'bash'), 'w') as fd:
                fd.write('bash')
            with open(os.path.join(workdir, 'crap'), 'w') as fd:
                fd.write('crap')

            bash_rep = apport.report.Report()
            bash_rep['ExecutablePath'] = os.path.join(workdir, 'bash')
            crap_rep = apport.report.Report()
            crap_rep['ExecutablePath'] = os.path.join(workdir, 'crap')
            # must be able to deal with executables that do not exist any more
            cp_rep = apport.report.Report()
            cp_rep['ExecutablePath'] = os.path.join(workdir, 'cp')

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
            with open(os.path.join(workdir, 'crap'), 'w') as fd:
                fd.write('crapnew')
            self.assertEqual(bash_rep.check_ignored(), True)
            self.assertEqual(crap_rep.check_ignored(), False)
            self.assertEqual(cp_rep.check_ignored(), False)

            # do not complain about an empty ignore file
            with open(apport.report.apport.report._ignore_file, 'w') as fd:
                fd.write('')
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)
            self.assertEqual(cp_rep.check_ignored(), False)

            # does not crash if the executable went away under our feet
            crap_rep['ExecutablePath'] = '/non existing'
            crap_rep.mark_ignore()
            self.assertEqual(os.path.getsize(apport.report.apport.report._ignore_file), 0)
        finally:
            shutil.rmtree(workdir)
            apport.report.apport.report._ignore_file = orig_ignore_file

    def test_blacklisting(self):
        '''check_ignored() for system-wise blacklist.'''

        orig_blacklist_dir = apport.report._blacklist_dir
        apport.report._blacklist_dir = tempfile.mkdtemp()
        orig_ignore_file = apport.report._ignore_file
        apport.report._ignore_file = '/nonexistant'
        try:
            bash_rep = apport.report.Report()
            bash_rep['ExecutablePath'] = '/bin/bash'
            crap_rep = apport.report.Report()
            crap_rep['ExecutablePath'] = '/bin/crap'

            # no ignores initially
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)

            # should not stumble over comments
            with open(os.path.join(apport.report._blacklist_dir, 'README'), 'w') as fd:
                fd.write('# Ignore file\n#/bin/bash\n')

            # no ignores on nonmatching paths
            with open(os.path.join(apport.report._blacklist_dir, 'bl1'), 'w') as fd:
                fd.write('/bin/bas\n/bin/bashh\nbash\nbin/bash\n')
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)

            # ignore crap now
            with open(os.path.join(apport.report._blacklist_dir, 'bl_2'), 'w') as fd:
                fd.write('/bin/crap\n')
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), True)

            # ignore bash now
            with open(os.path.join(apport.report._blacklist_dir, 'bl1'), 'a') as fd:
                fd.write('/bin/bash\n')
            self.assertEqual(bash_rep.check_ignored(), True)
            self.assertEqual(crap_rep.check_ignored(), True)
        finally:
            shutil.rmtree(apport.report._blacklist_dir)
            apport.report._blacklist_dir = orig_blacklist_dir
            apport.report._ignore_file = orig_ignore_file

    def test_whitelisting(self):
        '''check_ignored() for system-wise whitelist.'''

        orig_whitelist_dir = apport.report._whitelist_dir
        apport.report._whitelist_dir = tempfile.mkdtemp()
        orig_ignore_file = apport.report.apport.report._ignore_file
        apport.report.apport.report._ignore_file = '/nonexistant'
        try:
            bash_rep = apport.report.Report()
            bash_rep['ExecutablePath'] = '/bin/bash'
            crap_rep = apport.report.Report()
            crap_rep['ExecutablePath'] = '/bin/crap'

            # no ignores without any whitelist
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)

            # should not stumble over comments
            with open(os.path.join(apport.report._whitelist_dir, 'README'), 'w') as fd:
                fd.write('# Ignore file\n#/bin/bash\n')

            # accepts matching paths
            with open(os.path.join(apport.report._whitelist_dir, 'wl1'), 'w') as fd:
                fd.write('/bin/bash\n')
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), True)

            # also accept crap now
            with open(os.path.join(apport.report._whitelist_dir, 'wl_2'), 'w') as fd:
                fd.write('/bin/crap\n')
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)

            # only complete matches accepted
            with open(os.path.join(apport.report._whitelist_dir, 'wl1'), 'w') as fd:
                fd.write('/bin/bas\n/bin/bashh\nbash\n')
            self.assertEqual(bash_rep.check_ignored(), True)
            self.assertEqual(crap_rep.check_ignored(), False)
        finally:
            shutil.rmtree(apport.report._whitelist_dir)
            apport.report._whitelist_dir = orig_whitelist_dir
            apport.report.apport.report._ignore_file = orig_ignore_file

    def test_has_useful_stacktrace(self):
        '''has_useful_stacktrace().'''

        r = apport.report.Report()
        self.assertFalse(r.has_useful_stacktrace())

        r['StacktraceTop'] = ''
        self.assertFalse(r.has_useful_stacktrace())

        r['StacktraceTop'] = '?? ()'
        self.assertFalse(r.has_useful_stacktrace())

        r['StacktraceTop'] = '?? ()\n?? ()'
        self.assertFalse(r.has_useful_stacktrace())

        r['StacktraceTop'] = 'read () from /lib/libc.6.so\n?? ()'
        self.assertFalse(r.has_useful_stacktrace())

        r['StacktraceTop'] = 'read () from /lib/libc.6.so\n?? ()\n?? ()\n?? ()'
        self.assertFalse(r.has_useful_stacktrace())

        r['StacktraceTop'] = 'read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so'
        self.assertTrue(r.has_useful_stacktrace())

        r['StacktraceTop'] = 'read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so\n?? ()'
        self.assertTrue(r.has_useful_stacktrace())

        r['StacktraceTop'] = 'read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so\n?? ()\n?? ()'
        self.assertTrue(r.has_useful_stacktrace())

        r['StacktraceTop'] = 'read () from /lib/libc.6.so\n?? ()\nfoo (i=1) from /usr/lib/libfoo.so\n?? ()\n?? ()'
        self.assertFalse(r.has_useful_stacktrace())

    def test_standard_title(self):
        '''standard_title().'''

        report = apport.report.Report()
        self.assertEqual(report.standard_title(), None)

        # named signal crash
        report['Signal'] = '11'
        report['ExecutablePath'] = '/bin/bash'
        report['StacktraceTop'] = '''foo()
bar(x=3)
baz()
'''
        self.assertEqual(report.standard_title(),
            'bash crashed with SIGSEGV in foo()')

        # unnamed signal crash
        report['Signal'] = '42'
        self.assertEqual(report.standard_title(),
            'bash crashed with signal 42 in foo()')

        # do not crash on empty StacktraceTop
        report['StacktraceTop'] = ''
        self.assertEqual(report.standard_title(),
            'bash crashed with signal 42')

        # do not create bug title with unknown function name
        report['StacktraceTop'] = '??()\nfoo()'
        self.assertEqual(report.standard_title(),
            'bash crashed with signal 42 in foo()')

        # if we do not know any function name, don't mention ??
        report['StacktraceTop'] = '??()\n??()'
        self.assertEqual(report.standard_title(),
            'bash crashed with signal 42')

        # assertion message
        report['Signal'] = '6'
        report['ExecutablePath'] = '/bin/bash'
        report['AssertionMessage'] = 'foo.c:42 main: i > 0'
        self.assertEqual(report.standard_title(),
            'bash assert failure: foo.c:42 main: i > 0')

        # Python crash
        report = apport.report.Report()
        report['ExecutablePath'] = '/usr/share/apport/apport-gtk'
        report['Traceback'] = '''Traceback (most recent call last):
File "/usr/share/apport/apport-gtk", line 202, in <module>
app.run_argv()
File "/var/lib/python-support/python2.5/apport/ui.py", line 161, in run_argv
self.run_crashes()
File "/var/lib/python-support/python2.5/apport/ui.py", line 104, in run_crashes
self.run_crash(f)
File "/var/lib/python-support/python2.5/apport/ui.py", line 115, in run_crash
response = self.ui_present_crash(desktop_entry)
File "/usr/share/apport/apport-gtk", line 67, in ui_present_crash
subprocess.call(['pgrep', '-x',
NameError: global name 'subprocess' is not defined'''
        self.assertEqual(report.standard_title(),
            "apport-gtk crashed with NameError in ui_present_crash(): global name 'subprocess' is not defined")

        # slightly weird Python crash
        report = apport.report.Report()
        report['ExecutablePath'] = '/usr/share/apport/apport-gtk'
        report['Traceback'] = '''TypeError: Cannot create a consistent method resolution
order (MRO) for bases GObject, CanvasGroupableIface, CanvasGroupable'''
        self.assertEqual(report.standard_title(),
            'apport-gtk crashed with TypeError: Cannot create a consistent method resolution')

        # Python crash with custom message
        report = apport.report.Report()
        report['ExecutablePath'] = '/usr/share/apport/apport-gtk'
        report['Traceback'] = '''Traceback (most recent call last):
  File "/x/foo.py", line 242, in setup_chooser
    raise "Moo"
Mo?o[a-1]'''

        self.assertEqual(report.standard_title(), 'apport-gtk crashed with Mo?o[a-1] in setup_chooser()')

        # Python crash with custom message with newlines (LP #190947)
        report = apport.report.Report()
        report['ExecutablePath'] = '/usr/share/apport/apport-gtk'
        report['Traceback'] = '''Traceback (most recent call last):
  File "/x/foo.py", line 242, in setup_chooser
    raise "\nKey: "+key+" isn't set.\nRestarting AWN usually solves this issue\n"

Key: /apps/avant-window-navigator/app/active_png isn't set.
Restarting AWN usually solves this issue'''

        t = report.standard_title()
        self.assertTrue(t.startswith('apport-gtk crashed with'))
        self.assertTrue(t.endswith('setup_chooser()'))

        # Python crash at top level in module
        report = apport.report.Report()
        report['ExecutablePath'] = '/usr/bin/gnome-about'
        report['Traceback'] = '''Traceback (most recent call last):
  File "/usr/bin/gnome-about", line 30, in <module>
    import pygtk
  File "/usr/lib/pymodules/python2.6/pygtk.py", line 28, in <module>
    import nonexistent
ImportError: No module named nonexistent
'''
        self.assertEqual(report.standard_title(),
            "gnome-about crashed with ImportError in /usr/lib/pymodules/python2.6/pygtk.py: No module named nonexistent")

        # Python crash at top level in main program
        report = apport.report.Report()
        report['ExecutablePath'] = '/usr/bin/dcut'
        report['Traceback'] = '''Traceback (most recent call last):
  File "/usr/bin/dcut", line 28, in <module>
    import nonexistent
ImportError: No module named nonexistent
'''
        self.assertEqual(report.standard_title(),
            "dcut crashed with ImportError in __main__: No module named nonexistent")

        # package install problem
        report = apport.report.Report('Package')
        report['Package'] = 'bash'

        # no ErrorMessage
        self.assertEqual(report.standard_title(),
            'package bash failed to install/upgrade')

        # empty ErrorMessage
        report['ErrorMessage'] = ''
        self.assertEqual(report.standard_title(),
            'package bash failed to install/upgrade')

        # nonempty ErrorMessage
        report['ErrorMessage'] = 'botched\nnot found\n'
        self.assertEqual(report.standard_title(),
            'package bash failed to install/upgrade: not found')

        # matching package/system architectures
        report['Signal'] = '11'
        report['ExecutablePath'] = '/bin/bash'
        report['StacktraceTop'] = '''foo()
bar(x=3)
baz()
'''
        report['PackageArchitecture'] = 'amd64'
        report['Architecture'] = 'amd64'
        self.assertEqual(report.standard_title(),
            'bash crashed with SIGSEGV in foo()')

        # non-native package (on multiarch)
        report['PackageArchitecture'] = 'i386'
        self.assertEqual(report.standard_title(),
            'bash crashed with SIGSEGV in foo() [non-native i386 package]')

        # Arch: all package (matches every system architecture)
        report['PackageArchitecture'] = 'all'
        self.assertEqual(report.standard_title(),
            'bash crashed with SIGSEGV in foo()')

        report = apport.report.Report('KernelOops')
        report['OopsText'] = '------------[ cut here ]------------\nkernel BUG at /tmp/oops.c:5!\ninvalid opcode: 0000 [#1] SMP'
        self.assertEqual(report.standard_title(), 'kernel BUG at /tmp/oops.c:5!')

    def test_obsolete_packages(self):
        '''obsolete_packages().'''

        report = apport.report.Report()
        self.assertEqual(report.obsolete_packages(), [])

        # should work without Dependencies
        report['Package'] = 'bash 0'
        self.assertEqual(report.obsolete_packages(), ['bash'])
        report['Package'] = 'bash 0 [modified: /bin/bash]'
        self.assertEqual(report.obsolete_packages(), ['bash'])
        report['Package'] = 'bash ' + apport.packaging.get_available_version('bash')
        self.assertEqual(report.obsolete_packages(), [])

        report['Dependencies'] = 'coreutils 0\ncron 0\n'
        self.assertEqual(report.obsolete_packages(), ['coreutils', 'cron'])

        report['Dependencies'] = 'coreutils %s [modified: /bin/mount]\ncron 0\n' % \
            apport.packaging.get_available_version('coreutils')
        self.assertEqual(report.obsolete_packages(), ['cron'])

        report['Dependencies'] = 'coreutils %s\ncron %s\n' % (
            apport.packaging.get_available_version('coreutils'),
            apport.packaging.get_available_version('cron'))
        self.assertEqual(report.obsolete_packages(), [])

    def test_gen_stacktrace_top(self):
        '''_gen_stacktrace_top().'''

        # nothing to chop off
        r = apport.report.Report()
        r['Stacktrace'] = '''#0  0x10000488 in h (p=0x0) at crash.c:25
#1  0x100004c8 in g (x=1, y=42) at crash.c:26
#2  0x10000514 in f (x=1) at crash.c:27
#3  0x10000530 in e (x=1) at crash.c:28
#4  0x10000530 in d (x=1) at crash.c:29
#5  0x10000530 in c (x=1) at crash.c:30
#6  0x10000550 in main () at crash.c:31
'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '''h (p=0x0) at crash.c:25
g (x=1, y=42) at crash.c:26
f (x=1) at crash.c:27
e (x=1) at crash.c:28
d (x=1) at crash.c:29''')

        # nothing to chop off: some addresses missing (LP #269133)
        r = apport.report.Report()
        r['Stacktrace'] = '''#0 h (p=0x0) at crash.c:25
#1  0x100004c8 in g (x=1, y=42) at crash.c:26
#2 f (x=1) at crash.c:27
#3  0x10000530 in e (x=1) at crash.c:28
#4  0x10000530 in d (x=1) at crash.c:29
#5  0x10000530 in c (x=1) at crash.c:30
#6  0x10000550 in main () at crash.c:31
'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '''h (p=0x0) at crash.c:25
g (x=1, y=42) at crash.c:26
f (x=1) at crash.c:27
e (x=1) at crash.c:28
d (x=1) at crash.c:29''')

        # single signal handler invocation
        r = apport.report.Report()
        r['Stacktrace'] = '''#0  0x10000488 in raise () from /lib/libpthread.so.0
#1  0x100004c8 in ??
#2  <signal handler called>
#3  0x10000530 in e (x=1) at crash.c:28
#4  0x10000530 in d (x=1) at crash.c:29
#5  0x10000530 in c (x=1) at crash.c:30
#6  0x10000550 in main () at crash.c:31
'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '''e (x=1) at crash.c:28
d (x=1) at crash.c:29
c (x=1) at crash.c:30
main () at crash.c:31''')

        # single signal handler invocation: some addresses missing
        r = apport.report.Report()
        r['Stacktrace'] = '''#0  0x10000488 in raise () from /lib/libpthread.so.0
#1  ??
#2  <signal handler called>
#3  0x10000530 in e (x=1) at crash.c:28
#4  d (x=1) at crash.c:29
#5  0x10000530 in c (x=1) at crash.c:30
#6  0x10000550 in main () at crash.c:31
'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '''e (x=1) at crash.c:28
d (x=1) at crash.c:29
c (x=1) at crash.c:30
main () at crash.c:31''')

        # stacked signal handler; should only cut the first one
        r = apport.report.Report()
        r['Stacktrace'] = '''#0  0x10000488 in raise () from /lib/libpthread.so.0
#1  0x100004c8 in ??
#2  <signal handler called>
#3  0x10000530 in e (x=1) at crash.c:28
#4  0x10000530 in d (x=1) at crash.c:29
#5  0x10000123 in raise () from /lib/libpthread.so.0
#6  <signal handler called>
#7  0x10000530 in c (x=1) at crash.c:30
#8  0x10000550 in main () at crash.c:31
'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '''e (x=1) at crash.c:28
d (x=1) at crash.c:29
raise () from /lib/libpthread.so.0
<signal handler called>
c (x=1) at crash.c:30''')

        # Gnome assertion; should unwind the logs and assert call
        r = apport.report.Report()
        r['Stacktrace'] = '''#0  0xb7d39cab in IA__g_logv (log_domain=<value optimized out>, log_level=G_LOG_LEVEL_ERROR,
    format=0xb7d825f0 "file %s: line %d (%s): assertion failed: (%s)", args1=0xbfee8e3c "xxx") at /build/buildd/glib2.0-2.13.5/glib/gmessages.c:493
#1  0xb7d39f29 in IA__g_log (log_domain=0xb7edbfd0 "libgnomevfs", log_level=G_LOG_LEVEL_ERROR,
    format=0xb7d825f0 "file %s: line %d (%s): assertion failed: (%s)") at /build/buildd/glib2.0-2.13.5/glib/gmessages.c:517
#2  0xb7d39fa6 in IA__g_assert_warning (log_domain=0xb7edbfd0 "libgnomevfs", file=0xb7ee1a26 "gnome-vfs-volume.c", line=254,
    pretty_function=0xb7ee1920 "gnome_vfs_volume_unset_drive_private", expression=0xb7ee1a39 "volume->priv->drive == drive")
    at /build/buildd/glib2.0-2.13.5/glib/gmessages.c:552
No locals.
#3  0xb7ec6c11 in gnome_vfs_volume_unset_drive_private (volume=0x8081a30, drive=0x8078f00) at gnome-vfs-volume.c:254
        __PRETTY_FUNCTION__ = "gnome_vfs_volume_unset_drive_private"
#4  0x08054db8 in _gnome_vfs_volume_monitor_disconnected (volume_monitor=0x8070400, drive=0x8078f00) at gnome-vfs-volume-monitor.c:963
        vol_list = (GList *) 0x8096d30
        current_vol = (GList *) 0x8097470
#5  0x0805951e in _hal_device_removed (hal_ctx=0x8074da8, udi=0x8093be4 "/org/freedesktop/Hal/devices/volume_uuid_92FC9DFBFC9DDA35")
    at gnome-vfs-hal-mounts.c:1316
        backing_udi = <value optimized out>
#6  0xb7ef1ead in filter_func (connection=0x8075288, message=0x80768d8, user_data=0x8074da8) at libhal.c:820
        udi = <value optimized out>
        object_path = 0x8076d40 "/org/freedesktop/Hal/Manager"
        error = {name = 0x0, message = 0x0, dummy1 = 1, dummy2 = 0, dummy3 = 0, dummy4 = 1, dummy5 = 0, padding1 = 0xb7e50c00}
#7  0xb7e071d2 in dbus_connection_dispatch (connection=0x8075288) at dbus-connection.c:4267
#8  0xb7e33dfd in ?? () from /usr/lib/libdbus-glib-1.so.2'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '''gnome_vfs_volume_unset_drive_private (volume=0x8081a30, drive=0x8078f00) at gnome-vfs-volume.c:254
_gnome_vfs_volume_monitor_disconnected (volume_monitor=0x8070400, drive=0x8078f00) at gnome-vfs-volume-monitor.c:963
_hal_device_removed (hal_ctx=0x8074da8, udi=0x8093be4 "/org/freedesktop/Hal/devices/volume_uuid_92FC9DFBFC9DDA35")
filter_func (connection=0x8075288, message=0x80768d8, user_data=0x8074da8) at libhal.c:820
dbus_connection_dispatch (connection=0x8075288) at dbus-connection.c:4267''')

        # XError (taken from LP#848808)
        r = apport.report.Report()
        r['Stacktrace'] = '''#0  0x007cf416 in __kernel_vsyscall ()
No symbol table info available.
#1  0x01017c8f in __GI_raise (sig=6) at ../nptl/sysdeps/unix/sysv/linux/raise.c:64
#2  0x0101b2b5 in __GI_abort () at abort.c:92
#3  0x0807daab in meta_bug (format=0x80b0c60 "Unexpected X error: %s serial %ld error_code %d request_code %d minor_code %d)\n") at core/util.c:398
#4  0x0806989c in x_error_handler (error=0xbf924acc, xdisplay=0x9104b88) at core/errors.c:247
#5  x_error_handler (xdisplay=0x9104b88, error=0xbf924acc) at core/errors.c:203
#6  0x00e97d3b in _XError (dpy=0x9104b88, rep=0x9131840) at ../../src/XlibInt.c:1583
#7  0x00e9490d in handle_error (dpy=0x9104b88, err=0x9131840, in_XReply=0) at ../../src/xcb_io.c:212
#8  0x00e94967 in handle_response (dpy=0x9104b88, response=0x9131840, in_XReply=0) at ../../src/xcb_io.c:324
#9  0x00e952fe in _XReadEvents (dpy=0x9104b88) at ../../src/xcb_io.c:425
#10 0x00e93663 in XWindowEvent (dpy=0x9104b88, w=16777220, mask=4194304, event=0xbf924c6c) at ../../src/WinEvent.c:79
#11 0x0806071c in meta_display_get_current_time_roundtrip (display=0x916d7d0) at core/display.c:1217
#12 0x08089f64 in meta_window_show (window=0x91ccfc8) at core/window.c:2165
#13 implement_showing (window=0x91ccfc8, showing=1) at core/window.c:1583
#14 0x080879cc in meta_window_flush_calc_showing (window=0x91ccfc8) at core/window.c:1806'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '''meta_display_get_current_time_roundtrip (display=0x916d7d0) at core/display.c:1217
meta_window_show (window=0x91ccfc8) at core/window.c:2165
implement_showing (window=0x91ccfc8, showing=1) at core/window.c:1583
meta_window_flush_calc_showing (window=0x91ccfc8) at core/window.c:1806''')

        # another XError (taken from LP#834403)
        r = apport.report.Report()
        r['Stacktrace'] = '''#0  g_logv (log_domain=0x7fd41db08a46 "Gdk", log_level=<optimized out>, format=0x7fd41db12e87 "%s", args1=0x7fff50bf0c18) at /build/buildd/glib2.0-2.29.16/./glib/gmessages.c:577
#1  0x00007fd42006bb92 in g_log (log_domain=<optimized out>, log_level=<optimized out>, format=<optimized out>) at /build/buildd/glib2.0-2.29.16/./glib/gmessages.c:591
#2  0x00007fd41dae86f3 in _gdk_x11_display_error_event (display=<optimized out>, error=<optimized out>) at /build/buildd/gtk+3.0-3.1.12/./gdk/x11/gdkdisplay-x11.c:2374
#3  0x00007fd41daf5647 in gdk_x_error (error=0x7fff50bf0dc0, xdisplay=<optimized out>) at /build/buildd/gtk+3.0-3.1.12/./gdk/x11/gdkmain-x11.c:312
#4  gdk_x_error (xdisplay=<optimized out>, error=0x7fff50bf0dc0) at /build/buildd/gtk+3.0-3.1.12/./gdk/x11/gdkmain-x11.c:275
#5  0x00007fd41d5a301f in _XError (dpy=0x2425370, rep=<optimized out>) at ../../src/XlibInt.c:1583
#6  0x00007fd41d59fdd1 in handle_error (dpy=0x2425370, err=0x7fd408707980, in_XReply=<optimized out>) at ../../src/xcb_io.c:212
#7  0x00007fd41d5a0d27 in _XReply (dpy=0x2425370, rep=0x7fff50bf0f60, extra=0, discard=0) at ../../src/xcb_io.c:698
#8  0x00007fd41d5852fb in XGetWindowProperty (dpy=0x2425370, w=0, property=348, offset=0, length=2, delete=<optimized out>, req_type=348, actual_type=0x7fff50bf1038, actual_format=0x7fff50bf105c, nitems=0x7fff50bf1040, bytesafter=0x7fff50bf1048, prop=0x7fff50bf1050) at ../../src/GetProp.c:61
#9  0x00007fd41938269e in window_is_xembed (w=<optimized out>, d=<optimized out>) at canberra-gtk-module.c:373
#10 dispatch_sound_event (d=0x32f6a30) at canberra-gtk-module.c:454
#11 dispatch_queue () at canberra-gtk-module.c:815'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '''XGetWindowProperty (dpy=0x2425370, w=0, property=348, offset=0, length=2, delete=<optimized out>, req_type=348, actual_type=0x7fff50bf1038, actual_format=0x7fff50bf105c, nitems=0x7fff50bf1040, bytesafter=0x7fff50bf1048, prop=0x7fff50bf1050) at ../../src/GetProp.c:61
window_is_xembed (w=<optimized out>, d=<optimized out>) at canberra-gtk-module.c:373
dispatch_sound_event (d=0x32f6a30) at canberra-gtk-module.c:454
dispatch_queue () at canberra-gtk-module.c:815''')

        # problem with too old gdb, only assertion, nothing else
        r = apport.report.Report()
        r['Stacktrace'] = '''#0  0x00987416 in __kernel_vsyscall ()
No symbol table info available.
#1  0x00ebecb1 in *__GI_raise (sig=6)
        selftid = 945
#2  0x00ec218e in *__GI_abort () at abort.c:59
        save_stage = Unhandled dwarf expression opcode 0x9f
'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '')

        # ignore uninteresting frames
        r = apport.report.Report()
        r['Stacktrace'] = '''#0  0x00987416 in __kernel_vsyscall ()
#1  __strchr_sse42 () at strchr.S:97
#2 h (p=0x0) at crash.c:25
#3  0x100004c8 in g (x=1, y=42) at crash.c:26
#4  0x10000999 in __memmove_ssse3 ()
#5 f (x=1) at crash.c:27
#6  0x10000530 in e (x=1) at crash.c:28
#7  0x10000999 in __strlen_sse2_back () at strchr.S:42
#8  0x10000530 in d (x=1) at crash.c:29
#9  0x10000530 in c (x=1) at crash.c:30
#10 0x10000550 in main () at crash.c:31
'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '''h (p=0x0) at crash.c:25
g (x=1, y=42) at crash.c:26
f (x=1) at crash.c:27
e (x=1) at crash.c:28
d (x=1) at crash.c:29''')

    def test_crash_signature(self):
        '''crash_signature().'''

        r = apport.report.Report()
        self.assertEqual(r.crash_signature(), None)

        # signal crashes
        r['Signal'] = '42'
        r['ExecutablePath'] = '/bin/crash'

        r['StacktraceTop'] = '''foo_bar (x=1) at crash.c:28
d01 (x=1) at crash.c:29
raise () from /lib/libpthread.so.0
<signal handler called>
__frob::~frob (x=1) at crash.c:30'''

        self.assertEqual(r.crash_signature(), '/bin/crash:42:foo_bar:d01:raise:<signal handler called>:__frob::~frob')

        r['StacktraceTop'] = '''foo_bar (x=1) at crash.c:28
??
raise () from /lib/libpthread.so.0
<signal handler called>
__frob (x=1) at crash.c:30'''
        self.assertEqual(r.crash_signature(), None)

        r['StacktraceTop'] = ''
        self.assertEqual(r.crash_signature(), None)

        # Python crashes
        del r['Signal']
        r['Traceback'] = '''Traceback (most recent call last):
  File "test.py", line 7, in <module>
    print(_f(5))
  File "test.py", line 5, in _f
    return g_foo00(x+1)
  File "test.py", line 2, in g_foo00
    return x/0
ZeroDivisionError: integer division or modulo by zero'''
        self.assertEqual(r.crash_signature(), '/bin/crash:ZeroDivisionError:test.py@7:_f:g_foo00')

        # sometimes Python traces do not have file references
        r['Traceback'] = 'TypeError: function takes exactly 0 arguments (1 given)'
        self.assertEqual(r.crash_signature(), '/bin/crash:TypeError')

        r['Traceback'] = 'FooBar'
        self.assertEqual(r.crash_signature(), None)

        # kernel
        r['ProblemType'] = 'KernelCrash'
        r['Stacktrace'] = '''
crash 4.0-8.9
GNU gdb 6.1
GDB is free software, covered by the GNU General Public License, and you are
welcome to change it and/or distribute copies of it under certain conditions.
Type "show copying" to see the conditions.
There is absolutely no warranty for GDB.  Type "show warranty" for details.
This GDB was configured as "i686-pc-linux-gnu"...

      KERNEL: /usr/lib/debug/boot/vmlinux-2.6.31-2-generic
    DUMPFILE: /tmp/tmpRJZy_O
        CPUS: 1
        DATE: Thu Jul  9 12:58:08 2009
      UPTIME: 00:00:57
LOAD AVERAGE: 0.15, 0.05, 0.02
       TASKS: 173
    NODENAME: egon-desktop
     RELEASE: 2.6.31-2-generic
     VERSION: #16-Ubuntu SMP Mon Jul 6 20:38:51 UTC 2009
     MACHINE: i686  (2137 Mhz)
      MEMORY: 2 GB
       PANIC: "[   57.879776] Oops: 0002 [#1] SMP " (check log for details)
         PID: 0
     COMMAND: "swapper"
        TASK: c073c180  [THREAD_INFO: c0784000]
         CPU: 0
       STATE: TASK_RUNNING (PANIC)

PID: 0      TASK: c073c180  CPU: 0   COMMAND: "swapper"
 #0 [c0785ba0] sysrq_handle_crash at c03917a3
    [RA: c03919c6  SP: c0785ba0  FP: c0785ba0  SIZE: 4]
    c0785ba0: c03919c6
 #1 [c0785ba0] __handle_sysrq at c03919c4
    [RA: c0391a91  SP: c0785ba4  FP: c0785bc8  SIZE: 40]
    c0785ba4: c06d4bab  c06d42d2  f6534000  00000004
    c0785bb4: 00000086  0000002e  00000001  f6534000
    c0785bc4: c0785bcc  c0391a91
 #2 [c0785bc8] handle_sysrq at c0391a8c
    [RA: c0389961  SP: c0785bcc  FP: c0785bd0  SIZE: 8]
    c0785bcc: c0785c0c  c0389961
 #3 [c0785bd0] kbd_keycode at c038995c
    [RA: c0389b8b  SP: c0785bd4  FP: c0785c10  SIZE: 64]
    c0785bd4: c056f96a  c0785be4  00000096  c07578c0
    c0785be4: 00000001  f6ac6e00  f6ac6e00  00000001
    c0785bf4: 00000000  00000000  0000002e  0000002e
    c0785c04: 00000001  f70d6850  c0785c1c  c0389b8b
 #4 [c0785c10] kbd_event at c0389b86
    [RA: c043140c  SP: c0785c14  FP: c0785c20  SIZE: 16]
    c0785c14: c0758040  f6910900  c0785c3c  c043140c
 #5 [c0785c20] input_pass_event at c0431409
    [RA: c04332ce  SP: c0785c24  FP: c0785c40  SIZE: 32]
    c0785c24: 00000001  0000002e  00000001  f70d6000
    c0785c34: 00000001  0000002e  c0785c64  c04332ce
 #6 [c0785c40] input_handle_event at c04332c9
    [RA: c0433ac6  SP: c0785c44  FP: c0785c68  SIZE: 40]
    c0785c44: 00000001  ffff138d  0000003d  00000001
    c0785c54: f70d6000  00000001  f70d6000  0000002e
    c0785c64: c0785c84  c0433ac6
 #7 [c0785c68] input_event at c0433ac1
    [RA: c0479806  SP: c0785c6c  FP: c0785c88  SIZE: 32]
    c0785c6c: 00000001  00000092  f70d677c  f70d70b4
    c0785c7c: 0000002e  f70d7000  c0785ca8  c0479806
 #8 [c0785c88] hidinput_hid_event at c0479801
    [RA: c0475b31  SP: c0785c8c  FP: c0785cac  SIZE: 36]
    c0785c8c: 00000001  00000007  c0785c00  f70d6000
    c0785c9c: f70d70b4  f70d5000  f70d7000  c0785cc4
    c0785cac: c0475b31
    [RA: 0  SP: c0785ffc  FP: c0785ffc  SIZE: 0]
   PID    PPID  CPU   TASK    ST  %MEM     VSZ    RSS  COMM
>     0      0   0  c073c180  RU   0.0       0      0  [swapper]
      1      0   1  f7038000  IN   0.1    3096   1960  init
      2      0   0  f7038c90  IN   0.0       0      0  [kthreadd]
    271      2   1  f72bf110  IN   0.0       0      0  [bluetooth]
    325      2   1  f71c25b0  IN   0.0       0      0  [khungtaskd]
   1404      2   0  f6b5bed0  IN   0.0       0      0  [kpsmoused]
   1504      2   1  f649cb60  IN   0.0       0      0  [hd-audio0]
   2055      1   0  f6a18000  IN   0.0    1824    536  getty
   2056      1   0  f6a1d7f0  IN   0.0    1824    536  getty
   2061      1   0  f6a1f110  IN   0.1    3132   1604  login
   2062      1   1  f6a18c90  IN   0.0    1824    540  getty
   2063      1   1  f6b58c90  IN   0.0    1824    540  getty
   2130      1   0  f6b5f110  IN   0.0    2200   1032  acpid
   2169      1   0  f69ebed0  IN   0.0    2040    664  syslogd
   2192      1   1  f65b3ed0  IN   0.0    1976    532  dd
   2194      1   1  f6b5a5b0  IN   0.1    3996   2712  klogd
   2217      1   0  f6b74b60  IN   0.1    3008   1120  dbus-daemon
   2248      1   0  f65b7110  IN   0.2    6896   4304  hald
   2251      1   1  f65b3240  IN   0.1   19688   2604  console-kit-dae
RUNQUEUES[0]: c6002320
 RT PRIO_ARRAY: c60023c0
 CFS RB_ROOT: c600237c
  PID: 9      TASK: f703f110  CPU: 0   COMMAND: "events/0"
'''
        self.assertEqual(r.crash_signature(), 'kernel:sysrq_handle_crash:__handle_sysrq:handle_sysrq:kbd_keycode:kbd_event:input_pass_event:input_handle_event:input_event:hidinput_hid_event')

        # assertion failures
        r = apport.report.Report()
        r['Signal'] = '6'
        r['ExecutablePath'] = '/bin/bash'
        r['AssertionMessage'] = 'foo.c:42 main: i > 0'
        self.assertEqual(r.crash_signature(), '/bin/bash:foo.c:42 main: i > 0')

    def test_nonascii_data(self):
        '''methods get along with non-ASCII data'''

        # fake os.uname() into reporting a non-ASCII name
        uname = os.uname()
        uname = (uname[0], b't\xe2\x99\xaax'.decode('UTF-8'), uname[2], uname[3], uname[4])
        orig_uname = os.uname
        os.uname = lambda: uname

        try:
            pr = apport.report.Report()
            utf8_val = b'\xc3\xa4 ' + uname[1].encode('UTF-8') + b' \xe2\x99\xa5 '
            pr['ProcUnicodeValue'] = utf8_val.decode('UTF-8')
            pr['ProcByteArrayValue'] = utf8_val

            pr.anonymize()

            exp_utf8 = b'\xc3\xa4 hostname \xe2\x99\xa5 '
            self.assertEqual(pr['ProcUnicodeValue'], exp_utf8.decode('UTF-8'))
            self.assertEqual(pr['ProcByteArrayValue'], exp_utf8)
        finally:
            os.uname = orig_uname

    def test_address_to_offset(self):
        '''_address_to_offset()'''

        pr = apport.report.Report()

        self.assertRaises(AssertionError, pr._address_to_offset, 0)

        pr['ProcMaps'] = '''
00400000-004df000 r-xp 00000000 08:02 1044485                            /bin/bash
006de000-006df000 r--p 000de000 08:02 1044485                            /bin/bash
01596000-01597000 rw-p 00000000 00:00 0
01597000-015a4000 rw-p 00000000 00:00 0                                  [heap]
7f491f868000-7f491f88a000 r-xp 00000000 08:02 526219                     /lib/x86_64-linux-gnu/libtinfo.so.5.9
7f491fa8f000-7f491fc24000 r-xp 00000000 08:02 522605                     /lib/x86_64-linux-gnu/libc-2.13.so
7f491fc24000-7f491fe23000 ---p 00195000 08:02 522605                     /lib/with spaces !/libfoo.so
7fff6e57b000-7fff6e59c000 rw-p 00000000 00:00 0                          [stack]
7fff6e5ff000-7fff6e600000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
'''

        self.assertEqual(pr._address_to_offset(0x41d703), '/bin/bash+1d703')
        self.assertEqual(pr._address_to_offset(0x00007f491fac5687),
            '/lib/x86_64-linux-gnu/libc-2.13.so+36687')

        self.assertEqual(pr._address_to_offset(0x006ddfff), None)
        self.assertEqual(pr._address_to_offset(0x006de000), '/bin/bash+0')
        self.assertEqual(pr._address_to_offset(0x006df000), '/bin/bash+1000')
        self.assertEqual(pr._address_to_offset(0x006df001), None)

        self.assertEqual(pr._address_to_offset(0x7f491fc24010),
            '/lib/with spaces !/libfoo.so+10')

    def test_address_to_offset_live(self):
        '''_address_to_offset() for current /proc/pid/maps'''

        # this primarily checks that the parser actually gets along with the
        # real /proc/pid/maps and not just with our static test case above
        pr = apport.report.Report()
        pr.add_proc_info()
        self.assertEqual(pr._address_to_offset(0), None)
        res = pr._address_to_offset(int(pr['ProcMaps'].split('-', 1)[0], 16) + 5)
        self.assertEqual(res.split('+', 1)[1], '5')
        self.assertTrue('python' in res.split('+', 1)[0])

    def test_crash_signature_addresses(self):
        '''crash_signature_addresses()'''

        pr = apport.report.Report()
        self.assertEqual(pr.crash_signature_addresses(), None)

        pr['ExecutablePath'] = '/bin/bash'
        pr['Signal'] = '42'
        pr['ProcMaps'] = '''
00400000-004df000 r-xp 00000000 08:02 1044485                            /bin/bash
006de000-006df000 r--p 000de000 08:02 1044485                            /bin/bash
01596000-01597000 rw-p 00000000 00:00 0
01597000-015a4000 rw-p 00000000 00:00 0                                  [heap]
7f491f868000-7f491f88a000 r-xp 00000000 08:02 526219                     /lib/x86_64-linux-gnu/libtinfo.so.5.9
7f491fa8f000-7f491fc24000 r-xp 00000000 08:02 522605                     /lib/x86_64-linux-gnu/libc-2.13.so
7f491fc24000-7f491fe23000 ---p 00195000 08:02 522605                     /lib/with spaces !/libfoo.so
7fff6e57b000-7fff6e59c000 rw-p 00000000 00:00 0                          [stack]
7fff6e5ff000-7fff6e600000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
'''

        # no Stacktrace field
        self.assertEqual(pr.crash_signature_addresses(), None)

        # good stack trace
        pr['Stacktrace'] = '''
#0  0x00007f491fac5687 in kill () at ../sysdeps/unix/syscall-template.S:82
No locals.
#1  0x000000000043fd51 in kill_pid ()
#2  g_main_context_iterate (context=0x1731680) at gmain.c:3068
#3  0x000000000042eb76 in ?? ()
#4  0x00000000004324d8 in ??
No symbol table info available.
#5  0x00000000004707e3 in parse_and_execute ()
#6  0x000000000041d703 in _start ()
'''
        self.assertEqual(pr.crash_signature_addresses(),
                '/bin/bash:42:%s:/lib/x86_64-linux-gnu/libc-2.13.so+36687:/bin/bash+3fd51:/bin/bash+2eb76:/bin/bash+324d8:/bin/bash+707e3:/bin/bash+1d703' % os.uname()[4])

        # all resolvable, but too short
        pr['Stacktrace'] = '#0  0x00007f491fac5687 in kill () at ../sysdeps/unix/syscall-template.S:82'
        self.assertEqual(pr.crash_signature_addresses(), None)

        # one unresolvable, but long enough
        pr['Stacktrace'] = '''
#0  0x00007f491fac5687 in kill () at ../sysdeps/unix/syscall-template.S:82
No locals.
#1  0x000001000043fd51 in kill_pid ()
#2  g_main_context_iterate (context=0x1731680) at gmain.c:3068
#3  0x000000000042eb76 in ?? ()
#4  0x00000000004324d8 in ??
No symbol table info available.
#5  0x00000000004707e3 in parse_and_execute ()
#6  0x000000000041d715 in main ()
#7  0x000000000041d703 in _start ()
'''
        self.assertNotEqual(pr.crash_signature_addresses(), None)

        # two unresolvables, 2/7 is too much
        pr['Stacktrace'] = '''
#0  0x00007f491fac5687 in kill () at ../sysdeps/unix/syscall-template.S:82
No locals.
#1  0x000001000043fd51 in kill_pid ()
#2  g_main_context_iterate (context=0x1731680) at gmain.c:3068
#3  0x000001000042eb76 in ?? ()
#4  0x00000000004324d8 in ??
No symbol table info available.
#5  0x00000000004707e3 in parse_and_execute ()
#6  0x000000000041d715 in main ()
#7  0x000000000041d703 in _start ()
'''
        self.assertEqual(pr.crash_signature_addresses(), None)

if __name__ == '__main__':
    unittest.main()
