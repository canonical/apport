# coding: UTF-8
import unittest, tempfile, locale, subprocess, re, shutil, os.path, sys

import apport.hookutils


class T(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.workdir)

    def test_module_license_evaluation(self):
        '''module licenses can be validated correctly'''

        def _build_ko(license):
            asm = tempfile.NamedTemporaryFile(prefix='%s-' % (license),
                                              suffix='.S')
            asm.write(('.section .modinfo\n.string "license=%s"\n' % (license)).encode())
            asm.flush()
            ko = tempfile.NamedTemporaryFile(prefix='%s-' % (license),
                                             suffix='.ko')
            subprocess.call(['/usr/bin/as', asm.name, '-o', ko.name])
            return ko

        good_ko = _build_ko('GPL')
        bad_ko = _build_ko('BAD')

        # test:
        #  - loaded real module
        #  - unfindable module
        #  - fake GPL module
        #  - fake BAD module

        # direct license check
        self.assertTrue('GPL' in apport.hookutils._get_module_license('isofs'))
        self.assertEqual(apport.hookutils._get_module_license('does-not-exist'), 'invalid')
        self.assertTrue('GPL' in apport.hookutils._get_module_license(good_ko.name))
        self.assertTrue('BAD' in apport.hookutils._get_module_license(bad_ko.name))

        # check via nonfree_kernel_modules logic
        f = tempfile.NamedTemporaryFile()
        f.write(('isofs\ndoes-not-exist\n%s\n%s\n' %
                (good_ko.name, bad_ko.name)).encode())
        f.flush()
        nonfree = apport.hookutils.nonfree_kernel_modules(f.name)
        self.assertFalse('isofs' in nonfree)
        self.assertTrue('does-not-exist' in nonfree)
        self.assertFalse(good_ko.name in nonfree)
        self.assertTrue(bad_ko.name in nonfree)

    def test_attach_dmesg(self):
        '''attach_dmesg() does not overwrite already existing data'''

        report = {}

        apport.hookutils.attach_dmesg(report)
        self.assertTrue(report['BootDmesg'].startswith('['))
        self.assertTrue(len(report['BootDmesg']) > 500)
        self.assertTrue(report['CurrentDmesg'].startswith('['))

    def test_dmesg_overwrite(self):
        '''attach_dmesg() does not overwrite already existing data'''

        report = {'BootDmesg': 'existingboot'}

        apport.hookutils.attach_dmesg(report)
        self.assertEqual(report['BootDmesg'][:50], 'existingboot')
        self.assertTrue(report['CurrentDmesg'].startswith('['))

        report = {'BootDmesg': 'existingboot', 'CurrentDmesg': 'existingcurrent'}

        apport.hookutils.attach_dmesg(report)
        self.assertEqual(report['BootDmesg'], 'existingboot')
        self.assertEqual(report['CurrentDmesg'], 'existingcurrent')

    def test_attach_file(self):
        '''attach_file()'''

        with open('/etc/motd') as f:
            motd_contents = f.read().strip()
        with open('/etc/issue') as f:
            issue_contents = f.read().strip()

        # default key name
        report = {}
        apport.hookutils.attach_file(report, '/etc/motd')
        self.assertEqual(list(report), ['.etc.motd'])
        self.assertEqual(report['.etc.motd'], motd_contents)

        # custom key name
        report = {}
        apport.hookutils.attach_file(report, '/etc/motd', 'Motd')
        self.assertEqual(list(report), ['Motd'])
        self.assertEqual(report['Motd'], motd_contents)

        # nonexisting file
        report = {}
        apport.hookutils.attach_file(report, '/nonexisting')
        self.assertEqual(list(report), ['.nonexisting'])
        self.assertTrue(report['.nonexisting'].startswith('Error: '))

        # existing key
        report = {}
        apport.hookutils.attach_file(report, '/etc/motd')
        apport.hookutils.attach_file(report, '/etc/motd')
        self.assertEqual(list(report), ['.etc.motd'])
        self.assertEqual(report['.etc.motd'], motd_contents)

        apport.hookutils.attach_file(report, '/etc/issue', '.etc.motd', overwrite=False)
        self.assertEqual(sorted(report.keys()), ['.etc.motd', '.etc.motd_'])
        self.assertEqual(report['.etc.motd'], motd_contents)
        self.assertEqual(report['.etc.motd_'], issue_contents)

    def test_attach_file_binary(self):
        '''attach_file() for binary files'''

        myfile = os.path.join(self.workdir, 'data')
        with open(myfile, 'wb') as f:
            f.write(b'a\xc3\xb6b\xffx')

        report = {}
        apport.hookutils.attach_file(report, myfile, key='data')
        self.assertEqual(report['data'], b'a\xc3\xb6b\xffx')

        apport.hookutils.attach_file(report, myfile, key='data', force_unicode=True)
        self.assertEqual(report['data'], b'a\xc3\xb6b\xef\xbf\xbdx'.decode('UTF-8'))

    def test_attach_file_if_exists(self):
        '''attach_file_if_exists()'''

        with open('/etc/motd') as f:
            motd_contents = f.read().strip()

        # default key name
        report = {}
        apport.hookutils.attach_file_if_exists(report, '/etc/motd')
        self.assertEqual(list(report), ['.etc.motd'])
        self.assertEqual(report['.etc.motd'], motd_contents)

        # custom key name
        report = {}
        apport.hookutils.attach_file_if_exists(report, '/etc/motd', 'Motd')
        self.assertEqual(list(report), ['Motd'])
        self.assertEqual(report['Motd'], motd_contents)

        # nonexisting file
        report = {}
        apport.hookutils.attach_file_if_exists(report, '/nonexisting')
        self.assertEqual(list(report), [])

    def test_recent_logfile(self):
        '''recent_logfile'''

        self.assertEqual(apport.hookutils.recent_logfile('/nonexisting', re.compile('.')), '')
        self.assertEqual(apport.hookutils.recent_syslog(re.compile('ThisCantPossiblyHitAnything')), '')
        self.assertNotEqual(len(apport.hookutils.recent_syslog(re.compile('.'))), 0)

    def test_recent_logfile_overflow(self):
        '''recent_logfile on a huge file'''

        log = os.path.join(self.workdir, 'syslog')
        with open(log, 'w') as f:
            lines = 1000000
            while lines >= 0:
                f.write('Apr 20 11:30:00 komputer kernel: bogus message\n')
                lines -= 1

        mem_before = self._get_mem_usage()
        data = apport.hookutils.recent_logfile(log, re.compile('kernel'))
        mem_after = self._get_mem_usage()
        delta_kb = mem_after - mem_before
        sys.stderr.write('[Δ %i kB] ' % delta_kb)
        self.assertLess(delta_kb, 5000)

        self.assertTrue(data.startswith('Apr 20 11:30:00 komputer kernel: bogus message\n'))
        self.assertGreater(len(data), 100000)
        self.assertLess(len(data), 1000000)

    @unittest.skipIf(apport.hookutils.apport.hookutils.in_session_of_problem(apport.Report()) is None, 'no ConsoleKit session')
    def test_in_session_of_problem(self):
        '''in_session_of_problem()'''

        old_ctime = locale.getlocale(locale.LC_TIME)
        locale.setlocale(locale.LC_TIME, 'C')

        report = {'Date': 'Sat Jan  1 12:00:00 2011'}
        self.assertFalse(apport.hookutils.in_session_of_problem(report))

        report = {'Date': 'Mon Oct 10 21:06:03 2009'}
        self.assertFalse(apport.hookutils.in_session_of_problem(report))

        report = {'Date': 'Tue Jan  1 12:00:00 2211'}
        self.assertTrue(apport.hookutils.in_session_of_problem(report))

        locale.setlocale(locale.LC_TIME, '')

        report = {'Date': 'Sat Jan  1 12:00:00 2011'}
        self.assertFalse(apport.hookutils.in_session_of_problem(report))

        report = {'Date': 'Mon Oct 10 21:06:03 2009'}
        self.assertFalse(apport.hookutils.in_session_of_problem(report))

        report = apport.Report()
        self.assertTrue(apport.hookutils.in_session_of_problem(report))

        self.assertEqual(apport.hookutils.in_session_of_problem({}), None)

        locale.setlocale(locale.LC_TIME, old_ctime)

    def test_xsession_errors(self):
        '''xsession_errors()'''

        with open(os.path.join(self.workdir, '.xsession-errors'), 'w') as f:
            f.write('''Loading profile from /etc/profile
gnome-session[1948]: WARNING: standard glib warning
EggSMClient-CRITICAL **: egg_sm_client_set_mode: standard glib assertion
24/02/2012 11:14:46 Sending credentials s3kr1t

** WARNING **: nonstandard warning

WARN  2012-02-24 11:23:47 unity <unknown>:0 some unicode ♥ ♪

GNOME_KEYRING_CONTROL=/tmp/keyring-u7hrD6

(gnome-settings-daemon:5115): Gdk-WARNING **: The program 'gnome-settings-daemon' received an X Window System error.
This probably reflects a bug in the program.
The error was 'BadMatch (invalid parameter attributes)'.
  (Details: serial 723 error_code 8 request_code 143 minor_code 22)
  (Note to programmers: normally, X errors are reported asynchronously;
   that is, you will receive the error a while after causing it.
   To debug your program, run it with the --sync command line
   option to change this behavior. You can then get a meaningful
   backtrace from your debugger if you break on the gdk_x_error() function.)"

GdkPixbuf-CRITICAL **: gdk_pixbuf_scale_simple: another standard glib assertion
''')
        orig_home = os.environ.get('HOME')
        try:
            os.environ['HOME'] = self.workdir

            # explicit pattern
            pattern = re.compile('notfound')
            self.assertEqual(apport.hookutils.xsession_errors(pattern), '')

            pattern = re.compile('^\w+-CRITICAL')
            res = apport.hookutils.xsession_errors(pattern).splitlines()
            self.assertEqual(len(res), 2)
            self.assertTrue(res[0].startswith('EggSMClient-CRITICAL'))
            self.assertTrue(res[1].startswith('GdkPixbuf-CRITICAL'))

            # default pattern includes glib assertions and X Errors
            res = apport.hookutils.xsession_errors()
            self.assertFalse('nonstandard warning' in res)
            self.assertFalse('keyring' in res)
            self.assertFalse('credentials' in res)
            self.assertTrue('WARNING: standard glib warning' in res, res)
            self.assertTrue('GdkPixbuf-CRITICAL' in res, res)
            self.assertTrue("'gnome-settings-daemon' received an X Window" in res, res)
            self.assertTrue('BadMatch' in res, res)
            self.assertTrue('serial 723' in res, res)

        finally:
            if orig_home is not None:
                os.environ['HOME'] = orig_home
            else:
                os.unsetenv('HOME')

    def test_no_crashes(self):
        '''functions do not crash (very shallow)'''

        report = {}
        apport.hookutils.attach_hardware(report)
        apport.hookutils.attach_alsa(report)
        apport.hookutils.attach_network(report)
        apport.hookutils.attach_wifi(report)
        apport.hookutils.attach_printing(report)
        apport.hookutils.attach_conffiles(report, 'bash')
        apport.hookutils.attach_conffiles(report, 'apport')
        apport.hookutils.attach_conffiles(report, 'nonexisting')
        apport.hookutils.attach_upstart_overrides(report, 'apport')
        apport.hookutils.attach_upstart_overrides(report, 'nonexisting')
        apport.hookutils.attach_default_grub(report)

    def test_command_output(self):
        orig_lcm = os.environ.get('LC_MESSAGES')
        os.environ['LC_MESSAGES'] = 'en_US.UTF-8'
        try:
            # default mode: disable translations
            out = apport.hookutils.command_output(['env'])
            self.assertTrue('LC_MESSAGES=C' in out)

            # keep locale
            out = apport.hookutils.command_output(['env'], keep_locale=True)
            self.assertFalse('LC_MESSAGES=C' in out, out)
        finally:
            if orig_lcm is not None:
                os.environ['LC_MESSAGES'] = orig_lcm
            else:
                os.unsetenv('LC_MESSAGES')

        # nonexisting binary
        out = apport.hookutils.command_output(['/non existing'])
        self.assertTrue(out.startswith('Error: [Errno 2]'))

        # stdin
        out = apport.hookutils.command_output(['cat'], input=b'hello')
        self.assertEqual(out, 'hello')

    @classmethod
    def _get_mem_usage(klass):
        '''Get current memory usage in kB'''

        with open('/proc/self/status') as f:
            for line in f:
                if line.startswith('VmSize:'):
                    return int(line.split()[1])
            else:
                raise SystemError('did not find VmSize: in /proc/self/status')

unittest.main()
