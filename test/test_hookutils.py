import unittest, tempfile, locale, subprocess, re

import apport.hookutils

class T(unittest.TestCase):
    def test_module_license_evaluation(self):
        '''module licenses can be validated correctly'''

        def _build_ko(license):
            asm = tempfile.NamedTemporaryFile(prefix='%s-' % (license),
                                              suffix='.S')
            asm.write(('.section .modinfo\n.string "license=%s"\n' % (license)).encode())
            asm.flush()
            ko = tempfile.NamedTemporaryFile(prefix='%s-' % (license),
                                             suffix='.ko')
            subprocess.call(['/usr/bin/as',asm.name,'-o',ko.name])
            return ko
        
        good_ko = _build_ko('GPL')
        bad_ko  = _build_ko('BAD')

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
                (good_ko.name,bad_ko.name)).encode())
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
        self.assertTrue(report['CurrentDmesg'].startswith(b'['))

    def test_dmesg_overwrite(self):
        '''attach_dmesg() does not overwrite already existing data'''

        report = {'BootDmesg': 'existingboot'}

        apport.hookutils.attach_dmesg(report)
        self.assertEqual(report['BootDmesg'][:50], 'existingboot')
        self.assertTrue(report['CurrentDmesg'].startswith(b'['))
        
        report = {'BootDmesg': 'existingboot', 'CurrentDmesg': 'existingcurrent' }

        apport.hookutils.attach_dmesg(report)
        self.assertEqual(report['BootDmesg'], 'existingboot')
        self.assertEqual(report['CurrentDmesg'], 'existingcurrent')

    def test_attach_file(self):
        '''attach_file()'''

        with open('/etc/motd', 'rb') as f:
            motd_contents = f.read().strip()
        with open('/etc/issue', 'rb') as f:
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

    def test_attach_file_if_exists(self):
        '''attach_file_if_exists()'''

        with open('/etc/motd', 'rb') as f:
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
        self.assertEqual(apport.hookutils.recent_logfile('/nonexisting', re.compile('.')), '')
        self.assertEqual(apport.hookutils.recent_syslog(re.compile('ThisCantPossiblyHitAnything')), '')
        self.assertNotEqual(len(apport.hookutils.recent_syslog(re.compile('.'))), 0)

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

unittest.main()
