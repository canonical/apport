import unittest, tempfile, os, shutil, time, sys, pwd

import problem_report
import apport.fileutils
import apport.packaging

from io import BytesIO

from unittest.mock import patch


class T(unittest.TestCase):
    def setUp(self):
        self.orig_core_dir = apport.fileutils.core_dir
        apport.fileutils.core_dir = tempfile.mkdtemp()
        self.orig_report_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = tempfile.mkdtemp()
        self.orig_config_file = apport.fileutils._config_file

    def tearDown(self):
        shutil.rmtree(apport.fileutils.core_dir)
        apport.fileutils.core_dir = self.orig_core_dir
        shutil.rmtree(apport.fileutils.report_dir)
        apport.fileutils.report_dir = self.orig_report_dir
        self.orig_report_dir = None
        apport.fileutils._config_file = self.orig_config_file

    def _create_reports(self, create_inaccessible=False):
        '''Create some test reports'''

        r1 = os.path.join(apport.fileutils.report_dir, 'rep1.crash')
        r2 = os.path.join(apport.fileutils.report_dir, 'rep2.crash')

        with open(r1, 'w') as fd:
            fd.write('report 1')
        with open(r2, 'w') as fd:
            fd.write('report 2')
        os.chmod(r1, 0o600)
        os.chmod(r2, 0o600)
        if create_inaccessible:
            ri = os.path.join(apport.fileutils.report_dir, 'inaccessible.crash')
            with open(ri, 'w') as fd:
                fd.write('inaccessible')
            os.chmod(ri, 0)
            return [r1, r2, ri]
        else:
            return [r1, r2]

    def test_find_package_desktopfile(self):
        '''find_package_desktopfile()'''

        # package without any .desktop file
        nodesktop = 'bash'
        assert len([f for f in apport.packaging.get_files(nodesktop)
                    if f.endswith('.desktop')]) == 0

        # find a package with one, a package with multiple .desktop files, and
        # a package with a NoDisplay .desktop file
        onedesktop = None
        multidesktop = None
        nodisplay = None
        found_some = False
        for d in os.listdir('/usr/share/applications/'):
            if not d.endswith('.desktop'):
                continue
            path = os.path.join('/usr/share/applications/', d)
            pkg = apport.packaging.get_file_package(path)
            if pkg is None:
                continue
            found_some = True

            display_num = 0
            no_display_num = 0
            for desktop_file in apport.packaging.get_files(pkg):
                if not desktop_file.endswith('.desktop'):
                    continue
                with open(desktop_file, 'rb') as desktop_file:
                    if b'NoDisplay=true' in desktop_file.read():
                        no_display_num += 1
                    else:
                        display_num += 1

            if not nodisplay and display_num == 0 and no_display_num == 1:
                nodisplay = pkg
            elif not onedesktop and display_num == 1:
                onedesktop = pkg
            elif not multidesktop and display_num > 1:
                multidesktop = pkg

            if onedesktop and multidesktop and nodisplay:
                break

        self.assertTrue(found_some)

        if nodesktop:
            self.assertEqual(apport.fileutils.find_package_desktopfile(nodesktop),
                             None, 'no-desktop package %s' % nodesktop)
        if multidesktop:
            self.assertEqual(apport.fileutils.find_package_desktopfile(multidesktop),
                             None, 'multi-desktop package %s' % multidesktop)
        if onedesktop:
            d = apport.fileutils.find_package_desktopfile(onedesktop)
            self.assertNotEqual(d, None, 'one-desktop package %s' % onedesktop)
            self.assertTrue(os.path.exists(d))
            self.assertTrue(d.endswith('.desktop'))
        if nodisplay:
            self.assertEqual(apport.fileutils.find_package_desktopfile(nodisplay), None,
                             'NoDisplay package %s' % nodisplay)

    def test_likely_packaged(self):
        '''likely_packaged()'''

        self.assertEqual(apport.fileutils.likely_packaged('/bin/bash'), True)
        self.assertEqual(apport.fileutils.likely_packaged('/usr/bin/foo'), True)
        self.assertEqual(apport.fileutils.likely_packaged('/usr/local/bin/foo'), False)
        self.assertEqual(apport.fileutils.likely_packaged('/home/test/bin/foo'), False)
        self.assertEqual(apport.fileutils.likely_packaged('/tmp/foo'), False)
        # ignore crashes in /var/lib (LP#122859, LP#414368)
        self.assertEqual(apport.fileutils.likely_packaged('/var/lib/foo'), False)

    def test_find_file_package(self):
        '''find_file_package()'''

        self.assertEqual(apport.fileutils.find_file_package('/bin/bash'), 'bash')
        self.assertEqual(apport.fileutils.find_file_package('/bin/cat'), 'coreutils')
        self.assertEqual(apport.fileutils.find_file_package('/nonexisting'), None)

    def test_seen(self):
        '''get_new_reports() and seen_report()'''

        self.assertEqual(apport.fileutils.get_new_reports(), [])
        if os.getuid() == 0:
            tr = self._create_reports(True)
        else:
            tr = [r for r in self._create_reports(True) if 'inaccessible' not in r]
        self.assertEqual(set(apport.fileutils.get_new_reports()), set(tr))

        # now mark them as seen and check again
        nr = set(tr)
        for r in tr:
            self.assertEqual(apport.fileutils.seen_report(r), False)
            nr.remove(r)
            apport.fileutils.mark_report_seen(r)
            self.assertEqual(apport.fileutils.seen_report(r), True)
            self.assertEqual(set(apport.fileutils.get_new_reports()), nr)

    def test_mark_hanging_process(self):
        '''mark_hanging_process()'''
        pr = problem_report.ProblemReport()
        pr['ExecutablePath'] = '/bin/bash'
        apport.fileutils.mark_hanging_process(pr, '1')
        uid = str(os.getuid())
        base = '_bin_bash.%s.1.hanging' % uid
        expected = os.path.join(apport.fileutils.report_dir, base)
        self.assertTrue(os.path.exists(expected))

    def test_mark_report_upload(self):
        '''mark_report_upload()'''
        report = os.path.join(apport.fileutils.report_dir, 'report.crash')
        apport.fileutils.mark_report_upload(report)
        expected = os.path.join(apport.fileutils.report_dir, 'report.upload')
        self.assertTrue(os.path.exists(expected))

    def test_mark_2nd_report_upload(self):
        '''mark_report_upload() for a previously uploaded report'''
        upload = os.path.join(apport.fileutils.report_dir, 'report.upload')
        with open(upload, 'w'):
            pass
        uploaded = os.path.join(apport.fileutils.report_dir, 'report.uploaded')
        with open(uploaded, 'w'):
            pass
        time.sleep(1)
        report = os.path.join(apport.fileutils.report_dir, 'report.crash')
        with open(report, 'w'):
            pass
        time.sleep(1)
        apport.fileutils.mark_report_upload(report)
        upload_st = os.stat(upload)
        report_st = os.stat(report)
        self.assertTrue(upload_st.st_mtime > report_st.st_mtime)

    def test_get_all_reports(self):
        '''get_all_reports()'''

        self.assertEqual(apport.fileutils.get_all_reports(), [])
        if os.getuid() == 0:
            tr = self._create_reports(True)
        else:
            tr = [r for r in self._create_reports(True) if 'inaccessible' not in r]
        self.assertEqual(set(apport.fileutils.get_all_reports()), set(tr))

        # now mark them as seen and check again
        for r in tr:
            apport.fileutils.mark_report_seen(r)

        self.assertEqual(set(apport.fileutils.get_all_reports()), set(tr))

    def test_get_system_reports(self):
        '''get_all_system_reports() and get_new_system_reports()'''

        self.assertEqual(apport.fileutils.get_all_reports(), [])
        self.assertEqual(apport.fileutils.get_all_system_reports(), [])
        if os.getuid() == 0:
            tr = self._create_reports(True)
            self.assertEqual(set(apport.fileutils.get_all_system_reports()), set(tr))
            self.assertEqual(set(apport.fileutils.get_new_system_reports()), set(tr))

            # now mark them as seen and check again
            for r in tr:
                apport.fileutils.mark_report_seen(r)

            self.assertEqual(set(apport.fileutils.get_all_system_reports()), set(tr))
            self.assertEqual(set(apport.fileutils.get_new_system_reports()), set([]))
        else:
            tr = [r for r in self._create_reports(True) if 'inaccessible' not in r]
            self.assertEqual(set(apport.fileutils.get_all_system_reports()), set([]))
            self.assertEqual(set(apport.fileutils.get_new_system_reports()), set([]))

    @patch.object(os, 'stat')
    @patch.object(pwd, 'getpwuid')
    def test_get_system_reports_guest(self, *args):
        '''get_all_system_reports() filters out reports from guest user'''

        self._create_reports()

        os.stat.return_value.st_size = 1000
        os.stat.return_value.st_uid = 123
        pwd.getpwuid.return_value.pw_name = 'guest_tmp987'
        self.assertEqual(apport.fileutils.get_all_system_reports(), [])

    def test_unwritable_report(self):
        '''get_all_reports() and get_new_reports() for unwritable report'''

        self.assertEqual(apport.fileutils.get_all_reports(), [])
        self.assertEqual(apport.fileutils.get_all_system_reports(), [])

        r = os.path.join(apport.fileutils.report_dir, 'unwritable.crash')
        with open(r, 'w') as fd:
            fd.write('unwritable')
        os.chmod(r, 0o444)

        if os.getuid() == 0:
            self.assertEqual(set(apport.fileutils.get_new_reports()), set([r]))
            self.assertEqual(set(apport.fileutils.get_all_reports()), set([r]))
        else:
            self.assertEqual(set(apport.fileutils.get_new_reports()), set())
            self.assertEqual(set(apport.fileutils.get_all_reports()), set())

    def test_delete_report(self):
        '''delete_report()'''

        tr = self._create_reports()

        while tr:
            self.assertEqual(set(apport.fileutils.get_all_reports()), set(tr))
            apport.fileutils.delete_report(tr.pop())

    def test_get_recent_crashes(self):
        '''get_recent_crashes()'''

        # incomplete fields
        r = BytesIO(b'''ProblemType: Crash''')
        self.assertEqual(apport.fileutils.get_recent_crashes(r), 0)

        r = BytesIO(b'''ProblemType: Crash
Date: Wed Aug 01 00:00:01 1990''')
        self.assertEqual(apport.fileutils.get_recent_crashes(r), 0)

        # ancient report
        r = BytesIO(b'''ProblemType: Crash
Date: Wed Aug 01 00:00:01 1990
CrashCounter: 3''')
        self.assertEqual(apport.fileutils.get_recent_crashes(r), 0)

        # old report (one day + one hour ago)
        date = time.ctime(time.mktime(time.localtime()) - 25 * 3600)
        r = BytesIO(b'''ProblemType: Crash
Date: ''' + date.encode() + b'''
CrashCounter: 3''')
        self.assertEqual(apport.fileutils.get_recent_crashes(r), 0)

        # current report (one hour ago)
        date = time.ctime(time.mktime(time.localtime()) - 3600)
        r = BytesIO(b'''ProblemType: Crash
Date: ''' + date.encode() + b'''
CrashCounter: 3''')
        self.assertEqual(apport.fileutils.get_recent_crashes(r), 3)

    def test_make_report_file(self):
        '''make_report_file()'''

        pr = problem_report.ProblemReport()
        self.assertRaises(ValueError, apport.fileutils.make_report_file, pr)

        pr['Package'] = 'bash 1'
        with apport.fileutils.make_report_file(pr) as f:
            path = f.name
            self.assertTrue(path.startswith('%s/bash' % apport.fileutils.report_dir), path)
            os.unlink(path)

        pr['ExecutablePath'] = '/bin/bash'
        with apport.fileutils.make_report_file(pr) as f:
            path = f.name
            self.assertTrue(path.startswith('%s/_bin_bash' % apport.fileutils.report_dir), path)

        # file exists already, should fail now
        self.assertRaises(OSError, apport.fileutils.make_report_file, pr)

        # should still fail if it's a dangling symlink
        os.unlink(path)
        os.symlink(os.path.join(apport.fileutils.report_dir, 'pwned'), path)
        self.assertRaises(OSError, apport.fileutils.make_report_file, pr)

    def test_check_files_md5(self):
        '''check_files_md5()'''

        f1 = os.path.join(apport.fileutils.report_dir, 'test 1.txt')
        f2 = os.path.join(apport.fileutils.report_dir, 'test:2.txt')
        sumfile = os.path.join(apport.fileutils.report_dir, 'sums.txt')
        with open(f1, 'w') as fd:
            fd.write('Some stuff')
        with open(f2, 'w') as fd:
            fd.write('More stuff')
        # use one relative and one absolute path in checksums file
        with open(sumfile, 'w') as fd:
            fd.write('''2e41290da2fa3f68bd3313174467e3b5  %s
f6423dfbc4faf022e58b4d3f5ff71a70  %s
''' % (f1[1:], f2))
        self.assertEqual(apport.fileutils.check_files_md5(sumfile), [], 'correct md5sums')

        with open(f1, 'w') as fd:
            fd.write('Some stuff!')
        self.assertEqual(apport.fileutils.check_files_md5(sumfile), [f1[1:]], 'file 1 wrong')
        with open(f2, 'w') as fd:
            fd.write('More stuff!')
        self.assertEqual(apport.fileutils.check_files_md5(sumfile), [f1[1:], f2], 'files 1 and 2 wrong')
        with open(f1, 'w') as fd:
            fd.write('Some stuff')
        self.assertEqual(apport.fileutils.check_files_md5(sumfile), [f2], 'file 2 wrong')

    def test_get_config(self):
        '''get_config()'''

        # nonexisting
        apport.fileutils._config_file = '/nonexisting'
        self.assertEqual(apport.fileutils.get_config('main', 'foo'), None)
        self.assertEqual(apport.fileutils.get_config('main', 'foo', 'moo'), 'moo')
        apport.fileutils.get_config.config = None  # trash cache

        # empty
        f = tempfile.NamedTemporaryFile()
        apport.fileutils._config_file = f.name
        self.assertEqual(apport.fileutils.get_config('main', 'foo'), None)
        self.assertEqual(apport.fileutils.get_config('main', 'foo', 'moo'), 'moo')
        apport.fileutils.get_config.config = None  # trash cache

        # nonempty
        f.write(b'[main]\none=1\ntwo = TWO\nb1 = 1\nb2=False\n[spethial]\none= 99\n')
        f.flush()
        self.assertEqual(apport.fileutils.get_config('main', 'foo'), None)
        self.assertEqual(apport.fileutils.get_config('main', 'foo', 'moo'), 'moo')
        self.assertEqual(apport.fileutils.get_config('main', 'one'), '1')
        self.assertEqual(apport.fileutils.get_config('main', 'one', default='moo'), '1')
        self.assertEqual(apport.fileutils.get_config('main', 'two'), 'TWO')
        self.assertEqual(apport.fileutils.get_config('main', 'b1', bool=True), True)
        self.assertEqual(apport.fileutils.get_config('main', 'b2', bool=True), False)
        self.assertEqual(apport.fileutils.get_config('main', 'b3', bool=True), None)
        self.assertEqual(apport.fileutils.get_config('main', 'b3', default=False, bool=True), False)
        self.assertEqual(apport.fileutils.get_config('spethial', 'one'), '99')
        self.assertEqual(apport.fileutils.get_config('spethial', 'two'), None)
        self.assertEqual(apport.fileutils.get_config('spethial', 'one', 'moo'), '99')
        self.assertEqual(apport.fileutils.get_config('spethial', 'nope', 'moo'), 'moo')
        apport.fileutils.get_config.config = None  # trash cache

        f.close()

    def test_shared_libraries(self):
        '''shared_libraries()'''

        libs = apport.fileutils.shared_libraries(sys.executable)
        self.assertGreater(len(libs), 3)
        self.assertTrue('libc.so.6' in libs, libs)
        self.assertTrue('libc.so.6' in libs['libc.so.6'], libs['libc.so.6'])
        self.assertTrue(os.path.exists(libs['libc.so.6']))
        for line in libs:
            self.assertFalse('vdso' in line, libs)
            self.assertTrue(os.path.exists(libs[line]))

        self.assertEqual(apport.fileutils.shared_libraries('/non/existing'), {})
        self.assertEqual(apport.fileutils.shared_libraries('/etc'), {})
        self.assertEqual(apport.fileutils.shared_libraries('/etc/passwd'), {})

    def test_links_with_shared_library(self):
        '''links_with_shared_library()'''

        self.assertTrue(apport.fileutils.links_with_shared_library(sys.executable, 'libc'))
        self.assertTrue(apport.fileutils.links_with_shared_library(sys.executable, 'libc.so.6'))
        self.assertFalse(apport.fileutils.links_with_shared_library(sys.executable, 'libc.so.7'))
        self.assertFalse(apport.fileutils.links_with_shared_library(sys.executable, 'libd'))
        self.assertFalse(apport.fileutils.links_with_shared_library('/non/existing', 'libc'))
        self.assertFalse(apport.fileutils.links_with_shared_library('/etc', 'libc'))
        self.assertFalse(apport.fileutils.links_with_shared_library('/etc/passwd', 'libc'))

    def test_get_starttime(self):
        '''get_starttime()'''

        template = ('2022799 (%s) S 1834041 2022799 2022799 34820 '
                    '2022806 4194304 692 479 0 0 2 0 0 0 20 0 1 0 '
                    '34034895 13750272 1270 18446744073709551615 '
                    '94876723015680 94876723738373 140731174338544 '
                    '0 0 0 65536 3670020 1266777851 1 0 0 17 7 0 0 0 0 0 '
                    '94876723969264 94876724016644 94876748173312 '
                    '140731174345133 140731174345138 140731174345138 '
                    '140731174346734 0\n')

        for name in ['goodname', 'bad name', '(badname', 'badname)',
                     '(badname)', '((badname))', 'badname(', ')badname',
                     'bad) name', 'bad) name\\']:
            starttime = apport.fileutils.get_starttime(template % name)
            self.assertEqual(starttime, 34034895)

    def test_get_uid_and_gid(self):
        '''get_uid_and_gid()'''

        # Python 3's open uses universal newlines, which means all
        # line endings get replaced with \n, so we don't need to test
        # different line ending combinations
        template = ('Name:\t%s\n'
                    'Umask:\t0002\n'
                    'State:\tS (sleeping)\n'
                    'Tgid:\t2288405\n'
                    'Ngid:\t0\n'
                    'Pid:\t2288405\n'
                    'PPid:\t2167353\n'
                    'TracerPid:\t0\n'
                    'Uid:\t1000\t1000\t1000\t1000\n'
                    'Gid:\t2000\t2000\t2000\t2000\n'
                    'FDSize:\t256\n'
                    'Groups:\t4 20 24 27 30 46 108 120 131 132 135 137 1000 \n'
                    'NStgid:\t2288405\n'
                    'NSpid:\t2288405\n'
                    'NSpgid:\t2288405\n'
                    'NSsid:\t2288405\n'
                    'VmPeak:\t   13428 kB\n'
                    'VmSize:\t   13428 kB\n'
                    'VmLck:\t       0 kB\n'
                    'VmPin:\t       0 kB\n'
                    'VmHWM:\t    5200 kB\n'
                    'VmRSS:\t    5200 kB\n'
                    'RssAnon:\t    1700 kB\n'
                    'RssFile:\t    3500 kB\n'
                    'RssShmem:\t       0 kB\n'
                    'VmData:\t    1600 kB\n'
                    'VmStk:\t     132 kB\n'
                    'VmExe:\t     708 kB\n'
                    'VmLib:\t    1748 kB\n'
                    'VmPTE:\t      68 kB\n'
                    'VmSwap:\t       0 kB\n'
                    'HugetlbPages:\t       0 kB\n'
                    'CoreDumping:\t0\n'
                    'THP_enabled:\t1\n'
                    'Threads:\t1\n'
                    'SigQ:\t0/62442\n'
                    'SigPnd:\t0000000000000000\n'
                    'ShdPnd:\t0000000000000000\n'
                    'SigBlk:\t0000000000010000\n'
                    'SigIgn:\t0000000000380004\n'
                    'SigCgt:\t000000004b817efb\n'
                    'CapInh:\t0000000000000000\n'
                    'CapPrm:\t0000000000000000\n'
                    'CapEff:\t0000000000000000\n'
                    'CapBnd:\t000000ffffffffff\n'
                    'CapAmb:\t0000000000000000\n'
                    'NoNewPrivs:\t0\n'
                    'Seccomp:\t0\n'
                    'Speculation_Store_Bypass:\tthread vulnerable\n'
                    'Cpus_allowed:\tff\n'
                    'Cpus_allowed_list:\t0-7\n'
                    'Mems_allowed:\t00000000,00000000,00000000,00000000,'
                    '00000000,00000000,00000000,00000000,00000000,'
                    '00000000,00000000,00000000,00000000,00000000,'
                    '00000000,00000000,00000000,00000000,00000000,'
                    '00000000,00000000,00000000,00000000,00000000,'
                    '00000000,00000000,00000000,00000000,00000000,'
                    '00000000,00000000,00000001\n'
                    'Mems_allowed_list:\t0\n'
                    'voluntary_ctxt_switches:\t133\n'
                    'nonvoluntary_ctxt_switches:\t0\n')

        for name in ['goodname', 'Uid:', '\nUid:', 'Uid: 1000 1000 1000\n',
                     'a\nUid: 0\nGid: 0', 'a\nUid: 0\nGid:']:
            (uid, gid) = apport.fileutils.get_uid_and_gid(template % name)
            self.assertEqual(uid, 1000)
            self.assertEqual(gid, 2000)

    def test_get_core_path(self):
        '''get_core_path()'''

        boot_id = apport.fileutils.get_boot_id()

        # Basic test
        (core_name, core_path) = apport.fileutils.get_core_path(
            pid=123,
            exe="/usr/bin/test",
            uid=234,
            timestamp=222222)
        expected = "core._usr_bin_test.234." + boot_id + ".123.222222"
        expected_path = os.path.join(apport.fileutils.core_dir, expected)
        self.assertEqual(core_name, expected)
        self.assertEqual(core_path, expected_path)

        # Test dots in exe names
        (core_name, core_path) = apport.fileutils.get_core_path(
            pid=123,
            exe="/usr/bin/test.sh",
            uid=234,
            timestamp=222222)
        expected = "core._usr_bin_test_sh.234." + boot_id + ".123.222222"
        expected_path = os.path.join(apport.fileutils.core_dir, expected)
        self.assertEqual(core_name, expected)
        self.assertEqual(core_path, expected_path)

        # Test no exe name
        (core_name, core_path) = apport.fileutils.get_core_path(
            pid=123,
            exe=None,
            uid=234,
            timestamp=222222)
        expected = "core.unknown.234." + boot_id + ".123.222222"
        expected_path = os.path.join(apport.fileutils.core_dir, expected)
        self.assertEqual(core_name, expected)
        self.assertEqual(core_path, expected_path)

        # Test no uid
        (core_name, core_path) = apport.fileutils.get_core_path(
            pid=123,
            exe="/usr/bin/test",
            uid=None,
            timestamp=222222)
        expected = ("core._usr_bin_test." + str(os.getuid()) + "." +
                    boot_id + ".123.222222")
        expected_path = os.path.join(apport.fileutils.core_dir, expected)
        self.assertEqual(core_name, expected)
        self.assertEqual(core_path, expected_path)

    def test_clean_core_directory(self):
        '''clean_core_directory()'''

        fake_uid = 5150
        extra_core_files = 4
        num_core_files = apport.fileutils.max_corefiles_per_uid + extra_core_files

        # Create some test files
        for x in range(num_core_files):
            (core_name, core_path) = apport.fileutils.get_core_path(
                pid=123 + x,
                exe="/usr/bin/test",
                uid=fake_uid,
                timestamp=222222 + x)
            with open(core_path, 'w') as fd:
                fd.write('Some stuff')
                time.sleep(1)

        # Create a file with a different uid
        (core_name, core_path) = apport.fileutils.get_core_path(
            pid=231,
            exe="/usr/bin/test",
            uid=fake_uid + 1,
            timestamp=333333)
        with open(core_path, 'w') as fd:
            fd.write('Some stuff')

        # Make sure we have the proper number of test files
        self.assertEqual(num_core_files,
                         len(apport.fileutils.find_core_files_by_uid(fake_uid)))
        self.assertEqual(1,
                         len(apport.fileutils.find_core_files_by_uid(fake_uid + 1)))

        # Clean out the directory
        apport.fileutils.clean_core_directory(fake_uid)

        # Make sure we have the proper number of test files. We should
        # have one less than max_corefiles_per_uid.
        self.assertEqual(apport.fileutils.max_corefiles_per_uid - 1,
                         len(apport.fileutils.find_core_files_by_uid(fake_uid)))
        self.assertEqual(1,
                         len(apport.fileutils.find_core_files_by_uid(fake_uid + 1)))

        # Make sure we deleted the oldest ones
        for x in range(apport.fileutils.max_corefiles_per_uid - 1):
            offset = extra_core_files + x + 1
            (core_name, core_path) = apport.fileutils.get_core_path(
                pid=123 + offset,
                exe="/usr/bin/test",
                uid=fake_uid,
                timestamp=222222 + offset)
            self.assertTrue(os.path.exists(core_path))


if __name__ == '__main__':
    unittest.main()
