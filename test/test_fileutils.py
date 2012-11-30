import unittest, tempfile, os, shutil, time

import problem_report
import apport.fileutils
import apport.packaging

from io import BytesIO


class T(unittest.TestCase):
    def setUp(self):
        self.orig_report_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = tempfile.mkdtemp()
        self.orig_config_file = apport.fileutils._config_file

    def tearDown(self):
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
        for d in os.listdir('/usr/share/applications/'):
            if not d.endswith('.desktop'):
                continue
            path = os.path.join('/usr/share/applications/', d)
            pkg = apport.packaging.get_file_package(path)
            num = len([f for f in apport.packaging.get_files(pkg)
                       if f.endswith('.desktop')])
            if not nodisplay and num == 1:
                with open(path) as f:
                    if 'NoDisplay=true' in f.read():
                        nodisplay = pkg
            if not onedesktop and num == 1:
                onedesktop = pkg
            elif not multidesktop and num > 1:
                multidesktop = pkg

            if onedesktop and multidesktop and nodisplay:
                break

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
            tr = [r for r in self._create_reports(True) if not 'inaccessible' in r]
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
            tr = [r for r in self._create_reports(True) if not 'inaccessible' in r]
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
            tr = [r for r in self._create_reports(True) if not 'inaccessible' in r]
            self.assertEqual(set(apport.fileutils.get_all_system_reports()), set([]))
            self.assertEqual(set(apport.fileutils.get_new_system_reports()), set([]))

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

    def test_make_report_path(self):
        '''make_report_path()'''

        pr = problem_report.ProblemReport()
        self.assertRaises(ValueError, apport.fileutils.make_report_path, pr)

        pr['Package'] = 'bash 1'
        self.assertTrue(apport.fileutils.make_report_path(pr).startswith('%s/bash' % apport.fileutils.report_dir))
        pr['ExecutablePath'] = '/bin/bash'
        self.assertTrue(apport.fileutils.make_report_path(pr).startswith('%s/_bin_bash' % apport.fileutils.report_dir))

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

if __name__ == '__main__':
    unittest.main()
