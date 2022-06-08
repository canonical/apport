# Copyright (C) 2010 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import tempfile, unittest, subprocess, os, os.path, shutil

import apport, apport.fileutils

from tests.paths import SRCDIR, get_data_directory, is_local_source_directory, local_test_environment


@unittest.skipIf(shutil.which('java') is None, 'Java not available')
class T(unittest.TestCase):
    def setUp(self):
        self.env = os.environ | local_test_environment()
        datadir = get_data_directory()
        self.orig_report_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = tempfile.mkdtemp()
        self.env['APPORT_REPORT_DIR'] = apport.fileutils.report_dir
        self.env['APPORT_JAVA_EXCEPTION_HANDLER'] = os.path.join(
            datadir, 'java_uncaught_exception')
        if is_local_source_directory():
            self.crash_jar_path = os.path.join(SRCDIR, 'java', 'crash.jar')
            self.apport_jar_path = os.path.join(SRCDIR, 'java', 'apport.jar')
        else:
            self.crash_jar_path = os.path.join(datadir, 'testsuite', 'crash.jar')
            self.apport_jar_path = os.path.join(datadir, 'apport.jar')
        if not os.path.exists(self.apport_jar_path):
            self.skipTest(f"{self.apport_jar_path} missing")

    def tearDown(self):
        shutil.rmtree(apport.fileutils.report_dir)
        apport.fileutils.report_dir = self.orig_report_dir

    def test_crash_class(self):
        '''Crash in a .class file'''

        crash_class = os.path.dirname(self.crash_jar_path) + '/crash.class'
        if not os.path.exists(crash_class):
            self.skipTest(f"{crash_class} missing")
        p = subprocess.Popen(['java', '-classpath',
                              self.apport_jar_path + ':' + os.path.dirname(self.crash_jar_path), 'crash'],
                             env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, err) = p.communicate()
        self.assertNotEqual(p.returncode, 0, 'crash must exit with nonzero code')
        self.assertTrue(b"Can't catch this" in err,
                        'crash handler must print original exception:\n' + err.decode())

        self._check_crash_report(crash_class)

    def test_crash_jar(self):
        '''Crash in a .jar file'''

        if not os.path.exists(self.crash_jar_path):
            self.skipTest(f"{self.crash_jar_path} missing")
        p = subprocess.Popen(['java', '-classpath',
                              self.apport_jar_path + ':' + self.crash_jar_path, 'crash'],
                             env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, err) = p.communicate()
        self.assertNotEqual(p.returncode, 0, 'crash must exit with nonzero code')
        self.assertTrue(b"Can't catch this" in err,
                        'crash handler must print original exception:\n' + err.decode())

        self._check_crash_report(self.crash_jar_path + '!/crash.class')

    def _check_crash_report(self, main_file):
        '''Check that we have one crash report, and verify its contents'''

        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 1, 'did not create a crash report')
        r = apport.Report()
        with open(reports[0], 'rb') as f:
            r.load(f)
        self.assertEqual(r['ProblemType'], 'Crash')
        self.assertTrue(r['ProcCmdline'].startswith('java -classpath'), r)
        self.assertTrue(r['StackTrace'].startswith(
            "java.lang.RuntimeException: Can't catch this"))
        if '.jar!' in main_file:
            self.assertEqual(r['MainClassUrl'], 'jar:file:' + main_file)
        else:
            self.assertEqual(r['MainClassUrl'], 'file:' + main_file)
        self.assertTrue('DistroRelease' in r)
        self.assertTrue('ProcCwd' in r)
