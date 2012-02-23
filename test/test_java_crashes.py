# Copyright (C) 2010 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import tempfile, unittest, subprocess, sys, os, os.path, shutil

import apport, apport.fileutils

class T(unittest.TestCase):
    def setUp(self):
        self.srcdir = os.path.dirname(os.path.dirname(os.path.realpath(sys.argv[0])))
        self.orig_report_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = tempfile.mkdtemp()
        os.environ['APPORT_REPORT_DIR'] = apport.fileutils.report_dir
        os.environ['APPORT_JAVA_EXCEPTION_HANDLER'] = os.path.join(
                os.environ.get('APPORT_DATA_DIR','/usr/share/apport'),
                'java_uncaught_exception')
        self.apport_jar_path = os.path.join(self.srcdir, 'java', 'apport.jar')

    def tearDown(self):
        shutil.rmtree(apport.fileutils.report_dir)
        apport.fileutils.report_dir = self.orig_report_dir

    def test_crash_class(self):
        '''Crash in a .class file'''

        p = subprocess.Popen(['java', '-classpath',
            self.apport_jar_path + ':' + os.path.join(self.srcdir, 'java'), 'crash'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, err) = p.communicate()
        self.assertNotEqual(p.returncode, 0, 'crash must exit with nonzero code')
        self.assertTrue("Can't catch this" in err, 'crash handler must print original exception:\n' + err)

        self._check_crash_report('java/crash.class')

    def test_crash_jar(self):
        '''Crash in a .jar file'''

        p = subprocess.Popen(['java', '-classpath',
            self.apport_jar_path + ':' + os.path.join(self.srcdir, 'java', 'crash.jar'), 'crash'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, err) = p.communicate()
        self.assertNotEqual(p.returncode, 0, 'crash must exit with nonzero code')
        self.assertTrue("Can't catch this" in err, 'crash handler must print original exception:\n' + err)

        self._check_crash_report('java/crash.jar!/crash.class')

    def _check_crash_report(self, main_file):
        '''Check that we have one crash report, and verify its contents'''

        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 1, 'did not create a crash report')
        r = apport.Report()
        r.load(open(reports[0]))
        self.assertEqual(r['ProblemType'], 'Crash')
        self.assertTrue(r['ProcCmdline'].startswith('java -classpath'))
        self.assertTrue(r['StackTrace'].startswith(
            "java.lang.RuntimeException: Can't catch this"))
        if '.jar!' in main_file:
            self.assertEqual(r['MainClassUrl'], 'jar:file:%s/%s' % (self.srcdir, main_file))
        else:
            self.assertEqual(r['MainClassUrl'], 'file:%s/%s' % (self.srcdir, main_file))
        self.assertTrue('DistroRelease' in r)
        self.assertTrue('ProcCwd' in r)
            
#
# main
#

try:
    subprocess.check_call(['java', '-version'], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
except OSError:
    apport.warning('Java not available, skipping')
    sys.exit(0)

unittest.main()