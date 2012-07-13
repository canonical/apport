'''Test recoverable_problem'''

# Copyright (C) 2012 Canonical Ltd.
# Author: Evan Dandrea <ev@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import unittest
import sys
import os
import subprocess
import tempfile
import time
import shutil
import apport.report


class T(unittest.TestCase):
    def setUp(self):
        self.report_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.report_dir)
        os.environ['APPORT_REPORT_DIR'] = self.report_dir
        self.datadir = os.environ.get('APPORT_DATA_DIR', '/usr/share/apport')

    def wait_for_report(self):
        cwd = os.getcwd().replace('/', '_')
        base = sys.argv[0]
        if base.startswith('./'):
            base = base[2:]
        base = base.replace('/', '_')
        path = '%s_%s.%d.crash' % (cwd, base, os.getuid())
        path = os.path.join(self.report_dir, path)
        seconds = 0
        while not os.path.exists(path):
            time.sleep(1)
            seconds += 1
            self.assertTrue(seconds < 10, 'timeout while waiting for %s to be created.' % path)
        return path

    def call_recoverable_problem(self, data):
        cmd = ['%s/recoverable_problem' % self.datadir]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        err = proc.communicate(data.encode('UTF-8'))[1]
        if proc.returncode != 0:
            self.assertNotEqual(err, b'')  # we expect some error message
            raise subprocess.CalledProcessError(proc.returncode, cmd[0])
        self.assertEqual(err, b'')

    def test_recoverable_problem(self):
        '''recoverable_problem with valid data'''

        self.call_recoverable_problem('hello\0there')
        path = self.wait_for_report()
        with open(path, 'rb') as report_path:
            report = apport.report.Report()
            report.load(report_path)
            self.assertEqual(report['hello'], 'there')
            self.assertTrue('Pid:\t%d' % os.getpid() in report['ProcStatus'])

    def test_invalid_data(self):
        '''recoverable_problem with invalid data'''

        self.assertRaises(subprocess.CalledProcessError,
                          self.call_recoverable_problem, 'hello')

        self.assertRaises(subprocess.CalledProcessError,
                          self.call_recoverable_problem,
                          'hello\0there\0extraneous')

        self.assertRaises(subprocess.CalledProcessError,
                          self.call_recoverable_problem,
                          'hello\0\0there')


unittest.main()
