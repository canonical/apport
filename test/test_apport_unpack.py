'''Test apport-unpack'''

# Copyright (C) 2012 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import unittest, subprocess, tempfile, shutil, os, os.path
import problem_report


class T(unittest.TestCase):
    @classmethod
    def setUpClass(klass):
        klass.workdir = tempfile.mkdtemp()

        # create problem report file with all possible data types
        r = problem_report.ProblemReport()
        klass.utf8_str = b'a\xe2\x99\xa5b'
        klass.bindata = b'\x00\x01\xFF\x40'
        r['utf8'] = klass.utf8_str
        r['unicode'] = klass.utf8_str.decode('UTF-8')
        r['binary'] = klass.bindata
        r['compressed'] = problem_report.CompressedValue(b'FooFoo!')

        klass.report_file = os.path.join(klass.workdir, 'test.apport')
        with open(klass.report_file, 'wb') as f:
            r.write(f)

        klass.unpack_dir = os.path.join(klass.workdir, 'un pack')

    @classmethod
    def tearDownClass(klass):
        shutil.rmtree(klass.workdir)

    def tearDown(self):
        if os.path.isdir(self.unpack_dir):
            shutil.rmtree(self.unpack_dir)

    def test_unpack(self):
        '''apport-unpack for all possible data types'''

        self.assertEqual(self._call(['apport-unpack', self.report_file, self.unpack_dir]),
                (0, '', ''))

        self.assertEqual(self._get_unpack('utf8'), self.utf8_str)
        self.assertEqual(self._get_unpack('unicode'), self.utf8_str)
        self.assertEqual(self._get_unpack('binary'), self.bindata)
        self.assertEqual(self._get_unpack('compressed'), b'FooFoo!')

    def test_unpack_python(self):
        '''apport-unpack with explicity Python interpreter

        This will catch Python 2/3 specific errors when running the tests with
        a different $PYTHON than apport-unpacks' hashbang.
        '''
        bindir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'bin')

        self.assertEqual(self._call([os.getenv('PYTHON', 'python3'),
                                     os.path.join(bindir, 'apport-unpack'),
                                     self.report_file,
                                     self.unpack_dir]),
                         (0, '', ''))

        self.assertEqual(self._get_unpack('utf8'), self.utf8_str)
        self.assertEqual(self._get_unpack('unicode'), self.utf8_str)
        self.assertEqual(self._get_unpack('binary'), self.bindata)
        self.assertEqual(self._get_unpack('compressed'), b'FooFoo!')

    def test_help(self):
        '''calling apport-unpack with help'''

        (ret, out, err) = self._call(['apport-unpack', '--help'])
        self.assertEqual(ret, 0)
        self.assertEqual(err, '')
        self.assertTrue(out.startswith('Usage:'))

    def test_error(self):
        '''calling apport-unpack with wrong arguments'''

        (ret, out, err) = self._call(['apport-unpack'])
        self.assertEqual(ret, 1)
        self.assertEqual(err, '')
        self.assertTrue(out.startswith('Usage:'))

        (ret, out, err) = self._call(['apport-unpack', self.report_file])
        self.assertEqual(ret, 1)
        self.assertEqual(err, '')
        self.assertTrue(out.startswith('Usage:'))

        (ret, out, err) = self._call(['apport-unpack', '/nonexisting.crash', self.unpack_dir])
        self.assertEqual(ret, 1)
        self.assertTrue('/nonexisting.crash' in err)
        self.assertEqual(out, '')

    def _call(self, argv):
        a = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, err) = a.communicate()
        return (a.returncode, out.decode('UTF-8'), err.decode('UTF-8'))

    def _get_unpack(self, fname):
        with open(os.path.join(self.unpack_dir, fname), 'rb') as f:
            return f.read()

unittest.main()
