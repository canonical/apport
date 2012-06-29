'''Test crash-digger'''

# Copyright (C) 2007 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import unittest, subprocess, tempfile, os, shutil, os.path

import apport.fileutils


class T(unittest.TestCase):
    def setUp(self):
        '''Set up dummy config dir, crashdb.conf, and apport-retrace'''

        self.workdir = tempfile.mkdtemp()

        crashdb_conf = os.path.join(self.workdir, 'crashdb.conf')
        with open(crashdb_conf, 'w') as f:
            f.write('''default = 'memory'
databases = {
    'memory': {'impl': 'memory', 'distro': 'Testux', 'dummy_data': '1',
               'dupdb_url': '%s'},
    'empty': {'impl': 'memory', 'distro': 'Foonux'},
}''' % os.path.join(self.workdir, 'dupdb'))

        self.config_dir = os.path.join(self.workdir, 'config')
        os.mkdir(self.config_dir)
        os.mkdir(os.path.join(self.config_dir, 'Testux 1.0'))
        os.mkdir(os.path.join(self.config_dir, 'Testux 2.2'))

        self.apport_retrace_log = os.path.join(self.workdir, 'apport-retrace.log')

        self.apport_retrace = os.path.join(self.workdir, 'apport-retrace')
        with open(self.apport_retrace, 'w') as f:
            f.write('''#!/bin/sh
echo "$@" >> %s''' % self.apport_retrace_log)
        os.chmod(self.apport_retrace, 0o755)

        self.lock_file = os.path.join(self.workdir, 'lock')

        os.environ['APPORT_CRASHDB_CONF'] = crashdb_conf
        os.environ['PYTHONPATH'] = '.'

        self.orig_report_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = os.path.join(self.workdir, 'crashes')
        os.mkdir(apport.fileutils.report_dir)
        os.environ['APPORT_REPORT_DIR'] = apport.fileutils.report_dir

    def tearDown(self):
        shutil.rmtree(self.workdir)
        apport.fileutils.report_dir = self.orig_report_dir

    def call(self, args):
        '''Call crash-digger with given arguments.

        Return a pair (stdout, stderr).
        '''
        s = subprocess.Popen(['crash-digger', '--apport-retrace',
                              self.apport_retrace] + args, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (out, err) = s.communicate()
        return (out.decode('UTF-8'), err.decode('UTF-8'))

    def test_crashes(self):
        '''Crash retracing'''

        (out, err) = self.call(['-c', self.config_dir, '-a', '/dev/zero', '-d',
                                os.path.join(self.workdir, 'dup.db'), '-vl', self.lock_file])
        self.assertEqual(err, '', 'no error messages:\n' + err)
        self.assertTrue("Available releases: ['Testux 1.0', 'Testux 2.2']" in out)
        self.assertTrue('retracing #0' in out)
        self.assertTrue('retracing #1' in out)
        self.assertTrue('retracing #2' in out)
        self.assertTrue('crash is release FooLinux Pi/2 which does not have a config available' in out)
        self.assertFalse('failed with status' in out)
        self.assertFalse('#3' in out, 'dupcheck crashes are not retraced')
        self.assertFalse('#4' in out, 'dupcheck crashes are not retraced')

        with open(self.apport_retrace_log) as f:
            retrace_log = f.read()
        self.assertEqual(len(retrace_log.splitlines()), 2)
        self.assertFalse('dup.db -v 0\n' in retrace_log)
        self.assertTrue('dup.db -v 1\n' in retrace_log)
        self.assertTrue('dup.db -v 2\n' in retrace_log)
        self.assertFalse(os.path.exists(self.lock_file))

        self.assertFalse(os.path.isdir(os.path.join(self.workdir, 'dupdb', 'sig')))

    def test_crashes_error(self):
        '''Crash retracing if apport-retrace fails on bug #1'''

        # make apport-retrace fail on bug 1
        os.rename(self.apport_retrace, self.apport_retrace + '.bak')
        with open(self.apport_retrace, 'w') as f:
            f.write('''#!/bin/sh
echo "$@" >> %s
while [ -n "$2" ]; do shift; done
if [ "$1" = 1 ]; then
    echo "cannot frobnicate bug" >&2
    exit 1
fi
''' % self.apport_retrace_log)
        os.chmod(self.apport_retrace, 0o755)

        (out, err) = self.call(['-c', self.config_dir, '-a', '/dev/zero', '-d',
                                os.path.join(self.workdir, 'dup.db'), '-vl', self.lock_file])
        self.assertTrue('Traceback' in err)
        self.assertTrue('SystemError: retracing #1 failed' in err)
        self.assertTrue("Available releases: ['Testux 1.0', 'Testux 2.2']" in out)
        self.assertTrue('retracing #0' in out)
        self.assertTrue('retracing #1' in out)
        self.assertFalse('retracing #2' in out, 'should not continue after errors')
        self.assertTrue('crash is release FooLinux Pi/2 which does not have a config available' in out)
        self.assertFalse('#0 failed with status' in out)
        self.assertTrue('#1 failed with status: 1' in out)
        self.assertFalse('#3' in out, 'dupcheck crashes are not retraced')
        self.assertFalse('#4' in out, 'dupcheck crashes are not retraced')

        with open(self.apport_retrace_log) as f:
            retrace_log = f.read()
        self.assertEqual(len(retrace_log.splitlines()), 1)
        self.assertFalse('dup.db -v 0\n' in retrace_log)
        self.assertTrue('dup.db -v 1\n' in retrace_log)
        # stops after failing #1
        self.assertFalse('dup.db -v 2\n' in retrace_log)
        self.assertTrue(os.path.exists(self.lock_file))

        os.rename(self.apport_retrace + '.bak', self.apport_retrace)

        # subsequent start should not do anything until the lock file is cleaned up
        (out, err) = self.call(['-c', self.config_dir, '-a', '/dev/zero', '-d',
                                os.path.join(self.workdir, 'dup.db'), '-vl', self.lock_file])
        self.assertEqual(out, '')
        self.assertEqual(err, '')

        os.unlink(self.lock_file)

        # now it should run again
        (out, err) = self.call(['-c', self.config_dir, '-a', '/dev/zero', '-d',
                                os.path.join(self.workdir, 'dup.db'), '-vl', self.lock_file])
        self.assertTrue('retracing #2' in out)
        self.assertEqual(err, '', 'no error messages:\n' + err)
        self.assertFalse(os.path.exists(self.lock_file))

    def test_crashes_transient_error(self):
        '''Crash retracing if apport-retrace reports a transient error'''

        # make apport-retrace fail on bug 1
        os.rename(self.apport_retrace, self.apport_retrace + '.bak')
        with open(self.apport_retrace, 'w') as f:
            f.write('''#!/bin/sh
echo "$@" >> %s
while [ -n "$2" ]; do shift; done
if [ "$1" = 1 ]; then
    echo "cannot frobnicate crash db" >&2
    exit 99
fi
''' % self.apport_retrace_log)
        os.chmod(self.apport_retrace, 0o755)

        (out, err) = self.call(['-c', self.config_dir, '-a', '/dev/zero', '-d',
                                os.path.join(self.workdir, 'dup.db'), '-vl', self.lock_file])
        self.assertTrue("Available releases: ['Testux 1.0', 'Testux 2.2']" in out)
        self.assertTrue('retracing #0' in out)
        self.assertTrue('retracing #1' in out)
        self.assertFalse('retracing #2' in out, 'should not continue after errors')
        self.assertTrue('transient error reported; halting' in out)

        with open(self.apport_retrace_log) as f:
            retrace_log = f.read()
        self.assertTrue('dup.db -v 1\n' in retrace_log)
        # stops after failing #1
        self.assertFalse('dup.db -v 2\n' in retrace_log)

        self.assertFalse(os.path.exists(self.lock_file))

    def test_dupcheck(self):
        '''Duplicate checking'''

        (out, err) = self.call(['-a', '/dev/zero', '-d',
                                os.path.join(self.workdir, 'dup.db'), '-vDl', self.lock_file])
        self.assertEqual(err, '', 'no error messages:\n' + err)
        self.assertFalse('#1' in out, 'signal crashes are not retraced')
        self.assertFalse('#2' in out, 'signal crashes are not retraced')
        self.assertTrue('checking #3 for duplicate' in out)
        self.assertTrue('checking #4 for duplicate' in out)
        self.assertTrue('Report is a duplicate of #3 (not fixed yet)' in out)
        self.assertFalse(os.path.exists(self.apport_retrace_log))
        self.assertFalse(os.path.exists(self.lock_file))

    def test_stderr_redirection(self):
        '''apport-retrace's stderr is redirected to stdout'''

        with open(self.apport_retrace, 'w') as f:
            f.write('''#!/bin/sh
echo ApportRetraceError >&2''')
        (out, err) = self.call(['-c', self.config_dir, '-a', '/dev/zero', '-d',
                                os.path.join(self.workdir, 'dup.db'), '-vl', self.lock_file])
        self.assertEqual(err, '', 'no error messages:\n' + err)
        self.assertTrue('ApportRetraceError' in out)

    def test_publish_db(self):
        '''Duplicate database publishing'''

        (out, err) = self.call(['-c', self.config_dir, '-a', '/dev/zero', '-d',
                                os.path.join(self.workdir, 'dup.db'), '-vl', self.lock_file,
                                '--publish-db', os.path.join(self.workdir, 'dupdb')])
        self.assertEqual(err, '', 'no error messages:\n' + err)
        self.assertTrue('retracing #0' in out)

        self.assertTrue(os.path.isdir(os.path.join(self.workdir, 'dupdb', 'sig')))

    def test_alternate_crashdb(self):
        '''Alternate crash database name'''

        # existing DB "empty" has no crashes
        (out, err) = self.call(['-c', self.config_dir, '-a', '/dev/zero',
                                '-vl', self.lock_file, '--crash-db', 'empty'])
        self.assertEqual(err, '', 'no error messages:\n' + err)
        self.assertFalse('retracing #' in out)
        self.assertFalse('crash is' in out)
        self.assertFalse('failed with status' in out)

        # nonexisting DB
        (out, err) = self.call(['-c', self.config_dir, '-a', '/dev/zero',
                                '-vl', self.lock_file, '--crash-db', 'nonexisting'])
        self.assertEqual(out, '', 'no output messages:\n' + out)
        self.assertFalse('Traceback' in err, err)
        self.assertTrue('nonexisting' in err, err)

unittest.main()
