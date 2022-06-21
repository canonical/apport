# Test apport_python_hook.py
#
# Copyright (c) 2006 - 2011 Canonical Ltd.
# Authors: Robert Collins <robert@ubuntu.com>
#          Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import atexit
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
import unittest.mock

import apport.fileutils
import apport.report
from tests.paths import local_test_environment


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = os.environ | local_test_environment()
        cls.orig_report_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = tempfile.mkdtemp()
        cls.env['APPORT_REPORT_DIR'] = apport.fileutils.report_dir
        atexit.register(shutil.rmtree, apport.fileutils.report_dir)

    @classmethod
    def tearDownClass(cls):
        apport.fileutils.report_dir = cls.orig_report_dir

    def tearDown(self):
        for f in apport.fileutils.get_all_reports():
            os.unlink(f)

    def _test_crash(self, extracode='', scriptname=None):
        '''Create a test crash.'''

        # put the script into /var/tmp, since that isn't ignored in the
        # hook
        if scriptname:
            script = scriptname
            fd = os.open(scriptname, os.O_CREAT | os.O_WRONLY)
        else:
            (fd, script) = tempfile.mkstemp(dir='/var/tmp')
            self.addCleanup(os.unlink, script)

        os.write(
            fd,
            f'''\
#!/usr/bin/env {os.getenv('PYTHON', 'python3')}
import apport_python_hook
apport_python_hook.install()

def func(x):
    raise Exception(b'This should happen. \\xe2\\x99\\xa5'.decode('UTF-8'))

{extracode}
func(42)
'''.encode())
        os.close(fd)
        os.chmod(script, 0o755)
        env = self.env.copy()
        env['PYTHONPATH'] = f"{env.get('PYTHONPATH', '.')}:/my/bogus/path"

        p = subprocess.Popen([script, 'testarg1', 'testarg2'],
                             stderr=subprocess.PIPE, env=env)
        err = p.communicate()[1].decode()
        self.assertEqual(p.returncode, 1,
                         'crashing test python program exits with failure code')
        if not extracode:
            self.assertIn('This should happen.', err)
        self.assertNotIn('IOError', err)

        return script

    def test_general(self):
        '''general operation of the Python crash hook.'''

        script = self._test_crash()

        # did we get a report?
        reports = apport.fileutils.get_new_reports()
        pr = None
        self.assertEqual(len(reports), 1, 'crashed Python program produced a report')
        self.assertEqual(stat.S_IMODE(os.stat(reports[0]).st_mode),
                         0o640, 'report has correct permissions')

        pr = apport.report.Report()
        with open(reports[0], 'rb') as f:
            pr.load(f)

        # check report contents
        expected_keys = ['InterpreterPath', 'PythonArgs', 'Traceback',
                         'ProblemType', 'ProcEnviron', 'ProcStatus',
                         'ProcCmdline', 'Date', 'ExecutablePath', 'ProcMaps',
                         'UserGroups']
        self.assertTrue(set(expected_keys).issubset(set(pr.keys())),
                        'report has necessary fields')
        self.assertIn('bin/python', pr['InterpreterPath'])
        self.assertEqual(pr['ExecutablePath'], script)
        self.assertEqual(pr['ExecutableTimestamp'],
                         str(int(os.stat(script).st_mtime)))
        self.assertEqual(pr['PythonArgs'], "['%s', 'testarg1', 'testarg2']" % script)
        self.assertTrue(pr['Traceback'].startswith('Traceback'))
        self.assertIn("func\n    raise Exception(b'This should happen.", pr['Traceback'])

    def test_existing(self):
        '''Python crash hook overwrites seen existing files.'''

        script = self._test_crash()

        # did we get a report?
        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 1, 'crashed Python program produced a report')
        self.assertEqual(stat.S_IMODE(os.stat(reports[0]).st_mode),
                         0o640, 'report has correct permissions')

        # touch report -> "seen" case
        apport.fileutils.mark_report_seen(reports[0])

        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 0)

        script = self._test_crash(scriptname=script)
        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 1)

        # "unseen" case
        script = self._test_crash(scriptname=script)
        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 1)

    def test_symlink(self):
        '''Python crash of a symlinked program resolves to target'''

        script = self._test_crash()

        # load report for this
        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 1, 'crashed Python program produced a report')
        pr1 = apport.Report()
        with open(reports[0], 'rb') as f:
            pr1.load(f)
        for f in apport.fileutils.get_all_reports():
            os.unlink(f)

        script_link = os.path.join(os.path.dirname(script), 'script-link')
        os.symlink(os.path.basename(script), script_link)
        self.addCleanup(os.unlink, script_link)

        # run script through symlink name
        p = subprocess.Popen([script_link], env=self.env, stderr=subprocess.PIPE)
        err = p.communicate()[1].decode()
        self.assertEqual(p.returncode, 1,
                         'crashing test python program exits with failure code')
        self.assertIn('This should happen.', err)

        # get report for symlinked crash
        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 1, 'crashed Python program produced a report')
        pr2 = apport.Report()
        with open(reports[0], 'rb') as f:
            pr2.load(f)

        # check report contents
        self.assertIn('bin/python', pr2['InterpreterPath'])
        self.assertEqual(pr1['ExecutablePath'], script)
        self.assertEqual(pr2['ExecutablePath'], script)
        self.assertEqual(pr1.crash_signature(), pr2.crash_signature())

    def test_no_argv(self):
        '''with zapped sys.argv.'''

        self._test_crash('import sys\nsys.argv = None')

        # did we get a report?
        reports = apport.fileutils.get_new_reports()
        pr = None
        self.assertEqual(len(reports), 1, 'crashed Python program produced a report')
        self.assertEqual(stat.S_IMODE(os.stat(reports[0]).st_mode),
                         0o640, 'report has correct permissions')

        pr = apport.report.Report()
        with open(reports[0], 'rb') as f:
            pr.load(f)

        # check report contents
        expected_keys = ['InterpreterPath', 'Traceback', 'ProblemType',
                         'ProcEnviron', 'ProcStatus', 'ProcCmdline', 'Date',
                         'ExecutablePath', 'ProcMaps', 'UserGroups']
        self.assertTrue(set(expected_keys).issubset(set(pr.keys())),
                        'report has necessary fields')
        self.assertIn('bin/python', pr['InterpreterPath'])
        # we have no actual executable, so we should fall back to the
        # interpreter
        self.assertEqual(pr['ExecutablePath'], pr['InterpreterPath'])
        if 'ExecutableTimestamp' in pr:
            self.assertEqual(pr['ExecutableTimestamp'],
                             str(int(os.stat(pr['ExecutablePath']).st_mtime)))
        self.assertTrue(pr['Traceback'].startswith('Traceback'))

    def test_python_env(self):
        '''Python environmental variables appear in report'''

        self._test_crash()

        # did we get a report?
        reports = apport.fileutils.get_new_reports()
        pr = None
        self.assertEqual(len(reports), 1, 'crashed Python program produced a report')

        pr = apport.report.Report()
        with open(reports[0], 'rb') as f:
            pr.load(f)

        # check report contents
        self.assertIn('PYTHONPATH', pr['ProcEnviron'])
        self.assertIn('/my/bogus/path', pr['ProcEnviron'])

    def _assert_no_reports(self):
        '''Assert that there are no crash reports.'''

        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 0,
                         'no crash reports present (cwd: %s)' % os.getcwd())

    def test_interactive(self):
        '''interactive Python sessions never generate a report.'''

        orig_cwd = os.getcwd()
        try:
            for d in ('/tmp', '/usr/local', '/usr'):
                os.chdir(d)
                p = subprocess.Popen(['python3'], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                (out, err) = p.communicate(b'raise ValueError')
                out = out.decode()
                err = err.decode()
                assert p.returncode != 0
                assert out == ''
                assert 'ValueError' in err
                self._assert_no_reports()
        finally:
            os.chdir(orig_cwd)

    def test_ignoring(self):
        '''the Python crash hook respects the ignore list.'''

        # put the script into /var/tmp, since that isn't ignored in the
        # hook
        (fd, script) = tempfile.mkstemp(dir='/var/tmp')
        try:
            with tempfile.NamedTemporaryFile() as ignore_file, unittest.mock.patch("apport.report._ignore_file", ignore_file.name):
                os.write(
                    fd,
                    textwrap.dedent(
                        f'''\
                        #!/usr/bin/env {os.getenv('PYTHON', 'python3')}
                        import apport_python_hook
                        apport_python_hook.install()

                        # Inject the mocked ignore file path.
                        import apport.report
                        apport.report._ignore_file = "{ignore_file.name}"

                        def func(x):
                            raise Exception('This should happen.')

                        func(42)
                        '''
                    ).encode('ascii'),
                )
                os.close(fd)
                os.chmod(script, 0o755)

                # ignore
                r = apport.report.Report()
                r['ExecutablePath'] = script
                r.mark_ignore()
                r = None

                p = subprocess.Popen([script, 'testarg1', 'testarg2'], env=self.env,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                err = p.communicate()[1].decode()
                self.assertEqual(p.returncode, 1,
                                 'crashing test python program exits with failure code')
                self.assertIn('Exception: This should happen.', err)

        finally:
            os.unlink(script)

        # did we get a report?
        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 0)

    def test_no_flooding(self):
        '''limit successive reports'''

        count = 0
        limit = 5
        try:
            while count < limit:
                self._test_crash(scriptname='/var/tmp/pytestcrash')
                reports = apport.fileutils.get_new_reports()
                if not reports:
                    break
                self.assertEqual(len(reports), 1, 'crashed Python program produced one report')
                apport.fileutils.mark_report_seen(reports[0])
                count += 1
        finally:
            os.unlink('/var/tmp/pytestcrash')

        self.assertGreater(count, 1)
        self.assertLess(count, limit)

    def test_generic_os_error(self):
        '''OSError with errno and no known subclass'''

        self._test_crash(
            extracode=textwrap.dedent(
                '''\
                def g():
                    raise OSError(99, 'something bad')

                g()
                '''
            )
        )
        pr = self._load_report()
        # we expect it to append errno
        exe = pr['ExecutablePath']
        self.assertEqual(pr.crash_signature(),
                         '%s:OSError(99):%s@11:g' % (exe, exe))

    def test_generic_os_error_no_errno(self):
        '''OSError without errno and no known subclass'''

        self._test_crash(
            extracode=textwrap.dedent(
                '''\
                def g():
                    raise OSError('something bad')

                g()
                '''
            )
        )
        pr = self._load_report()
        # we expect it to not stumble over the missing errno
        exe = pr['ExecutablePath']
        self.assertEqual(pr.crash_signature(),
                         '%s:OSError:%s@11:g' % (exe, exe))

    def test_subclassed_os_error(self):
        '''OSError with known subclass'''

        self._test_crash(
            extracode=textwrap.dedent(
                '''\
                def g():
                    raise OSError(2, 'no such file /notexisting')

                g()
                '''
            )
        )
        pr = self._load_report()
        # we expect it to not append errno, as it's already encoded in the subclass
        exe = pr['ExecutablePath']
        self.assertEqual(pr.crash_signature(),
                         '%s:FileNotFoundError:%s@11:g' % (exe, exe))

    def _load_report(self):
        '''Ensure that there is exactly one crash report and load it'''

        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 1, 'crashed Python program produced a report')
        pr = apport.Report()
        with open(reports[0], 'rb') as f:
            pr.load(f)
        return pr
