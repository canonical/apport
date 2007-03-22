'''Python sys.excepthook hook to generate apport crash dumps.

See https://wiki.ubuntu.com/AutomatedProblemReports for details.

Copyright (c) 2006 Canonical Ltd.
Authors: Robert Collins <robert@ubuntu.com>
         Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import os
import sys

import report, fileutils

def apport_excepthook(exc_type, exc_obj, exc_tb):
    '''Catch an uncaught exception and make a traceback.'''

    # create and save a problem report. Note that exceptions in this code
    # are bad, and we probably need a per-thread reentrancy guard to 
    # prevent that happening. However, on Ubuntu there should never be
    # a reason for an exception here, other than [say] a read only var
    # or some such. So what we do is use a try - finally to ensure that
    # the original excepthook is invoked, and until we get bug reports 
    # ignore the other issues.

    # import locally here so that there is no routine overhead on python
    # startup time - only when a traceback occurs will this trigger.
    try:
        # ignore 'safe' exit types.
        if exc_type in (KeyboardInterrupt, ):
            return
        from cStringIO import StringIO
        import re, tempfile, traceback

        pr = report.Report()
        # apport will look up the package from the executable path.
        # if the module has mutated this, we're sunk, but it does not exist yet :(.
        binary = os.path.realpath(os.path.join(os.getcwdu(), sys.argv[0]))
        # for interactive python sessions, sys.argv[0] == ''; catch that and
        # other irregularities
        if not os.access(binary, os.X_OK) or not os.path.isfile(binary):
            return
        # append a basic traceback. In future we may want to include
        # additional data such as the local variables, loaded modules etc.
        tb_file = StringIO()
        traceback.print_exception(exc_type, exc_obj, exc_tb, file=tb_file)
        pr['Traceback'] = tb_file.getvalue().strip()
        pr.add_proc_info()
        # override the ExecutablePath with the script that was actually running.
        pr['ExecutablePath'] = binary
        pr['PythonArgs'] = '%r' % sys.argv
        # filter out binaries in user accessible paths
        if not fileutils.likely_packaged(binary):
            return
        if pr.check_ignored():
            return
        mangled_program = re.sub('/', '_', binary)
        # get the uid for now, user name later
        user = os.getuid()
        pr_filename = '/var/crash/%s.%i.crash' % (mangled_program, user)
        report_file = open(pr_filename, 'wt')
        os.chmod(pr_filename, 0600)
        try:
            pr.write(report_file)
        finally:
            report_file.close()

    finally:
        # resume original processing to get the default behaviour.
        sys.__excepthook__(exc_type, exc_obj, exc_tb)


def install():
    '''Install the python apport hook.'''

    sys.excepthook = apport_excepthook

#
# Unit test
#

if __name__ == '__main__':
    import unittest, tempfile, subprocess, os.path, stat
    import fileutils, problem_report

    class _PythonHookTest(unittest.TestCase):
        def test_env(self):
            '''Check the test environment.'''

            self.assertEqual(fileutils.get_all_reports(), [], 
                'No crash reports already present')

        def test_general(self):
            '''Test general operation of the Python crash hook.'''

            # put the script into /var/crash, since that isn't ignored in the
            # hook
            (fd, script) = tempfile.mkstemp(dir=fileutils.report_dir)
            try:
                os.write(fd, '''#!/usr/bin/python
def func(x):
    raise Exception, 'This should happen.'

func(42)
''')
                os.close(fd)
                os.chmod(script, 0755)

                p = subprocess.Popen([script, 'testarg1', 'testarg2'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                err = p.communicate()[1]
                self.assertEqual(p.returncode, 1, 
                    'crashing test python program exits with failure code')
                self.assert_('Exception: This should happen.' in err)

            finally:
                os.unlink(script)

            # did we get a report?
            reports = fileutils.get_new_reports()
            pr = None
            try:
                self.assertEqual(len(reports), 1, 'crashed Python program produced a report')
                self.assertEqual(stat.S_IMODE(os.stat(reports[0]).st_mode),
                    0600, 'report has correct permissions')

                pr = problem_report.ProblemReport()
                pr.load(open(reports[0]))
            finally:
                for r in reports:
                    os.unlink(r)

            # check report contents
            expected_keys = ['InterpreterPath', 'ProcCwd', 'PythonArgs',
                'Traceback', 'ProblemType', 'ProcEnviron', 'ProcStatus',
                'ProcCmdline', 'Date', 'ExecutablePath', 'ProcMaps']
            self.assert_(set(expected_keys).issubset(set(pr.keys())), 
                'report has necessary fields')
            self.assert_('bin/python' in pr['InterpreterPath'])
            self.assertEqual(pr['ExecutablePath'], script)
            self.assertEqual(pr['PythonArgs'], "['%s', 'testarg1', 'testarg2']" % script)
            self.assert_(pr['Traceback'].startswith('Traceback'))
            self.assert_("func\n    raise Exception, 'This should happen." in pr['Traceback'])

        def _assert_no_reports(self):
            '''Assert that there are no crash reports.'''

            reports = fileutils.get_new_reports()
            try:
                self.assertEqual(len(reports), 0, 
                    'no crash reports present (cwd: %s)' % os.getcwd())
            finally:
                # clean up in case we fail
                for r in reports:
                    pass
                    #os.unlink(r)

        def test_interactive(self):
            '''Test that interactive Python sessions never generate a report.'''

            orig_cwd = os.getcwd()
            try:
                for d in ('/tmp', '/usr/local', '/usr'):
                    os.chdir(d)
                    p = subprocess.Popen(['python'], stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    (out, err) = p.communicate('raise ValueError')
                    assert p.returncode != 0
                    assert out == ''
                    assert 'ValueError' in err
                    self._assert_no_reports()
            finally:
                os.chdir(orig_cwd)

        def test_ignoring(self):
            '''Test that the Python crash hook respects the ignore list.'''

            # put the script into /var/crash, since that isn't ignored in the
            # hook
            (fd, script) = tempfile.mkstemp(dir=fileutils.report_dir)
            ifpath = os.path.expanduser(report._ignore_file)
            orig_ignore_file = None
            try:
                os.write(fd, '''#!/usr/bin/python
def func(x):
    raise Exception, 'This should happen.'

func(42)
''')
                os.close(fd)
                os.chmod(script, 0755)

                # move aside current ignore file
                if os.path.exists(ifpath):
                    orig_ignore_file = ifpath + '.apporttest'
                    os.rename(ifpath, orig_ignore_file)

                # ignore
                r = report.Report()
                r['ExecutablePath'] = script
                r.mark_ignore()
                r = None

                p = subprocess.Popen([script, 'testarg1', 'testarg2'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                err = p.communicate()[1]
                self.assertEqual(p.returncode, 1, 
                    'crashing test python program exits with failure code')
                self.assert_('Exception: This should happen.' in err)

            finally:
                os.unlink(script)
                # clean up our ignore file
                if os.path.exists(ifpath):
                    os.unlink(ifpath)
                if orig_ignore_file:
                    os.rename(orig_ignore_file, ifpath)

            # did we get a report?
            reports = fileutils.get_new_reports()
            pr = None
            try:
                self.assertEqual(len(reports), 0)
            finally:
                for r in reports:
                    os.unlink(r)

    unittest.main()
