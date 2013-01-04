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

import unittest, tempfile, subprocess, os, stat, shutil, atexit
import dbus

temp_report_dir = tempfile.mkdtemp()
os.environ['APPORT_REPORT_DIR'] = temp_report_dir
atexit.register(shutil.rmtree, temp_report_dir)

import apport.fileutils, problem_report


class T(unittest.TestCase):
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

        os.write(fd, ('''#!/usr/bin/env %s
import apport_python_hook
apport_python_hook.install()

def func(x):
    raise Exception(b'This should happen. \\xe2\\x99\\xa5'.decode('UTF-8'))

%s
func(42)
''' % (os.getenv('PYTHON', 'python3'), extracode)).encode())
        os.close(fd)
        os.chmod(script, 0o755)
        env = os.environ.copy()
        env['PYTHONPATH'] = '/my/bogus/path'

        p = subprocess.Popen([script, 'testarg1', 'testarg2'],
                             stderr=subprocess.PIPE, env=env)
        err = p.communicate()[1].decode()
        self.assertEqual(p.returncode, 1,
                         'crashing test python program exits with failure code')
        if not extracode:
            self.assertTrue('This should happen.' in err, err)
        self.assertFalse('OSError' in err, err)

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

        pr = problem_report.ProblemReport()
        with open(reports[0], 'rb') as f:
            pr.load(f)

        # check report contents
        expected_keys = ['InterpreterPath', 'PythonArgs', 'Traceback',
                         'ProblemType', 'ProcEnviron', 'ProcStatus',
                         'ProcCmdline', 'Date', 'ExecutablePath', 'ProcMaps',
                         'UserGroups']
        self.assertTrue(set(expected_keys).issubset(set(pr.keys())),
                        'report has necessary fields')
        self.assertTrue('bin/python' in pr['InterpreterPath'])
        self.assertEqual(pr['ExecutablePath'], script)
        self.assertEqual(pr['ExecutableTimestamp'],
                         str(int(os.stat(script).st_mtime)))
        self.assertEqual(pr['PythonArgs'], "['%s', 'testarg1', 'testarg2']" % script)
        self.assertTrue(pr['Traceback'].startswith('Traceback'))
        self.assertTrue("func\n    raise Exception(b'This should happen." in
                        pr['Traceback'], pr['Traceback'])

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

    def test_no_argv(self):
        '''with zapped sys.argv.'''

        self._test_crash('import sys\nsys.argv = None')

        # did we get a report?
        reports = apport.fileutils.get_new_reports()
        pr = None
        self.assertEqual(len(reports), 1, 'crashed Python program produced a report')
        self.assertEqual(stat.S_IMODE(os.stat(reports[0]).st_mode),
                         0o640, 'report has correct permissions')

        pr = problem_report.ProblemReport()
        with open(reports[0], 'rb') as f:
            pr.load(f)

        # check report contents
        expected_keys = ['InterpreterPath', 'Traceback', 'ProblemType',
                         'ProcEnviron', 'ProcStatus', 'ProcCmdline', 'Date',
                         'ExecutablePath', 'ProcMaps', 'UserGroups']
        self.assertTrue(set(expected_keys).issubset(set(pr.keys())),
                        'report has necessary fields')
        self.assertTrue('bin/python' in pr['InterpreterPath'])
        self.assertTrue(pr['Traceback'].startswith('Traceback'))

    def test_python_env(self):
        '''Python environmental variables appear in report'''

        self._test_crash()

        # did we get a report?
        reports = apport.fileutils.get_new_reports()
        pr = None
        self.assertEqual(len(reports), 1, 'crashed Python program produced a report')

        pr = problem_report.ProblemReport()
        with open(reports[0], 'rb') as f:
            pr.load(f)

        # check report contents
        self.assertTrue('PYTHONPATH' in pr['ProcEnviron'],
                        'report contains PYTHONPATH')
        self.assertTrue('/my/bogus/path' in pr['ProcEnviron'],
                        pr['ProcEnviron'])

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
                p = subprocess.Popen(['python'], stdin=subprocess.PIPE,
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

        # put the script into /var/crash, since that isn't ignored in the
        # hook
        (fd, script) = tempfile.mkstemp(dir=apport.fileutils.report_dir)
        orig_home = os.getenv('HOME')
        if orig_home is not None:
            del os.environ['HOME']
        ifpath = os.path.expanduser(apport.report._ignore_file)
        orig_ignore_file = None
        if orig_home is not None:
            os.environ['HOME'] = orig_home
        try:
            os.write(fd, ('''#!/usr/bin/env %s
import apport_python_hook
apport_python_hook.install()

def func(x):
    raise Exception('This should happen.')

func(42)
''' % os.getenv('PYTHON', 'python3')).encode('ascii'))
            os.close(fd)
            os.chmod(script, 0o755)

            # move aside current ignore file
            if os.path.exists(ifpath):
                orig_ignore_file = ifpath + '.apporttest'
                os.rename(ifpath, orig_ignore_file)

            # ignore
            r = apport.report.Report()
            r['ExecutablePath'] = script
            r.mark_ignore()
            r = None

            p = subprocess.Popen([script, 'testarg1', 'testarg2'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            err = p.communicate()[1].decode()
            self.assertEqual(p.returncode, 1,
                             'crashing test python program exits with failure code')
            self.assertTrue('Exception: This should happen.' in err, err)

        finally:
            os.unlink(script)
            # clean up our ignore file
            if os.path.exists(ifpath):
                os.unlink(ifpath)
            if orig_ignore_file:
                os.rename(orig_ignore_file, ifpath)

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

    def test_dbus_service_unknown_invalid(self):
        '''DBus.Error.ServiceUnknown with an invalid name'''

        self._test_crash(extracode='''import dbus
obj = dbus.SessionBus().get_object('com.example.NotExisting', '/Foo')
''')

        pr = self._load_report()
        self.assertTrue(pr['Traceback'].startswith('Traceback'), pr['Traceback'])
        self.assertTrue('org.freedesktop.DBus.Error.ServiceUnknown' in pr['Traceback'], pr['Traceback'])
        self.assertEqual(pr['DbusErrorAnalysis'], 'no service file providing com.example.NotExisting')

    def test_dbus_service_unknown_wrongbus_notrunning(self):
        '''DBus.Error.ServiceUnknown with a valid name on a different bus (not running)'''

        subprocess.call(['killall', 'gvfsd-metadata'])
        self._test_crash(extracode='''import dbus
obj = dbus.SystemBus().get_object('org.gtk.vfs.Metadata', '/org/gtk/vfs/metadata')
''')

        pr = self._load_report()
        self.assertTrue('org.freedesktop.DBus.Error.ServiceUnknown' in pr['Traceback'], pr['Traceback'])
        self.assertTrue(pr['DbusErrorAnalysis'].startswith('provided by /usr/share/dbus-1/services/gvfs-metadata.service'),
                        pr['DbusErrorAnalysis'])
        self.assertTrue('gvfsd-metadata is not running' in pr['DbusErrorAnalysis'], pr['DbusErrorAnalysis'])

    def test_dbus_service_unknown_wrongbus_running(self):
        '''DBus.Error.ServiceUnknown with a valid name on a different bus (running)'''

        self._test_crash(extracode='''import dbus
# let the service be activated, to ensure it is running
obj = dbus.SessionBus().get_object('org.gtk.vfs.Metadata', '/org/gtk/vfs/metadata')
assert obj
obj = dbus.SystemBus().get_object('org.gtk.vfs.Metadata', '/org/gtk/vfs/metadata')
''')

        pr = self._load_report()
        self.assertTrue('org.freedesktop.DBus.Error.ServiceUnknown' in pr['Traceback'], pr['Traceback'])
        self.assertTrue(pr['DbusErrorAnalysis'].startswith('provided by /usr/share/dbus-1/services/gvfs-metadata.service'),
                        pr['DbusErrorAnalysis'])
        self.assertTrue('gvfsd-metadata is running' in pr['DbusErrorAnalysis'], pr['DbusErrorAnalysis'])

    def test_dbus_service_timeout_running(self):
        '''DBus.Error.NoReply with a running service'''

        # ensure the service is running
        metadata_obj = dbus.SessionBus().get_object('org.gtk.vfs.Metadata', '/org/gtk/vfs/metadata')
        self.assertNotEqual(metadata_obj, None)

        # timeout of zero will always fail with NoReply
        try:
            subprocess.call(['killall', '-STOP', 'gvfsd-metadata'])
            self._test_crash(extracode='''import dbus
obj = dbus.SessionBus().get_object('org.gtk.vfs.Metadata', '/org/gtk/vfs/metadata')
assert obj
i = dbus.Interface(obj, 'org.freedesktop.DBus.Peer')
i.Ping(timeout=1)
''')
        finally:
            subprocess.call(['killall', '-CONT', 'gvfsd-metadata'])

        # check report contents
        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 0, 'NoReply is an useless exception and should not create a report')

        # This is disabled for now as we cannot get the bus name from the NoReply exception
        #pr = self._load_report()
        #self.assertTrue('org.freedesktop.DBus.Error.NoReply' in pr['Traceback'], pr['Traceback'])
        #self.assertTrue(pr['DbusErrorAnalysis'].startswith('provided by /usr/share/dbus-1/services/gvfs-metadata.service'),
        #                pr['DbusErrorAnalysis'])
        #self.assertTrue('gvfsd-metadata is running' in pr['DbusErrorAnalysis'], pr['DbusErrorAnalysis'])

# This is disabled for now as we cannot get the bus name from the NoReply exception
#    def test_dbus_service_timeout_notrunning(self):
#        '''DBus.Error.NoReply with a crashing method'''
#
#        # run our own mock service with a crashing method
#        subprocess.call(['killall', 'gvfsd-metadata'])
#        service = subprocess.Popen([os.getenv('PYTHON', 'python3')],
#                                   stdin=subprocess.PIPE,
#                                   universal_newlines=True)
#        service.stdin.write('''import os
#import dbus, dbus.service, dbus.mainloop.glib
#from gi.repository import GLib
#
#class MockMetadata(dbus.service.Object):
#    @dbus.service.method('com.ubuntu.Test', in_signature='', out_signature='i')
#    def Crash(self):
#        os.kill(os.getpid(), 5)
#
#dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
#dbus_name = dbus.service.BusName('org.gtk.vfs.Metadata', dbus.SessionBus())
#svr = MockMetadata(bus_name=dbus_name, object_path='/org/gtk/vfs/metadata')
#GLib.MainLoop().run()
#''')
#        service.stdin.close()
#        self.addCleanup(service.terminate)
#        time.sleep(0.5)
#
#        self._test_crash(extracode='''import dbus
#obj = dbus.SessionBus().get_object('org.gtk.vfs.Metadata', '/org/gtk/vfs/metadata')
#assert obj
#dbus.Interface(obj, 'com.ubuntu.Test').Crash()
#''')
#
#        pr = self._load_report()
#        self.assertTrue('org.freedesktop.DBus.Error.NoReply' in pr['Traceback'], pr['Traceback'])
#        self.assertTrue(pr['DbusErrorAnalysis'].startswith('provided by /usr/share/dbus-1/services/gvfs-metadata.service'),
#                        pr['DbusErrorAnalysis'])
#        self.assertTrue('gvfsd-metadata is not running' in pr['DbusErrorAnalysis'], pr['DbusErrorAnalysis'])

    def _load_report(self):
        '''Ensure that there is exactly one crash report and load it'''

        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 1, 'crashed Python program produced a report')
        pr = problem_report.ProblemReport()
        with open(reports[0], 'rb') as f:
            pr.load(f)
        return pr

unittest.main()
