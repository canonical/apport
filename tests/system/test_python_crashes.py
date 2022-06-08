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
import subprocess
import tempfile
import unittest

import dbus

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

    def test_dbus_service_unknown_invalid(self):
        '''DBus.Error.ServiceUnknown with an invalid name'''

        self._test_crash(extracode='''import dbus
obj = dbus.SessionBus().get_object('com.example.NotExisting', '/Foo')
''')

        pr = self._load_report()
        self.assertTrue(pr['Traceback'].startswith('Traceback'), pr['Traceback'])
        self.assertIn('org.freedesktop.DBus.Error.ServiceUnknown', pr['Traceback'])
        self.assertEqual(pr['DbusErrorAnalysis'], 'no service file providing com.example.NotExisting')

    def test_dbus_service_unknown_wrongbus_notrunning(self):
        '''DBus.Error.ServiceUnknown with a valid name on a different bus (not running)'''

        subprocess.call(['killall', 'gvfsd-metadata'])
        self._test_crash(extracode='''import dbus
obj = dbus.SystemBus().get_object('org.gtk.vfs.Metadata', '/org/gtk/vfs/metadata')
''')

        pr = self._load_report()
        self.assertIn('org.freedesktop.DBus.Error.ServiceUnknown', pr['Traceback'])
        self.assertRegex(pr['DbusErrorAnalysis'], '^provided by .*/dbus-1/services.*vfs.*[mM]etadata.service')
        self.assertIn('gvfsd-metadata is not running', pr['DbusErrorAnalysis'])

    def test_dbus_service_unknown_wrongbus_running(self):
        '''DBus.Error.ServiceUnknown with a valid name on a different bus (running)'''

        self._test_crash(extracode='''import dbus
# let the service be activated, to ensure it is running
obj = dbus.SessionBus().get_object('org.gtk.vfs.Metadata', '/org/gtk/vfs/metadata')
assert obj
obj = dbus.SystemBus().get_object('org.gtk.vfs.Metadata', '/org/gtk/vfs/metadata')
''')

        pr = self._load_report()
        self.assertIn('org.freedesktop.DBus.Error.ServiceUnknown', pr['Traceback'])
        self.assertRegex(pr['DbusErrorAnalysis'], '^provided by .*/dbus-1/services.*vfs.*[mM]etadata.service')
        self.assertIn('gvfsd-metadata is running', pr['DbusErrorAnalysis'])

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
        # pr = self._load_report()
        # self.assertTrue('org.freedesktop.DBus.Error.NoReply' in pr['Traceback'], pr['Traceback'])
        # self.assertTrue(pr['DbusErrorAnalysis'].startswith('provided by /usr/share/dbus-1/services/gvfs-metadata.service'),
        #                 pr['DbusErrorAnalysis'])
        # self.assertTrue('gvfsd-metadata is running' in pr['DbusErrorAnalysis'], pr['DbusErrorAnalysis'])

# This is disabled for now as we cannot get the bus name from the NoReply exception
#     def test_dbus_service_timeout_notrunning(self):
#         '''DBus.Error.NoReply with a crashing method'''
#
#         # run our own mock service with a crashing method
#         subprocess.call(['killall', 'gvfsd-metadata'])
#         service = subprocess.Popen([os.getenv('PYTHON', 'python3')],
#                                    stdin=subprocess.PIPE,
#                                    universal_newlines=True)
#         service.stdin.write('''import os
# import dbus, dbus.service, dbus.mainloop.glib
# from gi.repository import GLib
#
# class MockMetadata(dbus.service.Object):
#     @dbus.service.method('com.ubuntu.Test', in_signature='', out_signature='i')
#     def Crash(self):
#         os.kill(os.getpid(), 5)
#
# dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
# dbus_name = dbus.service.BusName('org.gtk.vfs.Metadata', dbus.SessionBus())
# svr = MockMetadata(bus_name=dbus_name, object_path='/org/gtk/vfs/metadata')
# GLib.MainLoop().run()
# ''')
#         service.stdin.close()
#         self.addCleanup(service.terminate)
#         time.sleep(0.5)
#
#         self._test_crash(extracode='''import dbus
# obj = dbus.SessionBus().get_object('org.gtk.vfs.Metadata', '/org/gtk/vfs/metadata')
# assert obj
# dbus.Interface(obj, 'com.ubuntu.Test').Crash()
# ''')
#
#         pr = self._load_report()
#         self.assertTrue('org.freedesktop.DBus.Error.NoReply' in pr['Traceback'], pr['Traceback'])
#         self.assertTrue(pr['DbusErrorAnalysis'].startswith('provided by /usr/share/dbus-1/services/gvfs-metadata.service'),
#                         pr['DbusErrorAnalysis'])
#         self.assertTrue('gvfsd-metadata is not running' in pr['DbusErrorAnalysis'], pr['DbusErrorAnalysis'])

    def test_dbus_service_other_error(self):
        '''Other DBusExceptions get an unwrapped original exception'''

        self._test_crash(extracode='''import dbus
obj = dbus.SessionBus().get_object('org.gtk.vfs.Daemon', '/org/gtk/vfs/Daemon')
dbus.Interface(obj, 'org.gtk.vfs.Daemon').Nonexisting(1)
''')

        pr = self._load_report()
        self.assertTrue(pr['Traceback'].startswith('Traceback'), pr['Traceback'])
        self.assertIn('org.freedesktop.DBus.Error.UnknownMethod', pr['Traceback'])
        self.assertNotIn('DbusErrorAnalysis', pr)
        # we expect it to unwrap the actual exception from the DBusException
        self.assertIn('dbus.exceptions.DBusException(org.freedesktop.DBus.Error.UnknownMethod):',
                      pr.crash_signature())

    def _load_report(self):
        '''Ensure that there is exactly one crash report and load it'''

        reports = apport.fileutils.get_new_reports()
        self.assertEqual(len(reports), 1, 'crashed Python program produced a report')
        pr = apport.Report()
        with open(reports[0], 'rb') as f:
            pr.load(f)
        return pr
