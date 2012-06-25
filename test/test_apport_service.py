'''Test apport-service'''

# Copyright (C) 2012 Canonical Ltd.
# Author: Evan Dandrea <ev@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import unittest
import subprocess
import dbus
import os
import tempfile
import time
import sys
import apport
import traceback


class T(unittest.TestCase):
    @classmethod
    def setUpClass(klass):
        klass.temp_report_dir = tempfile.TemporaryDirectory()
        os.environ['APPORT_REPORT_DIR'] = klass.temp_report_dir.name
        cmd = ['data/apport-service']
        klass.apport_service = subprocess.Popen(cmd)
        # Wait for the daemon to start.
        time.sleep(1)

    def setUp(self):
        bus = dbus.SessionBus()
        obj = bus.get_object('com.ubuntu.Apport', '/com/ubuntu/Apport')
        self.iface = dbus.Interface(obj, 'com.ubuntu.Apport')
        self.tb = ''.join(traceback.format_stack())

    def test_apport_service(self):
        empty = dbus.Dictionary(signature=dbus.Signature('ss'))
        self.iface.RecoverableCrashReport('test_body', self.tb, empty)
        path = os.path.abspath(sys.argv[0]).replace('/', '_')
        report_dir = os.environ['APPORT_REPORT_DIR']
        expected_path = '%s/%s.%i.crash' % (report_dir, path, os.getuid())
        self.assertTrue(os.path.exists(expected_path))
        report = apport.Report()
        with open(expected_path, 'rb') as fp:
            report.load(fp)
            self.assertEqual(report['DialogBody'], 'test_body')
            self.assertEqual(report['Traceback'], self.tb)

    def test_apport_service_additional_keys(self):
        keys = {'TestKey': 'TestValue', 'TestKey2': 'TestValue2'}
        self.iface.RecoverableCrashReport('test_body', self.tb, keys)
        path = os.path.abspath(sys.argv[0]).replace('/', '_')
        report_dir = os.environ['APPORT_REPORT_DIR']
        expected_path = '%s/%s.%i.crash' % (report_dir, path, os.getuid())
        self.assertTrue(os.path.exists(expected_path))
        report = apport.Report()
        with open(expected_path, 'rb') as fp:
            report.load(fp)
            self.assertEqual(report['DialogBody'], 'test_body')
            self.assertEqual(report['Traceback'], self.tb)
            for key in keys:
                self.assertEqual(report[key], keys[key])

    @classmethod
    def tearDownClass(klass):
        klass.apport_service.terminate()
        klass.temp_report_dir.cleanup()

unittest.main()
