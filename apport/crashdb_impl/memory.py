'''Simple in-memory CrashDatabase implementation, mainly useful for testing.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import apport.crashdb
import apport

class CrashDatabase(apport.crashdb.CrashDatabase):
    '''Simple implementation of crash database interface which keeps everything
    in memory.
    
    This is mainly useful for testing and debugging.'''

    def __init__(self, auth_file, bugpattern_baseurl, options):
        '''Initialize crash database connection.
        
        This class does not support bug patterns and authentication.'''

        apport.crashdb.CrashDatabase.__init__(self, auth_file,
            bugpattern_baseurl, options)

        self.reports = [] # list of dictionaries with keys: report, fixed_version, dup_of, comment

    def upload(self, report):
        '''Store the report and return a handle number (starting from 0).'''

        self.reports.append({'report': report, 'fixed_version': None, 'dup_of':
            None, 'comment:': ''})
        return len(self.reports)-1

    def get_comment_url(self, report, handle):
        '''Return http://<sourcepackage>.bug.net/<handle> for package bugs
        or http://bug.net/<handle> for reports without a SourcePackage.'''

        if report.has_key('SourcePackage'):
            return 'http://%s.bug.net/%i' % (report['SourcePackage'],
                handle)
        else:
            return 'http://bug.net/%i' % handle

    def download(self, id):
        '''Download the problem report from given ID and return a Report.'''

        return self.reports[id]['report']

    def update(self, id, report, comment = ''):
        '''Update the given report ID with the retraced results from the report
        (Stacktrace, ThreadStacktrace, StacktraceTop; also Disassembly if
        desired) and an optional comment.'''

        self.reports[id]['report'] = report
        self.reports[id]['comment'] = comment

    def get_distro_release(self, id):
        '''Get 'DistroRelease: <release>' from the given report ID and return
        it.'''

        return self.reports[id]['report']['DistroRelease']

    def get_status_list(self):
        '''Return a mapping 'id -> fixed_version' of all currently tracked crashes.

        The keys are integers (crash IDs), the values are 'None' for unfixed
        crashes or the package version the crash was fixed in for resolved
        crashes. The list must not contain bugs which were rejected or manually
        marked as duplicate.
        
        This function should make sure that the returned map is consistent. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).'''

        result = {}
        for i in xrange(len(self.reports)):
            if self.reports[i]['dup_of'] is None:
                result[i] = self.reports[i]['fixed_version']

        return result

    def close_duplicate(self, id, master):
        '''Mark a crash id as duplicate of given master ID.'''

        self.reports[id]['dup_of'] = master

    def crash_regression(self, id, master):
        '''Mark a crash id as reintroducing an earlier crash which is
        already marked as fixed (having ID 'master').'''

        assert self.reports[master]['fixed_version'] != None
        self.reports[id]['comment'] = 'regression, already fixed in #%i' % master

    def latest_id(self):
        '''Return the ID of the most recently filed report.'''

        return len(self.reports)-1

#
# Unit test (this also tests the dup detection API from apport/crashdb.py)
#

if __name__ == '__main__':
    import unittest, copy

    class _MemoryCrashDBTest(unittest.TestCase):
        def setUp(self):
            self.crashes = CrashDatabase(None, None, {})

            # signal crash with source package and complete stack trace
            r = apport.Report()
            r['Package'] = 'libfoo1 1.2-3'
            r['SourcePackage'] = 'foo'
            r['DistroRelease'] = 'FooLinux Pi/2'
            r['Signal'] = '11'
            r['ExecutablePath'] = '/bin/crash'

            r['StacktraceTop'] = '''foo_bar (x=1) at crash.c:28
d01 (x=1) at crash.c:29
raise () from /lib/libpthread.so.0
<signal handler called>
__frob (x=1) at crash.c:30'''
            self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
                'http://foo.bug.net/0')

            # duplicate of above crash (slightly different arguments and
            # package version)
            r = apport.Report()
            r['Package'] = 'libfoo1 1.2-4'
            r['SourcePackage'] = 'foo'
            r['Signal'] = '11'
            r['ExecutablePath'] = '/bin/crash'

            r['StacktraceTop'] = '''foo_bar (x=2) at crash.c:28
d01 (x=3) at crash.c:29
raise () from /lib/libpthread.so.0
<signal handler called>
__frob (x=4) at crash.c:30'''
            self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
                'http://foo.bug.net/1')

            # unrelated signal crash
            r = apport.Report()
            r['Package'] = 'bar 42-4'
            r['SourcePackage'] = 'bar'
            r['Signal'] = '11'
            r['ExecutablePath'] = '/usr/bin/broken'

            r['StacktraceTop'] = '''h (p=0x0) at crash.c:25
g (x=1, y=42) at crash.c:26
f (x=1) at crash.c:27
e (x=1) at crash.c:28
d (x=1) at crash.c:29'''
            self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
                'http://bar.bug.net/2')

            # Python crash
            r = apport.Report()
            r['Package'] = 'python-goo 3epsilon1'
            r['SourcePackage'] = 'pygoo'
            r['ExecutablePath'] = '/usr/bin/pygoo'
            r['Traceback'] = '''Traceback (most recent call last):
  File "test.py", line 7, in <module>
    print _f(5)
  File "test.py", line 5, in _f
    return g_foo00(x+1)
  File "test.py", line 2, in g_foo00
    return x/0
ZeroDivisionError: integer division or modulo by zero'''
            self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
                'http://pygoo.bug.net/3')

            # mark the python crash as fixed
            self.crashes.reports[3]['fixed_version'] = '4.1'

            # Python crash reoccurs in a later version (regression)
            r = apport.Report()
            r['Package'] = 'python-goo 5'
            r['SourcePackage'] = 'pygoo'
            r['ExecutablePath'] = '/usr/bin/pygoo'
            r['Traceback'] = '''Traceback (most recent call last):
  File "test.py", line 7, in <module>
    print _f(5)
  File "test.py", line 5, in _f
    return g_foo00(x+1)
  File "test.py", line 2, in g_foo00
    return x/0
ZeroDivisionError: integer division or modulo by zero'''
            self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
                'http://pygoo.bug.net/4')

            # test-suite internal consistency check: Python signatures are
            # indeed equal and exist
            assert self.crashes.download(3).crash_signature(), \
                'test-suite internal check: Python crash sigs exist'
            self.assertEqual(self.crashes.download(3).crash_signature(),
                self.crashes.download(4).crash_signature())

            # we should have 5 crashes
            self.assertEqual(self.crashes.latest_id(), 4)

        #
        # Test memory.py implementation
        #

        def test_submit(self):
            '''Test crash uploading and downloading.'''

            # setUp() already checks upload() and get_comment_url()
            r = self.crashes.download(0)
            self.assertEqual(r['SourcePackage'], 'foo')
            self.assertEqual(r['Package'], 'libfoo1 1.2-3')
            self.assertEqual(self.crashes.reports[0]['dup_of'], None)

            self.assertRaises(IndexError, self.crashes.download, 5)

        def test_update(self):
            '''Test update().'''

            r = apport.Report()
            r['Package'] = 'new'

            self.crashes.update(1, r, 'muhaha')
            self.assertEqual(self.crashes.download(1)['Package'], 'new')
            self.assertEqual(self.crashes.reports[1]['comment'], 'muhaha')

            self.assertRaises(IndexError, self.crashes.update, 5, None)

        def test_get_distro_release(self):
            '''Test get_distro_release().'''

            self.assertEqual(self.crashes.get_distro_release(0), 'FooLinux Pi/2')

        def test_get_status_list(self):
            '''Test get_status_list() and close_duplicate().'''

            self.assertEqual(self.crashes.get_status_list(), 
                {0: None, 1: None, 2: None, 3: '4.1', 4: None})
            self.crashes.close_duplicate(1, 0)
            self.assertEqual(self.crashes.get_status_list(),
                {0: None, 2: None, 3: '4.1', 4: None})

        def test_crash_regression(self):
            '''Test crash_regression().'''

            self.crashes.crash_regression(4, 3)
            self.assertEqual(self.crashes.reports[4]['comment'], 
                'regression, already fixed in #3')

        #
        # Test crash duplication detection API of crashdb.py
        #

        def test_duplicate_db_fixed(self):
            '''Test duplicate_db_fixed().'''

            self.crashes.init_duplicate_db(':memory:')
            self.assertEqual(self.crashes.check_duplicate(0,
                self.crashes.download(0)), None)

            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, None)})

            self.crashes.duplicate_db_fixed(0, '42')

            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, '42')})

        def test_duplicate_db_remove(self):
            '''Test duplicate_db_remove().'''

            self.crashes.init_duplicate_db(':memory:')
            self.assertEqual(self.crashes.check_duplicate(0,
                self.crashes.download(0)), None)

            self.crashes.duplicate_db_remove(0)

            self.assertEqual(self.crashes._duplicate_db_dump(), {})

        def test_check_duplicate(self):
            '''Test check_duplicate().'''

            # db not yet initialized
            self.assertRaises(AssertionError, self.crashes.check_duplicate, 0,
                self.crashes.download(0))

            self.crashes.init_duplicate_db(':memory:')

            self.assertEqual(self.crashes._duplicate_db_dump(), {})

            # ID#0 -> no dup
            self.assertEqual(self.crashes.check_duplicate(0,
                self.crashes.download(0)), None)

            # ID#1 -> dup of #0
            self.assertEqual(self.crashes.check_duplicate(1,
                self.crashes.download(1)), (0, None))

            # ID#2 is unrelated, no dup
            self.assertEqual(self.crashes.check_duplicate(2,
                self.crashes.download(2)), None)

            # ID#3: no dup, master of ID#4
            self.assertEqual(self.crashes.check_duplicate(3,
                self.crashes.download(3)), None)
            # manually poke the fixed version into the dup db; this will
            # normally be done by duplicate_db_consolidate(), but let's test
            # this separately
            self.crashes.duplicate_db_fixed(3, '4.1')

            # check current states of real world; ID#1 is a dup and thus does
            # not appear
            self.assertEqual(self.crashes.get_status_list(), 
                {0: None, 2: None, 3: '4.1', 4: None})

            # ID#4: dup of ID#3, and a regression (fixed in 4.1, happened in 5)
            self.assertEqual(self.crashes.check_duplicate(4,
                self.crashes.download(4)), (3, '4.1'))

            # check crash states again; ID#4 is a regression of ID#3 in version
            # 5, so it's not a real duplicate
            self.assertEqual(self.crashes.get_status_list(), 
                {0: None, 2: None, 3: '4.1', 4: None})

            # check DB consistency; ID#1 is a dup and does not appear
            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, None),
                 self.crashes.download(2).crash_signature(): (2, None),
                 self.crashes.download(3).crash_signature(): (3, '4.1'),
                 self.crashes.download(4).crash_signature(): (4, None)})

            # add two more  Python crash dups and verify that they are dup'ed
            # to the correct ID
            r = copy.copy(self.crashes.download(3))
            self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
                'http://pygoo.bug.net/5')
            self.assertEqual(self.crashes.check_duplicate(5,
                self.crashes.download(5)), (3, '4.1'))

            r = copy.copy(self.crashes.download(3))
            r['Package'] = 'python-goo 5.1'
            self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
                'http://pygoo.bug.net/6')
            self.assertEqual(self.crashes.check_duplicate(6,
                self.crashes.download(6)), (4, None))

        def test_duplicate_db_consolidate(self):
            '''Test duplicate_db_consolidate().'''

            self.crashes.init_duplicate_db(':memory:')
            self.assertEqual(self.crashes.check_duplicate(0,
                self.crashes.download(0)), None)
            self.assertEqual(self.crashes.check_duplicate(2,
                self.crashes.download(2)), None)
            self.assertEqual(self.crashes.check_duplicate(3,
                self.crashes.download(3)), None)

            # manually kill #2
            self.crashes.close_duplicate(2, 0)
            self.assertEqual(self.crashes.get_status_list(), 
                {0: None, 1: None, 3: '4.1', 4: None})

            # no fixed version for #3 yet, and obsolete #2 is still there
            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, None),
                 self.crashes.download(2).crash_signature(): (2, None),
                 self.crashes.download(3).crash_signature(): (3, None)})

            self.crashes.duplicate_db_consolidate()

            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, None),
                 self.crashes.download(3).crash_signature(): (3, '4.1')})

    unittest.main()
