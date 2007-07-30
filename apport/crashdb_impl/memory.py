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

    def upload(self, report, progress_callback = None):
        '''Store the report and return a handle number (starting from 0).
        
        This does not support (nor need) progress callbacks.'''

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

    def get_unfixed(self):
        '''Return an ID set of all crashes which are not yet fixed.

        The list must not contain bugs which were rejected or duplicate.
        
        This function should make sure that the returned list is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).'''

        result = set()
        for i in xrange(len(self.reports)):
            if self.reports[i]['dup_of'] is None and \
                self.reports[i]['fixed_version'] == None:
                result.add(i)

        return result

    def get_fixed_version(self, id):
        '''Return the package version that fixes a given crash.

        Return None if the crash is not yet fixed, or an empty string if the
        crash is fixed, but it cannot be determined by which version. Return
        'invalid' if the crash report got invalidated, such as closed a
        duplicate or rejected.

        This function should make sure that the returned result is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).'''

        try:
            if self.reports[id]['dup_of'] != None:
                return 'invalid'
            return self.reports[id]['fixed_version']
        except IndexError:
            return 'invalid'

    def close_duplicate(self, id, master):
        '''Mark a crash id as duplicate of given master ID.'''

        self.reports[id]['dup_of'] = master

    def mark_regression(self, id, master):
        '''Mark a crash id as reintroducing an earlier crash which is
        already marked as fixed (having ID 'master').'''

        assert self.reports[master]['fixed_version'] != None
        self.reports[id]['comment'] = 'regression, already fixed in #%i' % master

    def _mark_dup_checked(self, id, report):
        '''Mark crash id as checked for being a duplicate.'''

        pass

    def latest_id(self):
        '''Return the ID of the most recently filed report.'''

        return len(self.reports)-1

#
# Unit test (this also tests the dup detection API from apport/crashdb.py)
#

if __name__ == '__main__':
    import unittest, copy, time

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

        def test_status(self):
            '''Test get_unfixed(), get_fixed_version() and close_duplicate().'''

            self.assertEqual(self.crashes.get_unfixed(), set([0, 1, 2, 4]))
            self.assertEqual(self.crashes.get_fixed_version(0), None)
            self.assertEqual(self.crashes.get_fixed_version(1), None)
            self.assertEqual(self.crashes.get_fixed_version(3), '4.1')
            self.crashes.close_duplicate(1, 0)
            self.assertEqual(self.crashes.get_unfixed(), set([0, 2, 4]))
            self.assertEqual(self.crashes.get_fixed_version(1), 'invalid')

            self.assertEqual(self.crashes.get_fixed_version(99), 'invalid')

        def test_mark_regression(self):
            '''Test mark_regression().'''

            self.crashes.mark_regression(4, 3)
            self.assertEqual(self.crashes.reports[4]['comment'], 
                'regression, already fixed in #3')

        #
        # Test crash duplication detection API of crashdb.py
        #

        def test_duplicate_db_fixed(self):
            '''Test duplicate_db_fixed().'''

            self.crashes.init_duplicate_db(':memory:')
            self.assertEqual(self.crashes.check_duplicate(0), None)

            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, None)})

            self.crashes.duplicate_db_fixed(0, '42')

            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, '42')})

        def test_duplicate_db_remove(self):
            '''Test duplicate_db_remove().'''

            self.crashes.init_duplicate_db(':memory:')
            self.assertEqual(self.crashes.check_duplicate(0), None)

            self.crashes.duplicate_db_remove(0)

            self.assertEqual(self.crashes._duplicate_db_dump(), {})

        def test_check_duplicate(self):
            '''Test check_duplicate().'''

            # db not yet initialized
            self.assertRaises(AssertionError, self.crashes.check_duplicate, 0,
                self.crashes.download(0))
            self.assertRaises(AssertionError, self.crashes.check_duplicate, 0)

            self.crashes.init_duplicate_db(':memory:')

            self.assertEqual(self.crashes._duplicate_db_dump(), {})

            # ID#0 -> no dup
            self.assertEqual(self.crashes.check_duplicate(0), None)

            # ID#1 -> dup of #0
            self.assertEqual(self.crashes.check_duplicate(1), (0, None))

            # ID#2 is unrelated, no dup
            self.assertEqual(self.crashes.check_duplicate(2), None)

            # ID#3: no dup, master of ID#4
            self.assertEqual(self.crashes.check_duplicate(3), None)
            # manually poke the fixed version into the dup db; this will
            # normally be done by duplicate_db_consolidate(), but let's test
            # this separately
            self.crashes.duplicate_db_fixed(3, '4.1')

            # check current states of real world; ID#1 is a dup and thus does
            # not appear
            self.assertEqual(self.crashes.get_unfixed(), set([0, 2, 4]))

            # ID#4: dup of ID#3, and a regression (fixed in 4.1, happened in 5)
            self.assertEqual(self.crashes.check_duplicate(4), (3, '4.1'))

            # check crash states again; ID#4 is a regression of ID#3 in version
            # 5, so it's not a real duplicate
            self.assertEqual(self.crashes.get_unfixed(), set([0, 2, 4]))

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
            self.assertEqual(self.crashes.check_duplicate(5), (3, '4.1'))

            r = copy.copy(self.crashes.download(3))
            r['Package'] = 'python-goo 5.1'
            self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
                'http://pygoo.bug.net/6')
            self.assertEqual(self.crashes.check_duplicate(6), (4, None))

            # check with unknown fixed version
            self.crashes.reports[3]['fixed_version'] = ''
            self.crashes.duplicate_db_fixed(3, '')

            r = copy.copy(self.crashes.download(3))
            r['Package'] = 'python-goo 5.1'
            self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
                'http://pygoo.bug.net/7')
            self.assertEqual(self.crashes.check_duplicate(7), (3, ''))

            # final consistency check
            self.assertEqual(self.crashes.get_unfixed(), set([0, 2, 4]))

        def test_check_duplicate_report_arg(self):
            '''Test check_duplicate() with explicitly passing report.'''

            self.crashes.init_duplicate_db(':memory:')

            # ID#0 -> no dup
            self.assertEqual(self.crashes.check_duplicate(0), None)

            # ID#2 is unrelated, no dup
            self.assertEqual(self.crashes.check_duplicate(2), None)

            # report from ID#1 is a dup of #0
            self.assertEqual(self.crashes.check_duplicate(2,
                self.crashes.download(1)), (0, None))

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
            self.assertEqual(self.crashes.get_unfixed(), set([0, 1, 4]))

            # no fixed version for #3 yet, and obsolete #2 is still there
            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, None),
                 self.crashes.download(2).crash_signature(): (2, None),
                 self.crashes.download(3).crash_signature(): (3, None)})

            self.crashes.duplicate_db_consolidate()

            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, None),
                 self.crashes.download(3).crash_signature(): (3, '4.1')})

        def test_duplicate_db_needs_consolidation(self):
            '''Test duplicate_db_needs_consolidation().'''

            self.crashes.init_duplicate_db(':memory:')

            # a fresh and empty db does not need consolidation
            self.failIf(self.crashes.duplicate_db_needs_consolidation())

            time.sleep(1.1)
            # for an one-day interval we do not need consolidation
            self.failIf(self.crashes.duplicate_db_needs_consolidation())
            # neither for a ten second one (check timezone offset errors)
            self.failIf(self.crashes.duplicate_db_needs_consolidation(10))
            # but for an one second interval
            self.assert_(self.crashes.duplicate_db_needs_consolidation(1))

            self.crashes.duplicate_db_consolidate()

            self.failIf(self.crashes.duplicate_db_needs_consolidation(1))

        def test_change_master_id(self):
            '''Test duplicate_db_change_master_id().'''

            # db not yet initialized
            self.assertRaises(AssertionError, self.crashes.check_duplicate, 0)

            self.crashes.init_duplicate_db(':memory:')

            self.assertEqual(self.crashes.check_duplicate(0), None)
            self.assertEqual(self.crashes.check_duplicate(2), None)

            # check DB consistency
            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, None),
                 self.crashes.download(2).crash_signature(): (2, None)})

            # invalid ID (raising KeyError is *hard*, so it's not done)
            self.crashes.duplicate_db_change_master_id(5, 99)

            # nevertheless, this should not change the DB
            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, None),
                 self.crashes.download(2).crash_signature(): (2, None)})

            # valid ID
            self.crashes.duplicate_db_change_master_id(2, 99)

            # check DB consistency
            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, None),
                 self.crashes.download(2).crash_signature(): (99, None)})

    unittest.main()
