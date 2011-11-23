# coding=utf-8

'''Simple in-memory CrashDatabase implementation, mainly useful for testing.'''

# Copyright (C) 2007 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import copy, time, os, unittest
import apport.crashdb
import apport

class CrashDatabase(apport.crashdb.CrashDatabase):
    '''Simple implementation of crash database interface which keeps everything
    in memory.
    
    This is mainly useful for testing and debugging.'''

    def __init__(self, auth_file, options):
        '''Initialize crash database connection.
        
        This class does not support bug patterns and authentication.'''

        apport.crashdb.CrashDatabase.__init__(self, auth_file, options)

        self.reports = [] # list of dictionaries with keys: report, fixed_version, dup_of, comment
        self.unretraced = set()
        self.dup_unchecked = set()

        if 'dummy_data' in options:
            self.add_dummy_data()

    def upload(self, report, progress_callback = None):
        '''Store the report and return a handle number (starting from 0).
        
        This does not support (nor need) progress callbacks.'''

        self.reports.append({'report': report, 'fixed_version': None, 'dup_of':
            None, 'comment:': ''})
        id = len(self.reports)-1
        if 'Traceback' in report:
            self.dup_unchecked.add(id)
        else:
            self.unretraced.add(id)
        return id

    def get_comment_url(self, report, handle):
        '''Return http://<sourcepackage>.bugs.example.com/<handle> for package bugs
        or http://bugs.example.com/<handle> for reports without a SourcePackage.'''

        if 'SourcePackage' in report:
            return 'http://%s.bugs.example.com/%i' % (report['SourcePackage'],
                handle)
        else:
            return 'http://bugs.example.com/%i' % handle

    def get_id_url(self, report, id):
        '''Return URL for a given report ID.

        The report is passed in case building the URL needs additional
        information from it, such as the SourcePackage name.

        Return None if URL is not available or cannot be determined.
        '''
        return self.get_comment_url(report, id)

    def download(self, id):
        '''Download the problem report from given ID and return a Report.'''

        return self.reports[id]['report']

    def get_affected_packages(self, id):
        '''Return list of affected source packages for given ID.'''

        return [self.reports[id]['report']['SourcePackage']]

    def is_reporter(self, id):
        '''Check whether the user is the reporter of given ID.'''

        return True

    def can_update(self, id):
        '''Check whether the user is eligible to update a report.

        A user should add additional information to an existing ID if (s)he is
        the reporter or subscribed, the bug is open, not a duplicate, etc. The
        exact policy and checks should be done according to  the particular
        implementation.
        '''
        return self.is_reporter(id)

    def update(self, id, report, comment, change_description=False,
            attachment_comment=None, key_filter=None):
        '''Update the given report ID with all data from report.

        This creates a text comment with the "short" data (see
        ProblemReport.write_mime()), and creates attachments for all the
        bulk/binary data. 
        
        If change_description is True, and the crash db implementation supports
        it, the short data will be put into the description instead (like in a
        new bug).

        comment will be added to the "short" data. If attachment_comment is
        given, it will be added to the attachment uploads.

        If key_filter is a list or set, then only those keys will be added.
        '''
        r = self.reports[id]
        r['comment'] = comment

        if key_filter:
            for f in key_filter:
                if f in report:
                    r['report'][f] = report[f]
        else:
            r['report'].update(report)

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
        for i in range(len(self.reports)):
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

    def duplicate_of(self, id):
        '''Return master ID for a duplicate bug.

        If the bug is not a duplicate, return None.
        '''
        return self.reports[id]['dup_of']

    def close_duplicate(self, report, id, master):
        '''Mark a crash id as duplicate of given master ID.
        
        If master is None, id gets un-duplicated.
        '''
        self.reports[id]['dup_of'] = master

    def mark_regression(self, id, master):
        '''Mark a crash id as reintroducing an earlier crash which is
        already marked as fixed (having ID 'master').'''

        assert self.reports[master]['fixed_version'] != None
        self.reports[id]['comment'] = 'regression, already fixed in #%i' % master

    def _mark_dup_checked(self, id, report):
        '''Mark crash id as checked for being a duplicate.'''

        try:
            self.dup_unchecked.remove(id)
        except KeyError:
            pass # happens when trying to check for dup twice

    def mark_retraced(self, id):
        '''Mark crash id as retraced.'''

        self.unretraced.remove(id)

    def get_unretraced(self):
        '''Return an ID set of all crashes which have not been retraced yet and
        which happened on the current host architecture.'''

        return self.unretraced

    def get_dup_unchecked(self):
        '''Return an ID set of all crashes which have not been checked for
        being a duplicate.

        This is mainly useful for crashes of scripting languages such as
        Python, since they do not need to be retraced. It should not return
        bugs that are covered by get_unretraced().'''

        return self.dup_unchecked

    def latest_id(self):
        '''Return the ID of the most recently filed report.'''

        return len(self.reports)-1

    def add_dummy_data(self):
        '''Add some dummy crash reports.

        This is mostly useful for test suites.'''

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
        self.upload(r)

        # duplicate of above crash (slightly different arguments and
        # package version)
        r = apport.Report()
        r['Package'] = 'libfoo1 1.2-4'
        r['SourcePackage'] = 'foo'
        r['DistroRelease'] = 'Testux 1.0'
        r['Signal'] = '11'
        r['ExecutablePath'] = '/bin/crash'

        r['StacktraceTop'] = '''foo_bar (x=2) at crash.c:28
d01 (x=3) at crash.c:29
raise () from /lib/libpthread.so.0
<signal handler called>
__frob (x=4) at crash.c:30'''
        self.upload(r)

        # unrelated signal crash
        r = apport.Report()
        r['Package'] = 'bar 42-4'
        r['SourcePackage'] = 'bar'
        r['DistroRelease'] = 'Testux 1.0'
        r['Signal'] = '11'
        r['ExecutablePath'] = '/usr/bin/broken'

        r['StacktraceTop'] = '''h (p=0x0) at crash.c:25
g (x=1, y=42) at crash.c:26
f (x=1) at crash.c:27
e (x=1) at crash.c:28
d (x=1) at crash.c:29'''
        self.upload(r)

        # Python crash
        r = apport.Report()
        r['Package'] = 'python-goo 3epsilon1'
        r['SourcePackage'] = 'pygoo'
        r['DistroRelease'] = 'Testux 2.2'
        r['ExecutablePath'] = '/usr/bin/pygoo'
        r['Traceback'] = '''Traceback (most recent call last):
File "test.py", line 7, in <module>
print _f(5)
File "test.py", line 5, in _f
return g_foo00(x+1)
File "test.py", line 2, in g_foo00
return x/0
ZeroDivisionError: integer division or modulo by zero'''
        self.upload(r)

        # Python crash reoccurs in a later version (used for regression detection)
        r = apport.Report()
        r['Package'] = 'python-goo 5'
        r['SourcePackage'] = 'pygoo'
        r['DistroRelease'] = 'Testux 2.2'
        r['ExecutablePath'] = '/usr/bin/pygoo'
        r['Traceback'] = '''Traceback (most recent call last):
File "test.py", line 7, in <module>
print _f(5)
File "test.py", line 5, in _f
return g_foo00(x+1)
File "test.py", line 2, in g_foo00
return x/0
ZeroDivisionError: integer division or modulo by zero'''
        self.upload(r)

#
# Unit test (this also tests the dup detection API from apport/crashdb.py)
#

class _T(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp()
        self.dupdb_dir = os.path.join(self.workdir, 'dupdb')
        self.crashes = CrashDatabase(None, {'dummy_data': '1',
            'dupdb_url': self.dupdb_dir})

        self.assertEqual(self.crashes.get_comment_url(self.crashes.download(0),
            0), 'http://foo.bugs.example.com/0')

        # test-suite internal consistency check: Python signatures are
        # indeed equal and exist
        assert self.crashes.download(3).crash_signature(), \
            'test-suite internal check: Python crash sigs exist'
        self.assertEqual(self.crashes.download(3).crash_signature(),
            self.crashes.download(4).crash_signature())

        # we should have 5 crashes
        self.assertEqual(self.crashes.latest_id(), 4)

    def tearDown(self):
        shutil.rmtree(self.workdir)

    def test_no_dummy_data(self):
        '''No dummy data is added by default'''

        self.crashes = CrashDatabase(None, {})
        self.assertEqual(self.crashes.latest_id(), -1)
        self.assertRaises(IndexError, self.crashes.download, 0)

    def test_retrace_markers(self):
        '''Bookkeeping in retraced and dupchecked bugs'''

        self.assertEqual(self.crashes.get_unretraced(), set([0, 1, 2]))
        self.assertEqual(self.crashes.get_dup_unchecked(), set([3, 4]))

    def test_dynamic_crashdb_conf(self):
        '''Dynamic code in crashdb.conf'''

        # use our dummy crashdb
        crashdb_conf = tempfile.NamedTemporaryFile()
        crashdb_conf.write(b'''default = 'testsuite'

def get_dyn():
    return str(2 + 2)

def get_dyn_name():
    return 'on_the' + 'fly'

databases = {
    'testsuite': { 
        'impl': 'memory',
        'dyn_option': get_dyn(),
    },
    get_dyn_name(): {
        'impl': 'memory',
        'whoami': 'dynname',
    }
}
''')
        crashdb_conf.flush()

        db = apport.crashdb.get_crashdb(None, None, crashdb_conf.name)
        self.assertEqual(db.options['dyn_option'], '4')
        db = apport.crashdb.get_crashdb(None, 'on_thefly', crashdb_conf.name)
        self.assertFalse('dyn_opion' in db.options)
        self.assertEqual(db.options['whoami'], 'dynname')

    #
    # Test memory.py implementation
    #

    def test_submit(self):
        '''Crash uploading and downloading'''

        # setUp() already checks upload() and get_comment_url()
        r = self.crashes.download(0)
        self.assertEqual(r['SourcePackage'], 'foo')
        self.assertEqual(r['Package'], 'libfoo1 1.2-3')
        self.assertEqual(self.crashes.reports[0]['dup_of'], None)

        self.assertRaises(IndexError, self.crashes.download, 5)

    def test_get_affected_packages(self):
        self.assertEqual(self.crashes.get_affected_packages(0), ['foo'])
        self.assertEqual(self.crashes.get_affected_packages(1), ['foo'])
        self.assertEqual(self.crashes.get_affected_packages(2), ['bar'])
        self.assertEqual(self.crashes.get_affected_packages(3), ['pygoo'])

    def test_update(self):
        '''update()'''

        r = apport.Report()
        r['Package'] = 'new'
        r['FooBar'] = 'Bogus'
        r['StacktraceTop'] = 'Fresh!'

        self.crashes.update(1, r, 'muhaha')
        self.assertEqual(self.crashes.reports[1]['comment'], 'muhaha')
        self.assertEqual(self.crashes.download(1)['Package'], 'new')
        self.assertEqual(self.crashes.download(1)['StacktraceTop'], 'Fresh!')
        self.assertEqual(self.crashes.download(1)['FooBar'], 'Bogus')

        self.assertRaises(IndexError, self.crashes.update, 5, None, '')

    def test_update_filter(self):
        '''update() with key_filter'''

        r = apport.Report()
        r['Package'] = 'new'
        r['FooBar'] = 'Bogus'
        r['StacktraceTop'] = 'Fresh!'

        self.crashes.update(1, r, 'muhaha', key_filter=['FooBar', 'StacktraceTop'])
        self.assertEqual(self.crashes.reports[1]['comment'], 'muhaha')
        self.assertEqual(self.crashes.download(1)['Package'], 'libfoo1 1.2-4')
        self.assertEqual(self.crashes.download(1)['StacktraceTop'], 'Fresh!')
        self.assertEqual(self.crashes.download(1)['FooBar'], 'Bogus')

        self.assertRaises(IndexError, self.crashes.update, 5, None, '')

    def test_update_traces(self):
        '''update_traces()'''

        r = apport.Report()
        r['Package'] = 'new'
        r['FooBar'] = 'Bogus'
        r['StacktraceTop'] = 'Fresh!'

        self.crashes.update_traces(1, r, 'muhaha')
        self.assertEqual(self.crashes.reports[1]['comment'], 'muhaha')
        self.assertEqual(self.crashes.download(1)['Package'], 'libfoo1 1.2-4')
        self.assertEqual(self.crashes.download(1)['StacktraceTop'], 'Fresh!')
        self.assertFalse('FooBar' in self.crashes.download(1))

        self.assertRaises(IndexError, self.crashes.update_traces, 5, None)

    def test_get_distro_release(self):
        '''get_distro_release()'''

        self.assertEqual(self.crashes.get_distro_release(0), 'FooLinux Pi/2')

    def test_status(self):
        '''get_unfixed(), get_fixed_version(), duplicate_of(), close_duplicate()'''

        self.assertEqual(self.crashes.get_unfixed(), set([0, 1, 2, 3, 4]))
        self.assertEqual(self.crashes.get_fixed_version(0), None)
        self.assertEqual(self.crashes.get_fixed_version(1), None)
        self.assertEqual(self.crashes.get_fixed_version(3), None)

        self.assertEqual(self.crashes.duplicate_of(0), None)
        self.assertEqual(self.crashes.duplicate_of(1), None)
        self.crashes.close_duplicate({}, 1, 0)
        self.assertEqual(self.crashes.duplicate_of(0), None)
        self.assertEqual(self.crashes.duplicate_of(1), 0)

        self.assertEqual(self.crashes.get_unfixed(), set([0, 2, 3, 4]))
        self.assertEqual(self.crashes.get_fixed_version(1), 'invalid')

        self.assertEqual(self.crashes.get_fixed_version(99), 'invalid')

    def test_mark_regression(self):
        '''mark_regression()'''

        self.crashes.reports[3]['fixed_version'] = '4.1'

        self.crashes.mark_regression(4, 3)
        self.assertEqual(self.crashes.reports[4]['comment'], 
            'regression, already fixed in #3')
        self.assertEqual(self.crashes.duplicate_of(3), None)
        self.assertEqual(self.crashes.duplicate_of(4), None)

    #
    # Test crash duplication detection API of crashdb.py
    #

    def test_duplicate_db_fixed(self):
        '''duplicate_db_fixed()'''

        self.crashes.init_duplicate_db(':memory:')
        self.assertEqual(self.crashes.check_duplicate(0), None)

        self.assertEqual(self.crashes._duplicate_db_dump(), 
            {self.crashes.download(0).crash_signature(): (0, None)})

        self.crashes.duplicate_db_fixed(0, '42')

        self.assertEqual(self.crashes._duplicate_db_dump(), 
            {self.crashes.download(0).crash_signature(): (0, '42')})

    def test_duplicate_db_remove(self):
        '''duplicate_db_remove()'''

        # db not yet initialized
        self.assertRaises(AssertionError, self.crashes.check_duplicate, 0)

        self.crashes.init_duplicate_db(':memory:')

        self.assertEqual(self.crashes.check_duplicate(0), None)
        self.assertEqual(self.crashes.check_duplicate(2), None)

        # invalid ID (raising KeyError is *hard*, so it's not done)
        self.crashes.duplicate_db_remove(99)

        # nevertheless, this should not change the DB
        self.assertEqual(self.crashes._duplicate_db_dump(), 
            {self.crashes.download(0).crash_signature(): (0, None),
             self.crashes.download(2).crash_signature(): (2, None)})

        # valid ID
        self.crashes.duplicate_db_remove(2)

        # check DB consistency
        self.assertEqual(self.crashes._duplicate_db_dump(), 
            {self.crashes.download(0).crash_signature(): (0, None)})

    def test_check_duplicate(self):
        '''check_duplicate() and known()'''

        # db not yet initialized
        self.assertRaises(AssertionError, self.crashes.check_duplicate, 0,
            self.crashes.download(0))
        self.assertRaises(AssertionError, self.crashes.check_duplicate, 0)

        self.crashes.init_duplicate_db(':memory:')

        self.assertEqual(self.crashes._duplicate_db_dump(), {})

        # ID#0 -> no dup
        self.assertEqual(self.crashes.known(self.crashes.download(0)), None)
        self.assertEqual(self.crashes.check_duplicate(0), None)
        # can't be known before publishing DB
        self.assertEqual(self.crashes.known(self.crashes.download(0)), None)
        self.crashes.duplicate_db_publish(self.dupdb_dir)
        self.assertEqual(self.crashes.known(self.crashes.download(0)), 
                'http://foo.bugs.example.com/0')

        # bug is not a duplicate of itself, when reprocessed
        self.assertEqual(self.crashes.check_duplicate(0), None)

        # ID#1 -> dup of #0
        self.crashes.duplicate_db_publish(self.dupdb_dir)
        self.assertEqual(self.crashes.known(self.crashes.download(1)), 
                'http://foo.bugs.example.com/0')
        self.assertEqual(self.crashes.check_duplicate(1), (0, None))

        # ID#2 is unrelated, no dup
        self.crashes.duplicate_db_publish(self.dupdb_dir)
        self.assertEqual(self.crashes.known(self.crashes.download(2)), None)
        self.assertEqual(self.crashes.check_duplicate(2), None)
        self.crashes.duplicate_db_publish(self.dupdb_dir)
        self.assertEqual(self.crashes.known(self.crashes.download(2)), 
                'http://bar.bugs.example.com/2')

        # ID#3: no dup, master of ID#4
        self.assertEqual(self.crashes.check_duplicate(3), None)

        # ID#4: dup of ID#3
        self.assertEqual(self.crashes.check_duplicate(4), (3, None))
        # not marked as regression
        self.assertFalse('comment' in self.crashes.reports[3])

        # check DB consistency; #1 and #4 are dupes and do not appear
        self.assertEqual(self.crashes._duplicate_db_dump(), 
            {self.crashes.download(0).crash_signature(): (0, None),
             self.crashes.download(2).crash_signature(): (2, None),
             self.crashes.download(3).crash_signature(): (3, None)})

        # now mark the python crash as fixed
        self.crashes.reports[3]['fixed_version'] = '4.1'

        # ID#4 is dup of ID#3, but happend in version 5 -> regression
        self.crashes.close_duplicate(self.crashes.download(4), 4, None) # reset
        self.assertEqual(self.crashes.check_duplicate(4), None)
        self.assertEqual(self.crashes.duplicate_of(4), None)
        self.assertEqual(self.crashes.reports[4]['comment'], 'regression, already fixed in #3')

        # check DB consistency; ID#3 should now be updated to be fixed in 4.1,
        # and as 4 is a regression, appear as a new crash
        self.assertEqual(self.crashes._duplicate_db_dump(), 
            {self.crashes.download(0).crash_signature(): (0, None),
             self.crashes.download(2).crash_signature(): (2, None),
             self.crashes.download(3).crash_signature(): (3, '4.1'),
             self.crashes.download(4).crash_signature(): (4, None)})

        # add two more  Python crash dups and verify that they are dup'ed
        # to the correct ID
        r = copy.copy(self.crashes.download(3))
        self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
            'http://pygoo.bugs.example.com/5')
        self.assertEqual(self.crashes.check_duplicate(5), (3, '4.1'))
        self.assertEqual(self.crashes.duplicate_of(5), 3)
        # not marked as regression, happened earlier than #3
        self.assertFalse('comment' in self.crashes.reports[5])

        r = copy.copy(self.crashes.download(3))
        r['Package'] = 'python-goo 5.1'
        self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
            'http://pygoo.bugs.example.com/6')
        self.assertEqual(self.crashes.check_duplicate(6), (4, None))
        self.assertEqual(self.crashes.duplicate_of(6), 4)
        # not marked as regression, as it's now a dupe of new master bug 4
        self.assertFalse('comment' in self.crashes.reports[6])

        # check DB consistency; #5 and #6 are dupes of #3 and #4, so no new
        # entries
        self.assertEqual(self.crashes._duplicate_db_dump(), 
            {self.crashes.download(0).crash_signature(): (0, None),
             self.crashes.download(2).crash_signature(): (2, None),
             self.crashes.download(3).crash_signature(): (3, '4.1'),
             self.crashes.download(4).crash_signature(): (4, None)})

        # check with unknown fixed version
        self.crashes.reports[3]['fixed_version'] = ''
        self.crashes.duplicate_db_fixed(3, '')

        r = copy.copy(self.crashes.download(3))
        r['Package'] = 'python-goo 5.1'
        self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
            'http://pygoo.bugs.example.com/7')
        self.assertEqual(self.crashes.check_duplicate(7), (3, ''))
        # not marked as regression
        self.assertFalse('comment' in self.crashes.reports[6])

        # final consistency check
        self.assertEqual(self.crashes._duplicate_db_dump(), 
            {self.crashes.download(0).crash_signature(): (0, None),
             self.crashes.download(2).crash_signature(): (2, None),
             self.crashes.download(3).crash_signature(): (3, ''),
             self.crashes.download(4).crash_signature(): (4, None)})

    def test_check_duplicate_utf8(self):
        '''check_duplicate() with UTF-8 strings'''

        # assertion failure, with UTF-8 strings
        r = apport.Report()
        r['Package'] = 'bash 5'
        r['SourcePackage'] = 'bash'
        r['DistroRelease'] = 'Testux 2.2'
        r['ExecutablePath'] = '/bin/bash'
        r['Signal'] = '6'
        r['AssertionMessage'] = 'Afirmação x != 0'
        self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
            'http://bash.bugs.example.com/5')
        self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
            'http://bash.bugs.example.com/6')

        self.crashes.init_duplicate_db(':memory:')
        self.assertEqual(self.crashes.check_duplicate(5), None)
        self.assertEqual(self.crashes.check_duplicate(6), (5, None))

    def test_check_duplicate_custom_signature(self):
        '''check_duplicate() with custom DuplicateSignature: field'''

        r = apport.Report()
        r['SourcePackage'] = 'bash'
        r['Package'] = 'bash 5'
        r['DuplicateSignature'] = 'Code42Blue'
        self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
            'http://bash.bugs.example.com/5')

        self.crashes.init_duplicate_db(':memory:')
        self.assertEqual(self.crashes.check_duplicate(5), None)

        self.assertEqual(self.crashes._duplicate_db_dump(), {'Code42Blue': (5, None)})

        # this one has a standard crash_signature
        self.assertEqual(self.crashes.check_duplicate(0), None)
        # ... but DuplicateSignature wins
        self.crashes.download(0)['DuplicateSignature'] = 'Code42Blue'
        self.assertEqual(self.crashes.check_duplicate(0), (5, None))

        self.crashes.download(1)['DuplicateSignature'] = 'CodeRed'
        self.assertEqual(self.crashes.check_duplicate(1), None)
        self.assertEqual(self.crashes._duplicate_db_dump(), 
                {'Code42Blue': (5, None), 'CodeRed': (1, None), 
                 self.crashes.download(0).crash_signature(): (0, None)})

    def test_check_duplicate_report_arg(self):
        '''check_duplicate() with explicitly passing report'''

        self.crashes.init_duplicate_db(':memory:')

        # ID#0 -> no dup
        self.assertEqual(self.crashes.check_duplicate(0), None)

        # ID#2 is unrelated, no dup
        self.assertEqual(self.crashes.check_duplicate(2), None)

        # report from ID#1 is a dup of #0
        self.assertEqual(self.crashes.check_duplicate(2,
            self.crashes.download(1)), (0, None))

    def test_known_address_sig(self):
        '''known() for address signatures'''

        self.crashes.init_duplicate_db(':memory:')

        r = apport.Report()
        r['SourcePackage'] = 'bash'
        r['Package'] = 'bash 5'
        r['ExecutablePath'] = '/bin/bash'
        r['Signal'] = '11'
        r['ProcMaps'] = '''
00400000-004df000 r-xp 00000000 08:02 1044485                            /bin/bash
7f491fa8f000-7f491fc24000 r-xp 00000000 08:02 522605                     /lib/x86_64-linux-gnu/libc-2.13.so
'''

        r['Stacktrace'] = '''
#0  0x00007f491fac5687 in kill ()
#1  0x000000000042eb76 in ?? ()
#2  0x00000000004324d8 in ??
#3  0x00000000004707e3 in parse_and_execute ()
#4  0x000000000041d703 in _start ()
'''

        self.assertNotEqual(r.crash_signature_addresses(), None)
        self.crashes.duplicate_db_publish(self.dupdb_dir)
        self.assertEqual(self.crashes.known(r), None)
        r_id = self.crashes.upload(r)
        self.assertEqual(self.crashes.check_duplicate(r_id), None)
        self.crashes.duplicate_db_publish(self.dupdb_dir)
        self.assertEqual(self.crashes.known(r), 
                self.crashes.get_comment_url(r, r_id))

        # another report with same address signature
        r2 = apport.Report()
        r2['SourcePackage'] = 'bash'
        r2['Package'] = 'bash 5'
        r2['ExecutablePath'] = '/bin/bash'
        r2['Signal'] = '11'

        r2['ProcMaps'] = '''
00400000-004df000 r-xp 00000000 08:02 1044485                            /bin/bash
5f491fa8f000-5f491fc24000 r-xp 00000000 08:02 522605                     /lib/x86_64-linux-gnu/libc-2.13.so
'''

        r2['Stacktrace'] = '''
#0  0x00005f491fac5687 in kill ()
#1  0x000000000042eb76 in ?? ()
#2  0x00000000004324d8 in ??
#3  0x00000000004707e3 in parse_and_execute ()
#4  0x000000000041d703 in _start ()
'''

        self.assertEqual(r.crash_signature_addresses(),
                r2.crash_signature_addresses())

        # DB knows about this already
        self.crashes.duplicate_db_publish(self.dupdb_dir)
        self.assertEqual(self.crashes.known(r2), 
                self.crashes.get_comment_url(r, r_id))

        # if it gets uploaded anyway, duplicate it properly
        r2_id = self.crashes.upload(r2)
        self.assertEqual(self.crashes.check_duplicate(r2_id), (r_id, None))

        # different address signature
        r3 = apport.Report()
        r3['SourcePackage'] = 'bash'
        r3['Package'] = 'bash 5'
        r3['ExecutablePath'] = '/bin/bash'
        r3['Signal'] = '11'

        r3['ProcMaps'] = '''
00400000-004df000 r-xp 00000000 08:02 1044485                            /bin/bash
5f491fa8f000-5f491fc24000 r-xp 00000000 08:02 522605                     /lib/x86_64-linux-gnu/libc-2.13.so
'''

        r3['Stacktrace'] = '''
#0  0x00005f491fac5687 in kill ()
#1  0x000000000042eb76 in ?? ()
#2  0x0000000000432401 in ??
#3  0x00000000004707e3 in parse_and_execute ()
#4  0x000000000041d703 in _start ()
'''
        self.assertNotEqual(r.crash_signature_addresses(),
                r3.crash_signature_addresses())
        self.crashes.duplicate_db_publish(self.dupdb_dir)
        self.assertEqual(self.crashes.known(r3), None)

        # pretend that we went through retracing and r and r3 are actually
        # dupes; temporarily add a signature here to convince check_duplicate()
        self.crashes.init_duplicate_db(':memory:')
        r['DuplicateSignature'] = 'moo'
        r3['DuplicateSignature'] = 'moo'
        r_id = self.crashes.upload(r)
        self.assertEqual(self.crashes.check_duplicate(r_id), None)
        r3_id = self.crashes.upload(r3)
        self.assertEqual(self.crashes.check_duplicate(r3_id), (r_id, None))
        del r['DuplicateSignature']
        del r3['DuplicateSignature']

        # now both r and r3 address sigs should be known as r_id
        self.crashes.duplicate_db_publish(self.dupdb_dir)
        self.assertEqual(self.crashes.known(r), 
                self.crashes.get_comment_url(r, r_id))
        self.assertEqual(self.crashes.known(r3), 
                self.crashes.get_comment_url(r3, r_id))

        # changing ID also works on address signatures
        self.crashes.duplicate_db_change_master_id(r_id, r3_id)
        self.crashes.duplicate_db_publish(self.dupdb_dir)
        self.assertEqual(self.crashes.known(r), 
                self.crashes.get_comment_url(r, r3_id))
        self.assertEqual(self.crashes.known(r3), 
                self.crashes.get_comment_url(r3, r3_id))

        # removing an ID also works for address signatures
        self.crashes.duplicate_db_remove(r3_id)
        self.crashes.duplicate_db_publish(self.dupdb_dir)
        self.assertEqual(self.crashes.known(r), None)
        self.assertEqual(self.crashes.known(r3), None)

        self.assertEqual(self.crashes._duplicate_db_dump(), {})

    def test_change_master_id(self):
        '''duplicate_db_change_master_id()'''

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

    def test_db_corruption(self):
        '''Detection of DB file corruption'''

        try:
            (fd, db) = tempfile.mkstemp()
            os.close(fd)
            self.crashes.init_duplicate_db(db)
            self.assertEqual(self.crashes.check_duplicate(0), None)
            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, None)})
            self.crashes.duplicate_db_fixed(0, '42')
            self.assertEqual(self.crashes._duplicate_db_dump(), 
                {self.crashes.download(0).crash_signature(): (0, '42')})

            del self.crashes

            # damage file
            f = open(db, 'r+')
            f.truncate(os.path.getsize(db)*2/3)
            f.close()

            self.crashes = CrashDatabase(None, {})
            self.assertRaises(Exception, self.crashes.init_duplicate_db, db)

        finally:
            os.unlink(db)

if __name__ == '__main__':
    import tempfile, shutil
    unittest.main()
