import copy
import os.path
import shutil
import tempfile
import textwrap
import unittest

import apport
from apport.crashdb_impl.memory import CrashDatabase


class T(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp()
        self.dupdb_dir = os.path.join(self.workdir, 'dupdb')
        self.crashes = CrashDatabase(None, {'dummy_data': '1',
                                            'dupdb_url': 'file://' + self.dupdb_dir})

        self.assertEqual(self.crashes.get_comment_url(self.crashes.download(0), 0),
                         'http://foo.bugs.example.com/0')

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
        crashdb_conf = tempfile.NamedTemporaryFile(mode='w+')
        crashdb_conf.write(
            textwrap.dedent(
                '''\
                default = 'testsuite'

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
                '''
            )
        )
        crashdb_conf.flush()

        db = apport.crashdb.get_crashdb(None, None, crashdb_conf.name)
        self.assertEqual(db.options['dyn_option'], '4')
        db = apport.crashdb.get_crashdb(None, 'on_thefly', crashdb_conf.name)
        self.assertFalse('dyn_opion' in db.options)
        self.assertEqual(db.options['whoami'], 'dynname')

    def test_accepts_default(self):
        '''accepts(): default configuration'''

        # by default crash DBs accept any type
        self.assertTrue(self.crashes.accepts(apport.Report('Crash')))
        self.assertTrue(self.crashes.accepts(apport.Report('Bug')))
        self.assertTrue(self.crashes.accepts(apport.Report('weirdtype')))

    def test_accepts_problem_types(self):
        '''accepts(): problem_types option in crashdb.conf'''

        # create a crash DB with type limits
        crashdb_conf = tempfile.NamedTemporaryFile(mode='w+')
        crashdb_conf.write(
            textwrap.dedent(
                '''\
                default = 'testsuite'

                databases = {
                    'testsuite': {
                        'impl': 'memory',
                        'problem_types': ['Bug', 'Kernel'],
                    },
                }
                '''
            )
        )
        crashdb_conf.flush()

        db = apport.crashdb.get_crashdb(None, None, crashdb_conf.name)

        self.assertTrue(db.accepts(apport.Report('Bug')))
        self.assertFalse(db.accepts(apport.Report('Crash')))
        self.assertFalse(db.accepts(apport.Report('weirdtype')))

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
        self.assertEqual(self.crashes.reports[3]['comment'], '')

        # check DB consistency; #1 and #4 are dupes and do not appear
        self.assertEqual(self.crashes._duplicate_db_dump(),
                         {self.crashes.download(0).crash_signature(): (0, None),
                          self.crashes.download(2).crash_signature(): (2, None),
                          self.crashes.download(3).crash_signature(): (3, None)})

        # now mark the python crash as fixed
        self.crashes.reports[3]['fixed_version'] = '4.1'

        # ID#4 is dup of ID#3, but happend in version 5 -> regression
        self.crashes.close_duplicate(self.crashes.download(4), 4, None)  # reset
        self.assertEqual(self.crashes.check_duplicate(4), None)
        self.assertEqual(self.crashes.duplicate_of(4), None)
        self.assertEqual(self.crashes.reports[4]['comment'], 'regression, already fixed in #3')

        # check DB consistency; ID#4 is a regression, thus appears as the new
        # master bug for the sig of 3/4
        self.assertEqual(self.crashes._duplicate_db_dump(),
                         {self.crashes.download(0).crash_signature(): (0, None),
                          self.crashes.download(2).crash_signature(): (2, None),
                          self.crashes.download(3).crash_signature(): (4, None)})

        # add two more  Python crash dups and verify that they are dup'ed
        # to the correct ID
        r = copy.copy(self.crashes.download(3))
        self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
                         'http://pygoo.bugs.example.com/5')
        self.assertEqual(self.crashes.check_duplicate(5), (3, '4.1'))
        self.assertEqual(self.crashes.duplicate_of(5), 3)
        # not marked as regression, happened earlier than #3
        self.assertEqual(self.crashes.reports[5]['comment'], '')

        r = copy.copy(self.crashes.download(3))
        r['Package'] = 'python-goo 5.1'
        self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
                         'http://pygoo.bugs.example.com/6')
        self.assertEqual(self.crashes.check_duplicate(6), (4, None))
        self.assertEqual(self.crashes.duplicate_of(6), 4)
        # not marked as regression, as it's now a dupe of new master bug 4
        self.assertEqual(self.crashes.reports[6]['comment'], '')

        # check DB consistency; #5 and #6 are dupes of #3 and #4, so no new
        # entries
        self.assertEqual(self.crashes._duplicate_db_dump(),
                         {self.crashes.download(0).crash_signature(): (0, None),
                          self.crashes.download(2).crash_signature(): (2, None),
                          self.crashes.download(3).crash_signature(): (4, None)})

        # check with unknown fixed version
        self.crashes.reports[3]['fixed_version'] = ''
        self.crashes.duplicate_db_fixed(3, '')

        r = copy.copy(self.crashes.download(3))
        r['Package'] = 'python-goo 5.1'
        self.assertEqual(self.crashes.get_comment_url(r, self.crashes.upload(r)),
                         'http://pygoo.bugs.example.com/7')
        self.assertEqual(self.crashes.check_duplicate(7), (3, ''))
        # not marked as regression
        self.assertEqual(self.crashes.reports[6]['comment'], '')

        # final consistency check
        self.assertEqual(self.crashes._duplicate_db_dump(),
                         {self.crashes.download(0).crash_signature(): (0, None),
                          self.crashes.download(2).crash_signature(): (2, None),
                          self.crashes.download(3).crash_signature(): (4, None)})

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

        self.crashes.duplicate_db_publish(self.dupdb_dir)

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
        self.assertEqual(self.crashes.check_duplicate(2, self.crashes.download(1)),
                         (0, None))

    def test_check_duplicate_multiple_masters(self):
        '''check_duplicate() with multiple master bugs

        Due to the unavoidable jitter in gdb stack traces, it can happen that a
        bug B has the same symbolic signature as a bug S, but the same address
        signature as a bug A, where A and S have slightly different symbolic
        and address signatures and thus were not identified as duplicates. In
        that case we want the lowest ID to become the new master bug, and the
        other two duplicates.
        '''
        a = apport.Report()
        a['SourcePackage'] = 'bash'
        a['Package'] = 'bash 5'
        a.crash_signature = lambda: '/bin/bash:11:read:main'
        a.crash_signature_addresses = lambda: '/bin/bash:11:/lib/libc.so+123:/bin/bash+DEAD'
        self.assertEqual(self.crashes.get_comment_url(a, self.crashes.upload(a)),
                         'http://bash.bugs.example.com/5')

        s = apport.Report()
        s['SourcePackage'] = 'bash'
        s['Package'] = 'bash 5'
        s.crash_signature = lambda: '/bin/bash:11:__getch:read:main'
        s.crash_signature_addresses = lambda: '/bin/bash:11:/lib/libc.so+BEEF:/lib/libc.so+123:/bin/bash+DEAD'
        self.assertEqual(self.crashes.get_comment_url(s, self.crashes.upload(s)),
                         'http://bash.bugs.example.com/6')

        # same addr sig as a, same symbolic sig as s
        b = apport.Report()
        b['SourcePackage'] = 'bash'
        b['Package'] = 'bash 5'
        b.crash_signature = lambda: '/bin/bash:11:__getch:read:main'
        b.crash_signature_addresses = lambda: '/bin/bash:11:/lib/libc.so+123:/bin/bash+DEAD'
        self.assertEqual(self.crashes.get_comment_url(b, self.crashes.upload(b)),
                         'http://bash.bugs.example.com/7')

        self.crashes.init_duplicate_db(':memory:')
        self.assertEqual(self.crashes.check_duplicate(5, a), None)

        # a and s have slightly different sigs -> no dupe
        self.assertEqual(self.crashes.check_duplicate(6, s), None)

        # now throw the interesting b at it
        self.assertEqual(self.crashes.check_duplicate(7, b), (5, None))

        # s and b should now be duplicates of a
        self.assertEqual(self.crashes.duplicate_of(5), None)
        self.assertEqual(self.crashes.duplicate_of(6), 5)
        self.assertEqual(self.crashes.duplicate_of(7), 5)

        # sig DB should only have a now
        self.assertEqual(self.crashes._duplicate_db_dump(), {'/bin/bash:11:read:main': (5, None)})

        # addr DB should have both possible patterns on a
        self.assertEqual(self.crashes._duplicate_search_address_signature(b.crash_signature_addresses()), 5)
        self.assertEqual(self.crashes._duplicate_search_address_signature(s.crash_signature_addresses()), 5)

    def test_known_address_sig(self):
        '''known() for address signatures'''

        self.crashes.init_duplicate_db(':memory:')

        r = apport.Report()
        r['SourcePackage'] = 'bash'
        r['Package'] = 'bash 5'
        r['ExecutablePath'] = '/bin/bash'
        r['Signal'] = '11'
        r['ProcMaps'] = (
            '00400000-004df000 r-xp 00000000 08:02 1044485                    '
            '        /bin/bash\n'
            '7f491fa8f000-7f491fc24000 r-xp 00000000 08:02 522605             '
            '        /lib/x86_64-linux-gnu/libc-2.13.so\n'
        )
        r['Stacktrace'] = textwrap.dedent(
            '''\
            #0  0x00007f491fac5687 in kill ()
            #1  0x000000000042eb76 in ?? ()
            #2  0x00000000004324d8 in ??
            #3  0x00000000004707e3 in parse_and_execute ()
            #4  0x000000000041d703 in _start ()
            '''
        )

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
        r2['ProcMaps'] = (
            '00400000-004df000 r-xp 00000000 08:02 1044485                    '
            '        /bin/bash\n'
            '5f491fa8f000-5f491fc24000 r-xp 00000000 08:02 522605             '
            '        /lib/x86_64-linux-gnu/libc-2.13.so\n'
        )
        r2['Stacktrace'] = textwrap.dedent(
            '''\
            #0  0x00005f491fac5687 in kill ()
            #1  0x000000000042eb76 in ?? ()
            #2  0x00000000004324d8 in ??
            #3  0x00000000004707e3 in parse_and_execute ()
            #4  0x000000000041d703 in _start ()
            '''
        )

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
        r3['ProcMaps'] = (
            '00400000-004df000 r-xp 00000000 08:02 1044485                    '
            '        /bin/bash\n'
            '5f491fa8f000-5f491fc24000 r-xp 00000000 08:02 522605             '
            '        /lib/x86_64-linux-gnu/libc-2.13.so\n'
        )
        r3['Stacktrace'] = textwrap.dedent(
            '''\
            #0  0x00005f491fac5687 in kill ()
            #1  0x000000000042eb76 in ?? ()
            #2  0x0000000000432401 in ??
            #3  0x00000000004707e3 in parse_and_execute ()
            #4  0x000000000041d703 in _start ()
            '''
        )
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

    def test_duplicate_db_publish_long_sigs(self):
        '''duplicate_db_publish() with very long signatures'''

        self.crashes.init_duplicate_db(':memory:')

        # give #0 a long symbolic sig which needs lots of quoting
        symb = self.crashes.download(0)
        symb.crash_signature = lambda: 's+' * 1000

        # and #1 a long addr sig
        addr = self.crashes.download(1)
        addr.crash_signature_addresses = lambda: '0x1+/' * 1000

        self.assertEqual(self.crashes.known(symb), None)
        self.assertEqual(self.crashes.check_duplicate(0), None)
        self.assertEqual(self.crashes.known(addr), None)
        self.assertEqual(self.crashes.check_duplicate(1), None)

        self.crashes.duplicate_db_publish(self.dupdb_dir)
        self.assertEqual(self.crashes.known(symb), 'http://foo.bugs.example.com/0')
        self.assertEqual(self.crashes.known(addr), 'http://foo.bugs.example.com/1')

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
            f.truncate(int(os.path.getsize(db) * 2 / 3))
            f.close()

            self.crashes = CrashDatabase(None, {})
            self.assertRaises(Exception, self.crashes.init_duplicate_db, db)

        finally:
            os.unlink(db)
