'''Crash database implementation for Launchpad.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import urllib, tempfile, shutil, os.path, re, gzip, sys
from cStringIO import StringIO

import launchpadbugs.storeblob
import launchpadbugs.connector as Connector

import apport.crashdb
import apport

Bug = Connector.ConnectBug()
BugList = Connector.ConnectBugList()

def get_source_version(distro, package, hostname):
    '''Return the version of given source package in the latest release of
    given distribution.

    If 'distro' is None, we will look for a launchpad project . 
    '''

    if distro:
        result = urllib.urlopen('https://%s/%s/+source/%s' % (hostname, distro, package)).read()
        m = re.search('href="/%s/\w+/\+source/%s/([^"]+)"' % (distro, re.escape(package)), result)
        if not m:
            raise ValueError, 'source package %s does not exist in %s' % (package, distro)
    else:
        # non distro packages
        result = urllib.urlopen('https://%s/%s/+series' % (hostname, package)).read()
        m = re.search('href="/%s/([^"]+)"' % (re.escape(package)), result)
        if not m:
            raise ValueError, 'Series for %s does not exist in Launchpad' % (package)
        
    return m.group(1)

class CrashDatabase(apport.crashdb.CrashDatabase):
    '''Launchpad implementation of crash database interface.'''

    def __init__(self, cookie_file, bugpattern_baseurl, options):
        '''Initialize Launchpad crash database connection. 
        
        You need to specify a Mozilla-style cookie file for download() and
        update(). For upload() and get_comment_url() you can use None.'''

        apport.crashdb.CrashDatabase.__init__(self, cookie_file,
            bugpattern_baseurl, options)

        self.distro = options.get('distro')
        self.arch_tag = 'need-%s-retrace' % apport.packaging.get_system_architecture()
        self.options = options
        self.cookie_file = cookie_file

        if self.options.get('staging', False):
            from launchpadbugs.lpconstants import HTTPCONNECTION
            Bug.set_connection_mode(HTTPCONNECTION.MODE.STAGING)
            BugList.set_connection_mode(HTTPCONNECTION.MODE.STAGING)
            self.hostname = 'staging.launchpad.net'
        else:
            self.hostname = 'launchpad.net'

        if self.cookie_file:
            Bug.authentication = self.cookie_file
            BugList.authentication = self.cookie_file

    def upload(self, report, progress_callback = None):
        '''Upload given problem report return a handle for it. 
        
        This should happen noninteractively. 
        
        If the implementation supports it, and a function progress_callback is
        passed, that is called repeatedly with two arguments: the number of
        bytes already sent, and the total number of bytes to send. This can be
        used to provide a proper upload progress indication on frontends.'''

        # set reprocessing tags
        hdr = {}
        hdr['Tags'] = 'apport-%s' % report['ProblemType'].lower()
        # append tags defined in the report
        if report.has_key('Tags'):
            hdr['Tags'] += ' ' + report['Tags']
        a = report.get('PackageArchitecture')
        if not a or a == 'all':
            a = report.get('Architecture')
        if a:
            hdr['Tags'] += ' ' + a
        if 'CoreDump' in report and a:
            hdr['Tags'] += ' need-%s-retrace' % a
            # FIXME: ugly Ubuntu specific hack until LP has a real crash db
            if report['DistroRelease'].split()[0] == 'Ubuntu':
                hdr['Private'] = 'yes'
                hdr['Subscribers'] = 'apport'
        # set dup checking tag for Python crashes
        elif report.has_key('Traceback'):
            hdr['Tags'] += ' need-duplicate-check'
            # FIXME: ugly Ubuntu specific hack until LP has a real crash db
            if report['DistroRelease'].split()[0] == 'Ubuntu':
                hdr['Private'] = 'yes'
                hdr['Subscribers'] = 'apport'

        # write MIME/Multipart version into temporary file
        mime = tempfile.TemporaryFile()
        report.write_mime(mime, extra_headers=hdr, skip_keys=['Date'])
        mime.flush()
        mime.seek(0)

        ticket = launchpadbugs.storeblob.upload(mime, progress_callback, 
                staging=self.options.get('staging', False))
        assert ticket
        return ticket

    def get_comment_url(self, report, handle):
        '''Return an URL that should be opened after report has been uploaded
        and upload() returned handle.

        Should return None if no URL should be opened (anonymous filing without
        user comments); in that case this function should do whichever
        interactive steps it wants to perform.'''

        args = {}
        title = report.standard_title()
        if title:
            args['field.title'] = title
        
        if not report.has_key('ThirdParty'):
            if report.has_key('SourcePackage'):
                return 'https://bugs.%s/%s/+source/%s/+filebug/%s?%s' % (
                    self.hostname, self.distro, report['SourcePackage'], handle, urllib.urlencode(args))
            else:
                return 'https://bugs.%s/%s/+filebug/%s?%s' % (
                    self.hostname, self.distro, handle, urllib.urlencode(args))
        else:
            assert report.has_key('SourcePackage')
            return 'https://bugs.%s/%s/+filebug/%s?%s' % (
                self.hostname, report['SourcePackage'], handle, urllib.urlencode(args))

    def download(self, id):
        '''Download the problem report from given ID and return a Report.'''

        report = apport.Report()
        attachment_path = tempfile.mkdtemp()
        Bug.content_types.append('application/x-gzip')
        try:
            b = Bug(id) 

            # parse out fields from summary
            m = re.search(r"(ProblemType:.*)$", b.description_raw, re.S)
            if not m:
                m = re.search(r"^--- \r?$[\r\n]*(.*)", b.description_raw, re.M | re.S)
            assert m, 'bug description must contain standard apport format data'

            description = m.group(1).replace('\xc2\xa0', ' ')

            if '\r\n\r\n' in description:
                # this often happens, remove all empty lines between top and
                # "Uname"
                if 'Uname:' in description:
                    # this will take care of bugs like LP #315728 where stuff
                    # is added after the apport data
                    (part1, part2) = description.split('Uname:', 1)
                    description = part1.replace('\r\n\r\n', '\r\n') + 'Uname:' \
                        + part2.split('\r\n\r\n', 1)[0]
                else:
                    description = description.replace('\r\n\r\n', '\r\n')

            report.load(StringIO(description))

            report['Date'] = b.date.ctime()
            if 'ProblemType' not in report:
                if 'apport-bug' in b.tags:
                    report['ProblemType'] = 'Bug'
                elif 'apport-crash' in b.tags:
                    report['ProblemType'] = 'Crash'
                elif 'apport-kernelcrash' in b.tags:
                    report['ProblemType'] = 'KernelCrash'
                elif 'apport-package' in b.tags:
                    report['ProblemType'] = 'Package'
                else:
                    raise ValueError, 'cannot determine ProblemType from tags: ' + str(b.tags)

            for att in b.attachments.filter(lambda a: re.match(
                    'Dependencies.txt|CoreDump.gz|ProcMaps.txt|Traceback.txt|DpkgTerminalLog.txt',
                    a.lp_filename)):

                key = os.path.splitext(att.lp_filename)[0]
                
                att.download(os.path.join(attachment_path, att.lp_filename))
                if att.lp_filename.endswith('.txt'):
                    report[key] = att.text
                elif att.lp_filename.endswith('.gz'):
                    report[key] = gzip.GzipFile(fileobj=StringIO(att.text)).read()#TODO: is this the best solution?
                else:
                    raise Exception, 'Unknown attachment type: ' + att.lp_filename

            return report
        finally:
            shutil.rmtree(attachment_path)

    def update(self, id, report, comment = ''):
        '''Update the given report ID with the retraced results from the report
        (Stacktrace, ThreadStacktrace, StacktraceTop; also Disassembly if
        desired) and an optional comment.'''

        bug = Bug(id)

        comment += '\n\nStacktraceTop:' + report['StacktraceTop'].decode('utf-8',
            'replace').encode('utf-8')

        # we need properly named files here, otherwise they will be displayed
        # as '<fdopen>'
        tmpdir = tempfile.mkdtemp()
        t = {}
        try:
            t[0] = open(os.path.join(tmpdir, 'Stacktrace.txt'), 'w+')
            t[0].write(report['Stacktrace'])
            t[0].flush()
            t[0].seek(0)
            att = Bug.NewAttachment(localfileobject=t[0],
                    description='Stacktrace.txt (retraced)')
            new_comment = Bug.NewComment(subject='Symbolic stack trace',
                    text=comment, attachment=att)
            bug.comments.add(new_comment)

            t[1] = open(os.path.join(tmpdir, 'ThreadStacktrace.txt'), 'w+')
            t[1].write(report['ThreadStacktrace'])
            t[1].flush()
            t[1].seek(0)
            att = Bug.NewAttachment(localfileobject=t[1],
                    description='ThreadStacktrace.txt (retraced)')
            new_comment = Bug.NewComment(subject='Symbolic threaded stack trace',
                    attachment=att)
            bug.comments.add(new_comment)

            if report.has_key('StacktraceSource'):
                t[2] = open(os.path.join(tmpdir, 'StacktraceSource.txt'), 'w+')
                t[2].write(report['StacktraceSource'])
                t[2].flush()
                t[2].seek(0)
                att = Bug.NewAttachment(localfileobject=t[2],
                        description='StacktraceSource.txt')
                new_comment = Bug.NewComment(subject='Stack trace with source code',
                        attachment=att)
                bug.comments.add(new_comment)

            if report.has_key('SourcePackage') and bug.sourcepackage == 'ubuntu':
                bug.set_sourcepackage(report['SourcePackage'])
        finally:
            shutil.rmtree(tmpdir)

        # remove core dump if stack trace is usable
        if report.has_useful_stacktrace():
            bug.attachments.remove(
                    func=lambda a: re.match('^CoreDump.gz$', a.lp_filename or a.description))
            bug.importance='Medium'
        bug.commit()
        for x in t.itervalues():
            x.close()
        self._subscribe_triaging_team(bug, report)

    def get_distro_release(self, id):
        '''Get 'DistroRelease: <release>' from the given report ID and return
        it.'''
        #using py-lp-bugs
        bug = Bug(url='https://%s/bugs/%s' % (self.hostname, str(id)))
        m = re.search('DistroRelease: ([-a-zA-Z0-9.+/ ]+)', bug.description)
        if m:
            return m.group(1)
        raise ValueError, 'URL does not contain DistroRelease: field'

    def get_unretraced(self):
        '''Return an ID set of all crashes which have not been retraced yet and
        which happened on the current host architecture.'''

        bugs = BugList('https://bugs.%s/ubuntu/+bugs?field.tag=%s' % (self.hostname, self.arch_tag))
        return set(int(i) for i in bugs)

    def get_dup_unchecked(self):
        '''Return an ID set of all crashes which have not been checked for
        being a duplicate.

        This is mainly useful for crashes of scripting languages such as
        Python, since they do not need to be retraced. It should not return
        bugs that are covered by get_unretraced().'''

        bugs = BugList('https://bugs.%s/ubuntu/+bugs?field.tag=need-duplicate-check&batch=300' % self.hostname)
        return set(int(i) for i in bugs)

    def get_unfixed(self):
        '''Return an ID set of all crashes which are not yet fixed.

        The list must not contain bugs which were rejected or duplicate.
        
        This function should make sure that the returned list is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).'''

        bugs = BugList('https://bugs.%s/ubuntu/+bugs?field.tag=apport-crash&batch=300' % self.hostname)
        return set(int(i) for i in bugs)

    def get_fixed_version(self, id):
        '''Return the package version that fixes a given crash.

        Return None if the crash is not yet fixed, or an empty string if the
        crash is fixed, but it cannot be determined by which version. Return
        'invalid' if the crash report got invalidated, such as closed a
        duplicate or rejected.

        This function should make sure that the returned result is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).'''

        # do not do version tracking yet; for that, we need to get the current
        # distrorelease and the current package version in that distrorelease
        # (or, of course, proper version tracking in Launchpad itself)
        try:
            b = Bug(id)
        except Bug.Error.LPUrlError, e:
            if e.value.startswith('Page not found'):
                return 'invalid'
            else:
                raise

        if b.status == 'Fix Released':
            if b.sourcepackage:
                try:
                    return get_source_version(self.distro, b.sourcepackage, self.hostname)
                except ValueError:
                    return '' # broken bug
            return ''
        if b.status == 'Invalid' or b.duplicate_of:
            return 'invalid'
        return None

    def duplicate_of(self, id):
        '''Return master ID for a duplicate bug.

        If the bug is not a duplicate, return None.
        '''
        b =  Bug(id)
        return b.duplicate_of

    def close_duplicate(self, id, master):
        '''Mark a crash id as duplicate of given master ID.
        
        If master is None, id gets un-duplicated.
        '''
        bug = Bug(id)

        # check whether the master itself is a dup
        if master:
            m = Bug(master)
            if m.duplicate_of:
                master = m.duplicate_of

            bug.attachments.remove(
                func=lambda a: re.match('^(CoreDump.gz$|Stacktrace.txt|ThreadStacktrace.txt|\
Dependencies.txt$|ProcMaps.txt$|ProcStatus.txt$|Registers.txt$|\
Disassembly.txt$)', a.lp_filename))
            if bug.private:
                bug.private = None
            bug.commit()

            # set duplicate last, since we cannot modify already dup'ed bugs
            bug = Bug(id)
            bug.duplicate_of = int(master)
        else:
            bug.duplicate_of = None
        bug.commit()

    def mark_regression(self, id, master):
        '''Mark a crash id as reintroducing an earlier crash which is
        already marked as fixed (having ID 'master').'''
        
        bug = Bug(id)
        comment = Bug.NewComment(subject='Possible regression detected',
            text='This crash has the same stack trace characteristics as bug #%i. \
However, the latter was already fixed in an earlier package version than the \
one in this report. This might be a regression or because the problem is \
in a dependent package.' % master)
        bug.comments.add(comment)
        bug.tags.append('regression-retracer')
        bug.commit()

    def mark_retraced(self, id):
        '''Mark crash id as retraced.'''

        b = Bug(id)
        if self.arch_tag in b.tags:
            b.tags.remove(self.arch_tag)
        b.commit()

    def mark_retrace_failed(self, id, invalid_msg=None):
        '''Mark crash id as 'failed to retrace'.'''

        b = Bug(id)
        if invalid_msg:
            comment = Bug.NewComment(subject='Crash report cannot be processed',
                text=invalid_msg)
            b.comments.add(comment)
            b.status = 'Invalid'

            b.attachments.remove(
                func=lambda a: re.match('^(CoreDump.gz$|Stacktrace.txt|ThreadStacktrace.txt|\
Dependencies.txt$|ProcMaps.txt$|ProcStatus.txt$|Registers.txt$|\
Disassembly.txt$)', a.lp_filename))
        else:
            if 'apport-failed-retrace' not in b.tags:
                b.tags.append('apport-failed-retrace')
        b.commit()

    def _mark_dup_checked(self, id, report):
        '''Mark crash id as checked for being a duplicate.'''

        b = Bug(id)
        if 'need-duplicate-check' in b.tags:
            b.tags.remove('need-duplicate-check')
        
        self._subscribe_triaging_team(b, report)
        b.commit()

    def _subscribe_triaging_team(self, bug, report):
        '''Subscribe the right triaging team to the bug.'''

        #FIXME: this entire function is an ugly Ubuntu specific hack until LP
        #gets a real crash db; see https://wiki.ubuntu.com/CrashReporting

        if report['DistroRelease'].split()[0] != 'Ubuntu':
            return # only Ubuntu bugs are filed private

        try:
            bug.subscriptions.add('ubuntu-crashes-universe')
        except ValueError:
            # already subscribed
            pass

#
# Unit tests
#

if __name__ == '__main__':
    import unittest, urllib2, cookielib

    crashdb = None
    segv_report = None
    python_report = None

    class _Tests(unittest.TestCase):
        # this assumes that a source package "coreutils" exists and builds a
        # binary package "coreutils"
        test_package = 'coreutils'
        test_srcpackage = 'coreutils'
        known_test_id = 89040
        known_test_id2 = 302779

        #
        # Generic tests, should work for all CrashDB implementations
        #

        def setUp(self):
            global crashdb
            if not crashdb:
                crashdb = self._get_instance()
            self.crashdb = crashdb

            # create a local reference report so that we can compare
            # DistroRelease, Architecture, etc.
            self.ref_report = apport.Report()
            self.ref_report.add_os_info()
            self.ref_report.add_user_info()

        def _file_segv_report(self):
            '''File a SEGV crash report.

            Return crash ID.
            '''
            r = apport.report._ApportReportTest._generate_sigsegv_report()
            r.add_package_info(self.test_package)
            r.add_os_info()
            r.add_gdb_info()
            r.add_user_info()
            self.assertEqual(r.standard_title(), 'crash crashed with SIGSEGV in f()')

            handle = self.crashdb.upload(r)
            self.assert_(handle)
            url = self.crashdb.get_comment_url(r, handle)
            self.assert_(url)

            id = self._fill_bug_form(url)
            self.assert_(id > 0)
            return id

        def test_1_report_segv(self):
            '''upload() and get_comment_url() for SEGV crash
            
            This needs to run first, since it sets segv_report.
            '''
            global segv_report
            id = self._file_segv_report()
            segv_report = id
            print >> sys.stderr, '(https://staging.launchpad.net/bugs/%i) ' % id,

        def test_1_report_python(self):
            '''upload() and get_comment_url() for Python crash
            
            This needs to run early, since it sets python_report.
            '''
            r = apport.Report('Crash')
            r['ExecutablePath'] = '/bin/foo'
            r['Traceback'] = '''Traceback (most recent call last):
  File "/bin/foo", line 67, in fuzz
    print weird
NameError: global name 'weird' is not defined'''
            r.add_package_info(self.test_package)
            r.add_os_info()
            r.add_user_info()
            self.assertEqual(r.standard_title(), 'foo crashed with NameError in fuzz()')

            handle = self.crashdb.upload(r)
            self.assert_(handle)
            url = self.crashdb.get_comment_url(r, handle)
            self.assert_(url)

            id = self._fill_bug_form(url)
            self.assert_(id > 0)
            global python_report
            python_report = id
            print >> sys.stderr, '(https://staging.launchpad.net/bugs/%i) ' % id,

        def test_2_download(self):
            '''download()'''

            r = self.crashdb.download(segv_report)
            self.assertEqual(r['ProblemType'], 'Crash')
            self.assertEqual(r['DistroRelease'], self.ref_report['DistroRelease'])
            self.assertEqual(r['Architecture'], self.ref_report['Architecture'])
            self.assertEqual(r['Uname'], self.ref_report['Uname'])
            self.assertEqual(r.get('NonfreeKernelModules'),
                self.ref_report.get('NonfreeKernelModules'))
            self.assertEqual(r.get('UserGroups'), self.ref_report.get('UserGroups'))

            self.assertEqual(r['Signal'], '11')
            self.assert_(r['ExecutablePath'].endswith('/crash'))
            self.assertEqual(r['SourcePackage'], self.test_srcpackage)
            self.assert_(r['Package'].startswith(self.test_package + ' '))
            self.assert_('f (x=42)' in r['Stacktrace'])
            self.assert_('f (x=42)' in r['StacktraceTop'])
            self.assert_(len(r['CoreDump']) > 1000)
            self.assert_('Dependencies' in r)

        def test_3_update(self):
            '''update()'''

            r = self.crashdb.download(segv_report)

            # updating with an useless stack trace retains core dump
            r['StacktraceTop'] = '?? ()'
            r['Stacktrace'] = 'long\ntrace'
            r['ThreadStacktrace'] = 'thread\neven longer\ntrace'
            self.crashdb.update(segv_report, r, 'I can has a better retrace?')
            r = self.crashdb.download(segv_report)
            self.assert_('CoreDump' in r)

            # updating with an useful stack trace removes core dump
            r['StacktraceTop'] = 'read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so'
            r['Stacktrace'] = 'long\ntrace'
            r['ThreadStacktrace'] = 'thread\neven longer\ntrace'
            self.crashdb.update(segv_report, r, 'good retrace!')
            r = self.crashdb.download(segv_report)
            self.failIf('CoreDump' in r)

        def test_get_distro_release(self):
            '''get_distro_release()'''

            self.assertEqual(self.crashdb.get_distro_release(segv_report),
                    self.ref_report['DistroRelease'])

        def test_duplicates(self):
            '''duplicate handling'''

            # initially we have no dups
            self.assertEqual(self.crashdb.duplicate_of(segv_report), None)
            self.assertEqual(self.crashdb.get_fixed_version(segv_report), None)

            # dupe our segv_report and check that it worked; then undupe it
            self.crashdb.close_duplicate(segv_report, self.known_test_id)
            self.assertEqual(self.crashdb.duplicate_of(segv_report), self.known_test_id)
            self.assertEqual(self.crashdb.get_fixed_version(segv_report), 'invalid')
            self.crashdb.close_duplicate(segv_report, None)
            self.assertEqual(self.crashdb.duplicate_of(segv_report), None)
            self.assertEqual(self.crashdb.get_fixed_version(segv_report), None)

            # this should have removed attachments
            r = self.crashdb.download(segv_report)
            self.failIf('CoreDump' in r)

            # now try duplicating to a duplicate bug; this should automatically
            # transition to the master bug
            self.crashdb.close_duplicate(self.known_test_id,
                    self.known_test_id2)
            self.crashdb.close_duplicate(segv_report, self.known_test_id)
            self.assertEqual(self.crashdb.duplicate_of(segv_report),
                    self.known_test_id2)

            self.crashdb.close_duplicate(self.known_test_id, None)
            self.crashdb.close_duplicate(self.known_test_id2, None)
            self.crashdb.close_duplicate(segv_report, None)

        def test_marking_segv(self):
            '''processing status markings for signal crashes'''

            # mark_retraced()
            unretraced_before = self.crashdb.get_unretraced()
            self.assert_(segv_report in unretraced_before)
            self.failIf(python_report in unretraced_before)
            self.crashdb.mark_retraced(segv_report)
            unretraced_after = self.crashdb.get_unretraced()
            self.failIf(segv_report in unretraced_after)
            self.assertEqual(unretraced_before,
                    unretraced_after.union(set([segv_report])))
            self.assertEqual(self.crashdb.get_fixed_version(segv_report), None)

            # mark_retrace_failed()
            self._mark_needs_retrace(segv_report)
            self.crashdb.mark_retraced(segv_report)
            self.crashdb.mark_retrace_failed(segv_report)
            unretraced_after = self.crashdb.get_unretraced()
            self.failIf(segv_report in unretraced_after)
            self.assertEqual(unretraced_before,
                    unretraced_after.union(set([segv_report])))
            self.assertEqual(self.crashdb.get_fixed_version(segv_report), None)

            # mark_retrace_failed() of invalid bug
            self._mark_needs_retrace(segv_report)
            self.crashdb.mark_retraced(segv_report)
            self.crashdb.mark_retrace_failed(segv_report, "I don't like you")
            unretraced_after = self.crashdb.get_unretraced()
            self.failIf(segv_report in unretraced_after)
            self.assertEqual(unretraced_before,
                    unretraced_after.union(set([segv_report])))
            self.assertEqual(self.crashdb.get_fixed_version(segv_report),
                    'invalid')

        def test_marking_python(self):
            '''processing status markings for interpreter crashes'''

            unchecked_before = self.crashdb.get_dup_unchecked()
            self.assert_(python_report in unchecked_before)
            self.failIf(segv_report in unchecked_before)
            self.crashdb._mark_dup_checked(python_report, self.ref_report)
            unchecked_after = self.crashdb.get_dup_unchecked()
            self.failIf(python_report in unchecked_after)
            self.assertEqual(unchecked_before,
                    unchecked_after.union(set([python_report])))
            self.assertEqual(self.crashdb.get_fixed_version(python_report),
                    None)

        def test_update_invalid(self):
            '''updating a invalid crash
            
            This simulates a race condition where a crash being processed gets
            invalidated by marking it as a duplicate.
            '''
            id = self._file_segv_report()
            print >> sys.stderr, '(https://staging.launchpad.net/bugs/%i) ' % id,

            r = self.crashdb.download(id)

            self.crashdb.close_duplicate(id, segv_report)

            # updating with an useful stack trace removes core dump
            r['StacktraceTop'] = 'read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so'
            r['Stacktrace'] = 'long\ntrace'
            r['ThreadStacktrace'] = 'thread\neven longer\ntrace'
            self.crashdb.update(id, r, 'good retrace!')

            r = self.crashdb.download(id)
            self.failIf('CoreDump' in r)

        #
        # Launchpad specific implementation and tests
        #

        @classmethod
        def _get_instance(klass):
            '''Create a CrashDB instance'''

            return CrashDatabase(os.path.expanduser('~/.lpcookie.txt'), 
                    '', {'distro': 'ubuntu', 'staging': True})

        def _fill_bug_form(self, url):
            '''Fill bug form and commit the bug.

            Return the report ID.
            '''
            cj = cookielib.MozillaCookieJar()
            cj.load(self.crashdb.cookie_file)
            opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))

            re_pkg = re.compile('<input type="text" value="([^"]+)" id="field.packagename"')
            re_title = re.compile('<input.*id="field.title".*value="([^"]+)"')
            re_tags = re.compile('<input.*id="field.tags".*value="([^"]+)"')

            # parse default field values from reporting page
            url = url.replace('+filebug/', '+filebug-advanced/')
            
            res = opener.open(url)
            self.assertEqual(res.getcode(), 200)
            content = res.read()

            m_pkg = re_pkg.search(content)
            m_title = re_title.search(content)
            m_tags = re_tags.search(content)

            # strip off GET arguments from URL
            url = url.split('?')[0]

            # create request to file bug
            args = {
                'packagename_option': 'choose',
                'field.packagename': m_pkg.group(1),
                'field.title': m_title.group(1),
                'field.tags': m_tags.group(1),
                'field.comment': 'ZOMG!',
                'field.actions.submit_bug': '1',
            }

            res = opener.open(url, data=urllib.urlencode(args))
            self.assertEqual(res.getcode(), 200)
            self.assert_('+source/%s/+bug/' % m_pkg.group(1) in res.geturl())
            id = res.geturl().split('/')[-1]
            return int(id)

        def _mark_needs_retrace(self, id):
            '''Mark a report ID as needing retrace.'''

            b = Bug(id)
            if self.crashdb.arch_tag not in b.tags:
                b.tags.append(self.crashdb.arch_tag)
            b.commit()

        def _mark_needs_dupcheck(self, id):
            '''Mark a report ID as needing duplicate check.'''

            b = Bug(id)
            if 'need-duplicate-check' not in b.tags:
                b.tags.append('need-duplicate-check')
            b.commit()

    unittest.main()
