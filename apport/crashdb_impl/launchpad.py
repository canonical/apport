'''Crash database implementation for Launchpad.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''
'''
TODO:
    * missing API:
        - storeblob LP: #315358
        - changing target of task LP #309182
        
    * related bugs
        - setting bug privacy LP #308374
'''

import urllib, tempfile, shutil, os.path, re, gzip
from cStringIO import StringIO

import launchpadbugs.storeblob

import apport.crashdb
import apport
from utils import get_launchpad, HTTPError

CONSUMER = 'apport-collect'

APPORT_FILES = ('Dependencies.txt', 'CoreDump.gz', 'ProcMaps.txt',
        'Traceback.txt', 'Disassembly.txt', 'Registers.txt', 'Stacktrace.txt',
        'ThreadStacktrace.txt')
def filter_filename(attachments):
    for attachment in attachments:
        f = attachment.data.open()
        name = f.filename
        if name in APPORT_FILES:
            yield f
            
def id_set(tasks):
    # same as set(int(i.bug.id) for i in tasks) but faster
    return set(int(i.self_link.split('/').pop()) for i in tasks)
    
def get_distro_tasks(tasks, distro=None):
    distro = distro or 'ubuntu'
    for t in tasks:
        if t.bug_target_name.lower() == distro or \
                re.match('^.+\(%s.*\)$' %distro, t.bug_target_name.lower()):
            yield t
    

def get_source_version(distro, package, launchpad=None):
    '''Return the version of given source package in the latest release of
    given distribution.

    If 'distro' is None, we will look for a launchpad project . 
    '''
    
    if launchpad is None:
        launchpad = get_launchpad(CONSUMER)
    # TODO: look for LP project if distro == None
    distro = launchpad.distributions[distro.lower()]
    sources = distro.main_archive.getPublishedSources(
        exact_match=True,
        source_name=package,
        distro_series=distro.current_series
    )
    # first element is the latest one
    return sources[0].source_package_version

class CrashDatabase(apport.crashdb.CrashDatabase):
    '''Launchpad implementation of crash database interface.'''

    def __init__(self, cookie_file, bugpattern_baseurl, options, cache=None):
        '''Initialize Launchpad crash database connection. 
        
        You need to specify a launchpadlib-style credentials file to
        access launchpad'''
        # TODO: rename cookie_file->credentials_file

        apport.crashdb.CrashDatabase.__init__(self, cookie_file,
            bugpattern_baseurl, options)

        self.distro = options.get('distro')
        self.arch_tag = 'need-%s-retrace' % apport.packaging.get_system_architecture()
        self.options = options
        self.cookie_file = cookie_file

        if cookie_file is None:
            raise RunTimeError
        self.launchpad = get_launchpad(CONSUMER, cred_file=cookie_file)
        self.__ubuntu = None
        
    @property
    def ubuntu(self):
        if self.__ubuntu is None:
            self.__ubuntu = self.launchpad.distributions['ubuntu']
        return self.__ubuntu

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

        if self.options.get('staging'):
            hostname = 'staging.launchpad.net'
        else:
            hostname = 'launchpad.net'
        
        if not report.has_key('ThirdParty'):
            if report.has_key('SourcePackage'):
                return 'https://bugs.%s/%s/+source/%s/+filebug/%s?%s' % (
                    hostname, self.distro, report['SourcePackage'], handle, urllib.urlencode(args))
            else:
                return 'https://bugs.%s/%s/+filebug/%s?%s' % (
                    hostname, self.distro, handle, urllib.urlencode(args))
        else:
            assert report.has_key('SourcePackage')
            return 'https://bugs.%s/%s/+filebug/%s?%s' % (
                hostname, report['SourcePackage'], handle, urllib.urlencode(args))

    def download(self, id):
        '''Download the problem report from given ID and return a Report.'''

        report = apport.Report()
        b = self.launchpad.bugs[id]

        # parse out fields from summary
        m = re.search(r'(ProblemType:.*)$', b.description, re.S)
        if not m:
            m = re.search(r'^--- \r?$[\r\n]*(.*)', b.description, re.M | re.S)
        assert m, 'bug description must contain standard apport format data'

        description = m.group(1).encode('UTF-8').replace('\xc2\xa0', ' ')
        
        if '\r\n\r\n' in description:
            # this often happens, remove all empty lines between top and
            # 'Uname'
            if 'Uname:' in description:
                # this will take care of bugs like LP #315728 where stuff
                # is added after the apport data
                (part1, part2) = description.split('Uname:', 1)
                description = part1.replace('\r\n\r\n', '\r\n') + 'Uname:' \
                    + part2.split('\r\n\r\n', 1)[0]
            else:
                description = description.replace('\r\n\r\n', '\r\n')

        report.load(StringIO(description))

        report['Date'] = b.date_created.ctime()
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

        for attachment in filter_filename(b.attachments):
            key, ext = os.path.splitext(attachment.filename)
            if ext == '.txt':
                report[key] = attachment.read()
            elif ext == '.gz':
                report[key] = gzip.GzipFile(fileobj=attachment).read()#TODO: is this the best solution?
            else:
                raise Exception, 'Unknown attachment type: ' + attachment.filename
        return report

    def update(self, id, report, comment = ''):
        '''Update the given report ID with the retraced results from the report
        (Stacktrace, ThreadStacktrace, StacktraceTop; also Disassembly if
        desired) and an optional comment.'''

        bug = self.launchpad.bugs[id]

        comment += '\n\nStacktraceTop:' + report['StacktraceTop'].decode('utf-8',
            'replace').encode('utf-8')

        # we need properly named files here, otherwise they will be displayed
        # as '<fdopen>'
        bug.addAttachment(comment=comment,
                #content_type=?
                data=report['Stacktrace'],
                description='Stacktrace.txt (retraced)',
                filename='Stacktrace.txt',
                is_patch=False)
                
        bug.addAttachment(comment='', #some other comment here?
                #content_type=?
                data=report['ThreadStacktrace'],
                description='ThreadStacktrace.txt (retraced)',
                filename='ThreadStacktrace.txt',
                is_patch=False)

        if report.has_key('StacktraceSource'):
            bug.addAttachment(comment='', #some other comment here?
                    #content_type=?
                    data=report['StacktraceSource'],
                    description='StacktraceSource.txt',
                    filename='StacktraceSource.txt',
                    is_patch=False)

        #~ if report.has_key('SourcePackage') and bug.sourcepackage == 'ubuntu':
            #~ bug.set_sourcepackage(report['SourcePackage']) #No API -->TODO

        # remove core dump if stack trace is usable
        if report.has_useful_stacktrace():
            for a in bug.attachments:
                if a.title == 'CoreDump.gz':
                    try:
                        a.removeFromBug()
                    except HTTPError:
                        pass # workaround for 404 error, see LP #315387
            try:
                task = get_distro_tasks(bug.bug_tasks).next()
            except StopIteration:
                raise ValueError('no distro taks found')
            task.transitionToImportance(importance='Medium')
        self._subscribe_triaging_team(bug, report)

    def get_distro_release(self, id):
        '''Get 'DistroRelease: <release>' from the given report ID and return
        it.'''
        bug = self.launchpad.bugs[id]
        m = re.search('DistroRelease: ([-a-zA-Z0-9.+/ ]+)', bug.description)
        if m:
            return m.group(1)
        raise ValueError, 'URL does not contain DistroRelease: field'

    def get_unretraced(self):
        '''Return an ID set of all crashes which have not been retraced yet and
        which happened on the current host architecture.'''
        bugs = self.ubuntu.searchTasks(tags=self.arch_tag)
        return id_set(bugs)

    def get_dup_unchecked(self):
        '''Return an ID set of all crashes which have not been checked for
        being a duplicate.

        This is mainly useful for crashes of scripting languages such as
        Python, since they do not need to be retraced. It should not return
        bugs that are covered by get_unretraced().'''
        
        bugs = self.ubuntu.searchTasks(tags='need-duplicate-check')
        return id_set(bugs)

    def get_unfixed(self):
        '''Return an ID set of all crashes which are not yet fixed.

        The list must not contain bugs which were rejected or duplicate.
        
        This function should make sure that the returned list is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).'''
        
        bugs = self.ubuntu.searchTasks(tags='apport-crash')
        return id_set(bugs)

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
        
        #TODO:
        #   * the launchpadlib version does not consider the case of 'rejected' tasks
        #     which status is meant here, did this ever work?
        #   * it is now possible to have multibel fixed task per distro. ATM, this raises an AssertionError
        
        try:
            b = self.launchpad.bugs[id]
        except KeyError:
            return 'invalid'
            
        if b.duplicate_of:
            return 'invalid'
            
        distro_identifier = '(%s)' %self.distro.lower()
        fixed_tasks = filter(lambda task: task.status == 'Fix Released' and \
                distro_identifier in task.bug_target_display_name.lower(), b.bug_tasks)
        
        if not fixed_tasks:
            fixed_distro = filter(lambda task: task.status == 'Fix Released' and \
                    task.bug_target_name.lower() == self.distro.lower(), b.bug_tasks)
            if fixed_distro:
                # fixed in distro inself (without source package)
                return ''
            else:
                # not fixed in distro
                return None
            
        # the version using py-lp-bugs did not consider the following case
        assert len(fixed_tasks) == 1, 'There is more than one task fixed in %s' %self.distro

        task = fixed_tasks.pop()
        
        try:
            return get_source_version(self.distro, task.bug_target_display_name.split()[0])
        except ValueError: #TODO not sure about the error here
            return '' # broken bug

    def duplicate_of(self, id):
        '''Return master ID for a duplicate bug.

        If the bug is not a duplicate, return None.
        '''
        b = self.launchpad.bugs[id].duplicate_of
        if b:
            return b.id
        else:
            return None

    def close_duplicate(self, id, master):
        '''Mark a crash id as duplicate of given master ID.
        
        If master is None, id gets un-duplicated.
        '''
        bug = self.launchpad.bugs[id]

        if master:
            # check whether the master itself is a dup
            master = self.launchpad.bugs[master]
            if master.duplicate_of:
                master = master.duplicate_of
            
            for a in bug.attachments:
                if a.title in ('CoreDump.gz', 'Stacktrace.txt',
                    'ThreadStacktrace.txt', 'Dependencies.txt', 'ProcMaps.txt',
                    'ProcStatus.txt', 'Registers.txt', 'Disassembly.txt'):
                    try:
                        a.removeFromBug()
                    except HTTPError:
                        pass # workaround for 404 error, see LP #315387
            # TODO: bug in API does not allow setting privacy
            #~ if bug.private:
                #~ bug.private = False
                #~ bug.lp_save()

            # set duplicate last, since we cannot modify already dup'ed bugs
            if not bug.duplicate_of:
                bug.duplicate_of = master
                bug.lp_save()
        else:
            if bug.duplicate_of:
                bug.duplicate_of = None
                bug.lp_save()

    def mark_regression(self, id, master):
        '''Mark a crash id as reintroducing an earlier crash which is
        already marked as fixed (having ID 'master').'''
        
        bug = self.launchpad.bugs[id]
        bug.newMessage(content='This crash has the same stack trace characteristics as bug #%i. \
However, the latter was already fixed in an earlier package version than the \
one in this report. This might be a regression or because the problem is \
in a dependent package.' % master,
            subject='Possible regression detected')
        # TODO: workaround LP #254901:
        #   bug.tags.append('regression-retracer')
        # is not working
        bug.tags = bug.tags + ['regression-retracer']
        bug.lp_save()

    def mark_retraced(self, id):
        '''Mark crash id as retraced.'''

        bug = self.launchpad.bugs[id]
        if self.arch_tag in bug.tags:
            # TODO: workaround LP #254901:
            #   bug.tags.remove(self.arch_tag)
            # is not working
            x = bug.tags[:]
            x.remove(self.arch_tag)
            bug.tags = x
            bug.lp_save()

    def mark_retrace_failed(self, id, invalid_msg=None):
        '''Mark crash id as 'failed to retrace'.'''

        bug = self.launchpad.bugs[id]
        if invalid_msg:
            try:
                task = get_distro_tasks(bug.bug_tasks).next()
            except StopIteration:
                raise ValueError('no distro taks found')
            task.transitionToStatus(status='Invalid')
            bug.newMessage(content=invalid_msg,
                    subject='Crash report cannot be processed')
#            b.attachments.remove(
#                func=lambda a: re.match('^(CoreDump.gz$|Stacktrace.txt|ThreadStacktrace.txt|\
#Dependencies.txt$|ProcMaps.txt$|ProcStatus.txt$|Registers.txt$|\
#Disassembly.txt$)', a.lp_filename))
        else:
            if 'apport-failed-retrace' not in bug.tags:
                # TODO: workaround LP #254901:
                #   bug.tags.append('apport-failed-retrace')
                # is not working
                bug.tags = bug.tags + ['apport-failed-retrace']
                bug.lp_save()

    def _mark_dup_checked(self, id, report):
        '''Mark crash id as checked for being a duplicate.'''

        bug = self.launchpad.bugs[id]
        if 'need-duplicate-check' in bug.tags:
            # TODO: workaround LP #254901:
            #   bug.tags.remove('need-duplicate-check')
            # is not working
            x = bug.tags[:]
            x.remove('need-duplicate-check')
            bug.tags = x
            bug.lp_save()        
        self._subscribe_triaging_team(b, report)

    def _subscribe_triaging_team(self, bug, report):
        '''Subscribe the right triaging team to the bug.'''

        #FIXME: this entire function is an ugly Ubuntu specific hack until LP
        #gets a real crash db; see https://wiki.ubuntu.com/CrashReporting

        if report['DistroRelease'].split()[0] != 'Ubuntu':
            return # only Ubuntu bugs are filed private
        
        #use a url hack here, it is faster
        person = '%s~ubuntu-crashes-universe' %self.launchpad._root_uri
        bug.subscribe(person=person)

#
# Unit tests
#

if __name__ == '__main__':
    import unittest, urllib2, cookielib

    crashdb = None
    sigv_report = None

    class _Tests(unittest.TestCase):
        # this assumes that a source package 'coreutils' exists and builds a
        # binary package 'coreutils'
        test_package = 'coreutils'
        test_srcpackage = 'coreutils'
        known_test_id = 302779
        known_test_id2 = 89040

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

        def test_1_report(self):
            '''upload() and get_comment_url()
            
            This needs to run first, since it sets sigv_report.
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
            global sigv_report
            sigv_report = id

        def test_2_download(self):
            '''download()'''

            r = self.crashdb.download(sigv_report)
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
            self.assert_('f (x=42)' in r['ThreadStacktrace'])
            self.assert_(len(r['CoreDump']) > 1000)
            self.assert_('Dependencies' in r)
            self.assert_('Disassembly' in r)
            self.assert_('Registers' in r)

        def test_3_update(self):
            '''update()'''

            r = self.crashdb.download(sigv_report)
            self.assert_('CoreDump' in r)
            self.assert_('Dependencies' in r)
            self.assert_('Disassembly' in r)
            self.assert_('Registers' in r)
            self.assert_('Stacktrace' in r)
            self.assert_('ThreadStacktrace' in r)

            # updating with an useless stack trace retains core dump
            r['StacktraceTop'] = '?? ()'
            r['Stacktrace'] = 'long\ntrace'
            r['ThreadStacktrace'] = 'thread\neven longer\ntrace'
            self.crashdb.update(sigv_report, r, 'I can has a better retrace?')
            r = self.crashdb.download(sigv_report)
            self.assert_('CoreDump' in r)
            self.assert_('Dependencies' in r)
            self.assert_('Disassembly' in r)
            self.assert_('Registers' in r)
            self.assert_('Stacktrace' in r) # TODO: ascertain that it's the updated one
            self.assert_('ThreadStacktrace' in r)

            # updating with an useful stack trace removes core dump
            r['StacktraceTop'] = 'read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so'
            r['Stacktrace'] = 'long\ntrace'
            r['ThreadStacktrace'] = 'thread\neven longer\ntrace'
            self.crashdb.update(sigv_report, r, 'good retrace!')
            r = self.crashdb.download(sigv_report)
            self.failIf('CoreDump' in r)
            self.assert_('Dependencies' in r)
            self.assert_('Disassembly' in r)
            self.assert_('Registers' in r)
            self.assert_('Stacktrace' in r)
            self.assert_('ThreadStacktrace' in r)

        def test_get_distro_release(self):
            '''get_distro_release()'''

            self.assertEqual(self.crashdb.get_distro_release(sigv_report),
                    self.ref_report['DistroRelease'])

        def test_duplicates(self):
            '''duplicate handling'''

            # initially we have no dups
            self.assertEqual(self.crashdb.duplicate_of(sigv_report), None)
            self.assertEqual(self.crashdb.get_fixed_version(sigv_report), None)

            # dupe our sigv_report and check that it worked; then undupe it
            self.crashdb.close_duplicate(sigv_report, self.known_test_id)
            self.assertEqual(self.crashdb.duplicate_of(sigv_report), self.known_test_id)

            # this should be a no-op
            self.crashdb.close_duplicate(sigv_report, self.known_test_id)
            self.assertEqual(self.crashdb.duplicate_of(sigv_report), self.known_test_id)

            self.assertEqual(self.crashdb.get_fixed_version(sigv_report), 'invalid')
            self.crashdb.close_duplicate(sigv_report, None)
            self.assertEqual(self.crashdb.duplicate_of(sigv_report), None)
            self.assertEqual(self.crashdb.get_fixed_version(sigv_report), None)

            # this should have removed attachments; note that Stacktrace is
            # short, and thus inline
            r = self.crashdb.download(sigv_report)
            self.failIf('CoreDump' in r)
            self.failIf('ThreadStacktrace' in r)
            self.failIf('Dependencies' in r)
            self.failIf('Disassembly' in r)
            self.failIf('Registers' in r)

            # now try duplicating to a duplicate bug; this should automatically
            # transition to the master bug
            self.crashdb.close_duplicate(self.known_test_id,
                    self.known_test_id2)
            self.crashdb.close_duplicate(sigv_report, self.known_test_id)
            self.assertEqual(self.crashdb.duplicate_of(sigv_report),
                    self.known_test_id2)

            self.crashdb.close_duplicate(self.known_test_id, None)
            self.crashdb.close_duplicate(self.known_test_id2, None)

            # this should be a no-op
            self.crashdb.close_duplicate(self.known_test_id, None)
            self.assertEqual(self.crashdb.duplicate_of(self.known_test_id), None)

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

    unittest.main()
