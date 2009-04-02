'''Crash database implementation for Launchpad.

Copyright (C) 2007, 2009 Canonical Ltd.
Authors: Martin Pitt <martin.pitt@ubuntu.com> and Markus Korn <thekorn@gmx.de>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import urllib, tempfile, atexit, shutil, os.path, re, gzip, sys
from cStringIO import StringIO

from launchpadlib.errors import HTTPError
from launchpadlib.launchpad import Launchpad, STAGING_SERVICE_ROOT, EDGE_SERVICE_ROOT
from launchpadlib.credentials import Credentials

import apport.crashdb
import apport

default_credentials_path = os.path.expanduser('~/.cache/apport/launchpad.credentials')

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
    

class CrashDatabase(apport.crashdb.CrashDatabase):
    '''Launchpad implementation of crash database interface.'''

    def __init__(self, auth, bugpattern_baseurl, options):
        '''Initialize Launchpad crash database. 
        
        You need to specify a launchpadlib-style credentials file to
        access launchpad. If you supply None, it will use
        default_credentials_path (~/.cache/apport/launchpad.credentials).
        '''
        if not auth:
            if options.get('staging'):
                auth = default_credentials_path + '.staging'
            else:
                auth = default_credentials_path
        apport.crashdb.CrashDatabase.__init__(self, auth,
            bugpattern_baseurl, options)

        self.distro = options.get('distro')
        self.arch_tag = 'need-%s-retrace' % apport.packaging.get_system_architecture()
        self.options = options
        self.auth = auth
        assert self.auth

        self.__launchpad = None
        self.__lp_distro = None
        
    @property
    def launchpad(self):
        '''Return Launchpad instance.'''

        if self.__launchpad:
            return self.__launchpad

        cache_dir = tempfile.mkdtemp()
        atexit.register(shutil.rmtree, cache_dir)
        if self.options.get('staging'):
            launchpad_instance = STAGING_SERVICE_ROOT
        else:
            launchpad_instance = EDGE_SERVICE_ROOT

        auth_dir = os.path.dirname(self.auth)
        if not os.path.isdir(auth_dir):
            os.makedirs(auth_dir)

        if os.path.exists(self.auth):
            # use existing credentials
            credentials = Credentials()
            credentials.load(open(self.auth))
            self.__launchpad = Launchpad(credentials, launchpad_instance, cache_dir)
        else:
            # get credentials and save them
            try:
                self.__launchpad = Launchpad.get_token_and_login('apport-collect',
                        launchpad_instance, cache_dir)
            except launchpadlib.errors.HTTPError, e:
                print >> sys.stderr, 'Error connecting to Launchpad: %s\nYou have to allow "Change anything" privileges.' % str(e)
                sys.exit(1)
            f = open(self.auth, 'w')
            os.chmod(self.auth, 0600)
            self.__launchpad.credentials.save(f)
            f.close()

        return self.__launchpad

    def _get_distro_tasks(self, tasks):
        if not self.distro:
            raise StopIteration

        for t in tasks:
            if t.bug_target_name.lower() == self.distro or \
                    re.match('^.+\(%s.*\)$' % self.distro, t.bug_target_name.lower()):
                yield t
    
    @property
    def lp_distro(self):
        if not self.distro:
            return None
        if self.__lp_distro is None:
            self.__lp_distro = self.launchpad.distributions[self.distro]
        return self.__lp_distro

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

        ticket = upload_blob(mime, progress_callback,
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

        project = self.options.get('project')
        if 'ThirdParty' in report:
            project = report['SourcePackage']
        
        if not project:
            if report.has_key('SourcePackage'):
                return 'https://bugs.%s/%s/+source/%s/+filebug/%s?%s' % (
                    hostname, self.distro, report['SourcePackage'], handle, urllib.urlencode(args))
            else:
                return 'https://bugs.%s/%s/+filebug/%s?%s' % (
                    hostname, self.distro, handle, urllib.urlencode(args))
        else:
            return 'https://bugs.%s/%s/+filebug/%s?%s' % (
                hostname, project, handle, urllib.urlencode(args))

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

        # ensure it's assigned to the right package
        if report.has_key('SourcePackage') and \
                '+source' not in str(bug.bug_tasks[0].target):
            try:
                bug.bug_tasks[0].transitionToTarget(target=
                        self.lp_distro.getSourcePackage(name=report['SourcePackage']))
            except HTTPError:
                pass # LP#342355 workaround

        # remove core dump if stack trace is usable
        if report.has_useful_stacktrace():
            for a in bug.attachments:
                if a.title == 'CoreDump.gz':
                    try:
                        a.removeFromBug()
                    except HTTPError:
                        pass # LP#315387 workaround
            try:
                task = self._get_distro_tasks(bug.bug_tasks).next()
                task.transitionToImportance(importance='Medium')
            except StopIteration:
                pass # no distro tasks
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
        bugs = self.lp_distro.searchTasks(tags=self.arch_tag)
        return id_set(bugs)

    def get_dup_unchecked(self):
        '''Return an ID set of all crashes which have not been checked for
        being a duplicate.

        This is mainly useful for crashes of scripting languages such as
        Python, since they do not need to be retraced. It should not return
        bugs that are covered by get_unretraced().'''
        
        bugs = self.lp_distro.searchTasks(tags='need-duplicate-check')
        return id_set(bugs)

    def get_unfixed(self):
        '''Return an ID set of all crashes which are not yet fixed.

        The list must not contain bugs which were rejected or duplicate.
        
        This function should make sure that the returned list is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).'''
        
        bugs = self.lp_distro.searchTasks(tags='apport-crash')
        return id_set(bugs)

    def _get_source_version(self, package):
        '''Return the version of given source package in the latest release of
        given distribution.

        If 'distro' is None, we will look for a launchpad project . 
        '''
        sources = self.lp_distro.main_archive.getPublishedSources(
            exact_match=True,
            source_name=package,
            distro_series=self.lp_distro.current_series
        )
        # first element is the latest one
        return sources[0].source_package_version

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
            b = self.launchpad.bugs[id]
        except KeyError:
            return 'invalid'
            
        if b.duplicate_of:
            return 'invalid'

        tasks = list(b.bug_tasks) # just fetch it once

        if self.distro:
            distro_identifier = '(%s)' %self.distro.lower()
            fixed_tasks = filter(lambda task: task.status == 'Fix Released' and \
                    distro_identifier in task.bug_target_display_name.lower(), tasks)
            
            if not fixed_tasks:
                fixed_distro = filter(lambda task: task.status == 'Fix Released' and \
                        task.bug_target_name.lower() == self.distro.lower(), tasks)
                if fixed_distro:
                    # fixed in distro inself (without source package)
                    return ''
                
            assert len(fixed_tasks) <= 1, 'There is more than one task fixed in %s' % self.distro

            if fixed_tasks:
                task = fixed_tasks.pop()
                return self._get_source_version(task.bug_target_display_name.split()[0])

            # check if there any invalid ones
            if filter(lambda task: task.status == 'Invalid' and \
                    distro_identifier in task.bug_target_display_name.lower(), tasks):
                return 'invalid'
        else:
            fixed_tasks = filter(lambda task: task.status == 'Fix Released',
                    tasks)
            if fixed_tasks:
                # TODO: look for current series
                return ''
            # check if there any invalid ones
            if filter(lambda task: task.status == 'Invalid', tasks):
                return 'invalid'

        return None

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
                        pass # LP#315387 workaround

            bug = self.launchpad.bugs[id] # refresh, LP#336866 workaround
            if bug.private:
                bug.private = False

            # set duplicate last, since we cannot modify already dup'ed bugs
            if not bug.duplicate_of:
                bug.duplicate_of = master
        else:
            if bug.duplicate_of:
                bug.duplicate_of = None

        if bug._dirty_attributes: # LP#336866 workaround
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
        bug.tags = bug.tags + ['regression-retracer'] # LP#254901 workaround
        bug.lp_save()

    def mark_retraced(self, id):
        '''Mark crash id as retraced.'''

        bug = self.launchpad.bugs[id]
        if self.arch_tag in bug.tags:
            x = bug.tags[:] # LP#254901 workaround
            x.remove(self.arch_tag)
            bug.tags = x
            bug.lp_save()

    def mark_retrace_failed(self, id, invalid_msg=None):
        '''Mark crash id as 'failed to retrace'.'''

        bug = self.launchpad.bugs[id]
        if invalid_msg:
            try:
                task = self._get_distro_tasks(bug.bug_tasks).next()
            except StopIteration:
                # no distro task, just use the first one
                task = bug.bug_tasks[0]
            task.transitionToStatus(status='Invalid')
            bug.newMessage(content=invalid_msg,
                    subject='Crash report cannot be processed')
#            b.attachments.remove(
#                func=lambda a: re.match('^(CoreDump.gz$|Stacktrace.txt|ThreadStacktrace.txt|\
#Dependencies.txt$|ProcMaps.txt$|ProcStatus.txt$|Registers.txt$|\
#Disassembly.txt$)', a.lp_filename))
        else:
            if 'apport-failed-retrace' not in bug.tags:
                bug.tags = bug.tags + ['apport-failed-retrace'] # LP#254901 workaround
                bug.lp_save()

    def _mark_dup_checked(self, id, report):
        '''Mark crash id as checked for being a duplicate.'''

        bug = self.launchpad.bugs[id]
        if 'need-duplicate-check' in bug.tags:
            x = bug.tags[:] # LP#254901 workaround
            x.remove('need-duplicate-check')
            bug.tags = x
            bug.lp_save()        
        self._subscribe_triaging_team(bug, report)

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
# Launchpad storeblob API (should go into launchpadlib, see LP #315358)
#

import multipartpost_handler, urllib2, time, httplib

_https_upload_callback = None

#
# This progress code is based on KodakLoader by Jason Hildebrand
# <jason@opensky.ca>. See http://www.opensky.ca/~jdhildeb/software/kodakloader/
# for details.
class HTTPSProgressConnection(httplib.HTTPSConnection):
    '''Implement a HTTPSConnection with an optional callback function for
    upload progress.'''

    def send(self, data):
        global _https_upload_callback

        # if callback has not been set, call the old method
        if not _https_upload_callback:
            httplib.HTTPSConnection.send(self, data)
            return

        sent = 0
        total = len(data)
        chunksize = 1024
        while sent < total:
            _https_upload_callback(sent, total)
            t1 = time.time()
            httplib.HTTPSConnection.send(self, data[sent:sent+chunksize])
            sent += chunksize
            t2 = time.time()

            # adjust chunksize so that it takes between .5 and 2 
            # seconds to send a chunk
            if t2 - t1 < .5:
                chunksize *= 2
            elif t2 - t1 > 2:
                chunksize /= 2

class HTTPSProgressHandler(urllib2.HTTPSHandler):

    def https_open(self, req):
        return self.do_open(HTTPSProgressConnection, req)

def upload_blob(blob, progress_callback = None, staging=False):
    '''Upload blob (file-like object) to Launchpad.

    progress_callback can be set to a function(sent, total) which is regularly
    called with the number of bytes already sent and total number of bytes to
    send. It is called every 0.5 to 2 seconds (dynamically adapted to upload
    bandwidth).

    Return None on error, or the ticket number on success.

    By default this uses the production Launchpad instance. Set staging=True to
    use staging.launchpad.net (for testing).
    '''
    ticket = None

    global _https_upload_callback
    _https_upload_callback = progress_callback

    opener = urllib2.build_opener(HTTPSProgressHandler, multipartpost_handler.MultipartPostHandler)
    if staging:
        url = 'https://staging.launchpad.net/+storeblob'
    else:
        url = 'https://launchpad.net/+storeblob'
    result = opener.open(url,
        { 'FORM_SUBMIT': '1', 'field.blob': blob })
    ticket = result.info().get('X-Launchpad-Blob-Token')

    return ticket

#
# Unit tests
#

if __name__ == '__main__':
    import unittest, urllib2, cookielib

    crashdb = None
    segv_report = None
    python_report = None

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
            self.assert_('f (x=42)' in r['ThreadStacktrace'])
            self.assert_(len(r['CoreDump']) > 1000)
            self.assert_('Dependencies' in r)
            self.assert_('Disassembly' in r)
            self.assert_('Registers' in r)

        def test_3_update(self):
            '''update()'''

            r = self.crashdb.download(segv_report)
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
            self.crashdb.update(segv_report, r, 'I can has a better retrace?')
            r = self.crashdb.download(segv_report)
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
            self.crashdb.update(segv_report, r, 'good retrace!')
            r = self.crashdb.download(segv_report)
            self.failIf('CoreDump' in r)
            self.assert_('Dependencies' in r)
            self.assert_('Disassembly' in r)
            self.assert_('Registers' in r)
            self.assert_('Stacktrace' in r)
            self.assert_('ThreadStacktrace' in r)

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

            # this should be a no-op
            self.crashdb.close_duplicate(segv_report, self.known_test_id)
            self.assertEqual(self.crashdb.duplicate_of(segv_report), self.known_test_id)

            self.assertEqual(self.crashdb.get_fixed_version(segv_report), 'invalid')
            self.crashdb.close_duplicate(segv_report, None)
            self.assertEqual(self.crashdb.duplicate_of(segv_report), None)
            self.assertEqual(self.crashdb.get_fixed_version(segv_report), None)

            # this should have removed attachments; note that Stacktrace is
            # short, and thus inline
            r = self.crashdb.download(segv_report)
            self.failIf('CoreDump' in r)
            self.failIf('Dependencies' in r)
            self.failIf('Disassembly' in r)
            self.failIf('Registers' in r)

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

            # this should be a no-op
            self.crashdb.close_duplicate(self.known_test_id, None)
            self.assertEqual(self.crashdb.duplicate_of(self.known_test_id), None)

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

        def test_get_fixed_version(self):
            '''get_fixed_version() for fixed bugs

            Other cases are already checked in test_marking_segv() (invalid
            bugs) and test_duplicates (duplicate bugs) for efficiency.
            '''
            self._mark_report_fixed(segv_report)
            fixed_ver = self.crashdb.get_fixed_version(segv_report)
            self.assertNotEqual(fixed_ver, None)
            self.assert_(fixed_ver[0].isdigit())
            self._mark_report_new(segv_report)
            self.assertEqual(self.crashdb.get_fixed_version(segv_report), None)

        #
        # Launchpad specific implementation and tests
        #

        @classmethod
        def _get_instance(klass):
            '''Create a CrashDB instance'''

            return CrashDatabase(os.environ.get('LP_CREDENTIALS'), '', 
                    {'distro': 'ubuntu', 'staging': True})

        def _fill_bug_form(self, url):
            '''Fill form for a distro bug and commit the bug.

            Return the report ID.
            '''
            cj = cookielib.MozillaCookieJar()
            cj.load(os.path.expanduser('~/.lpcookie.txt'))
            opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))

            re_pkg = re.compile('<input type="text" value="([^"]+)" id="field.packagename"')
            re_title = re.compile('<input.*id="field.title".*value="([^"]+)"')
            re_tags = re.compile('<input.*id="field.tags".*value="([^"]+)"')

            # parse default field values from reporting page
            url = url.replace('+filebug/', '+filebug-advanced/')
            
            res = opener.open(url)
            try:
                self.assertEqual(res.getcode(), 200)
            except AttributeError:
                pass # getcode() is new in Python 2.6
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
            try:
                self.assertEqual(res.getcode(), 200)
            except AttributeError:
                pass # getcode() is new in Python 2.6
            self.assert_('+source/%s/+bug/' % m_pkg.group(1) in res.geturl())
            id = res.geturl().split('/')[-1]
            return int(id)

        def _fill_bug_form_project(self, url):
            '''Fill form for a project bug and commit the bug.

            Return the report ID.
            '''
            cj = cookielib.MozillaCookieJar()
            cj.load(os.path.expanduser('~/.lpcookie.txt'))
            opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))

            m = re.search('launchpad.net/([^/]+)/\+filebug', url)
            assert m
            project = m.group(1)

            re_title = re.compile('<input.*id="field.title".*value="([^"]+)"')
            re_tags = re.compile('<input.*id="field.tags".*value="([^"]+)"')

            # parse default field values from reporting page
            url = url.replace('+filebug/', '+filebug-advanced/')
            
            res = opener.open(url)
            self.assertEqual(res.getcode(), 200)
            content = res.read()

            m_title = re_title.search(content)
            m_tags = re_tags.search(content)

            # strip off GET arguments from URL
            url = url.split('?')[0]

            # create request to file bug
            args = {
                'field.title': m_title.group(1),
                'field.tags': m_tags.group(1),
                'field.comment': 'ZOMG!',
                'field.actions.submit_bug': '1',
            }

            res = opener.open(url, data=urllib.urlencode(args))
            self.assertEqual(res.getcode(), 200)
            self.assert_(('launchpad.net/%s/+bug' % project) in res.geturl())
            id = res.geturl().split('/')[-1]
            return int(id)

        def _mark_needs_retrace(self, id):
            '''Mark a report ID as needing retrace.'''

            bug = self.crashdb.launchpad.bugs[id]
            if self.crashdb.arch_tag not in bug.tags:
                bug.tags = bug.tags + [self.crashdb.arch_tag]
                bug.lp_save()

        def _mark_needs_dupcheck(self, id):
            '''Mark a report ID as needing duplicate check.'''

            bug = self.crashdb.launchpad.bugs[id]
            if 'need-duplicate-check' not in bug.tags:
                bug.tags = bug.tags + ['need-duplicate-check']
                bug.lp_save()

        def _mark_report_fixed(self, id):
            '''Close a report ID as "fixed".'''

            bug = self.crashdb.launchpad.bugs[id]
            tasks = list(bug.bug_tasks)
            assert len(tasks) == 1
            tasks[0].transitionToStatus(status='Fix Released')

        def _mark_report_new(self, id):
            '''Reopen a report ID as "new".'''

            bug = self.crashdb.launchpad.bugs[id]
            tasks = list(bug.bug_tasks)
            assert len(tasks) == 1
            tasks[0].transitionToStatus(status='New')

        def test_project(self):
            '''reporting crashes against a project instead of a distro'''

            # crash database for langpack-o-matic project (this does not have
            # packages in any distro)
            crashdb = CrashDatabase(os.environ.get('LP_CREDENTIALS'), '', 
                {'project': 'langpack-o-matic', 'staging': True})
            self.assertEqual(crashdb.distro, None)

            # create Python crash report
            r = apport.Report('Crash')
            r['ExecutablePath'] = '/bin/foo'
            r['Traceback'] = '''Traceback (most recent call last):
  File "/bin/foo", line 67, in fuzz
    print weird
NameError: global name 'weird' is not defined'''
            r.add_os_info()
            r.add_user_info()
            self.assertEqual(r.standard_title(), 'foo crashed with NameError in fuzz()')

            # file it
            handle = crashdb.upload(r)
            self.assert_(handle)
            url = crashdb.get_comment_url(r, handle)
            self.assert_('launchpad.net/langpack-o-matic/+filebug' in url)

            id = self._fill_bug_form_project(url)
            self.assert_(id > 0)
            print >> sys.stderr, '(https://staging.launchpad.net/bugs/%i) ' % id,

            # update
            r = crashdb.download(id)
            r['StacktraceTop'] = 'read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so'
            r['Stacktrace'] = 'long\ntrace'
            r['ThreadStacktrace'] = 'thread\neven longer\ntrace'
            crashdb.update(id, r, 'good retrace!')
            r = crashdb.download(id)

            # test fixed version
            self.assertEqual(crashdb.get_fixed_version(id), None)
            crashdb.close_duplicate(id, self.known_test_id)
            self.assertEqual(crashdb.duplicate_of(id), self.known_test_id)
            self.assertEqual(crashdb.get_fixed_version(id), 'invalid')
            crashdb.close_duplicate(id, None)
            self.assertEqual(crashdb.duplicate_of(id), None)
            self.assertEqual(crashdb.get_fixed_version(id), None)

    unittest.main()
