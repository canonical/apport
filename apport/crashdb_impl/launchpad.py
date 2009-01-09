'''Crash database implementation for Launchpad.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''
"""
TODO:
    * missing API:
        - storeblob LP: #315358
        - deleting attachments LP #315387
        - changing target of task LP #309182
        
    * related bugs
        - setting bug privacy LP #308374
        - date related data are strings not datetime objects, working
          around this using api_time_parser.parse_time() LP: #309950
        - adding/removing tags LP #254901
        
    * remove all tempfiles (apport does not need local files, correct?)

"""

import urllib, tempfile, shutil, os.path, re, gzip
from cStringIO import StringIO

import launchpadbugs.storeblob

# (thekorn) need this for testing
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import apport.crashdb
import apport
from utils import get_launchpad, HTTPError
from api_time_parser import parse_time

CONSUMER = "apport"

APPORT_FILES = ("Dependencies.txt", "CoreDump.gz", "ProcMaps.txt", "Traceback.txt")
def filter_filename(attachments):
    for attachment in attachments:
        f = attachment.data.open()
        name = f.filename
        if name in APPORT_FILES:
            yield f
            
def id_set(tasks):
    # same as set(int(i.bug.id) for i in tasks) but faster
    return set(int(i.self_link.split("/").pop()) for i in tasks)
    
def get_distro_tasks(tasks, distro=None):
    distro = distro or "ubuntu"
    for t in tasks:
        if t.bug_target_name.lower() == distro or \
                re.match("^.+\(%s.*\)$" %distro, t.bug_target_name.lower()):
            yield t
    

def get_source_version(distro, package, launchpad=None):
    '''Return the version of given source package in the latest release of
    given distribution.'''
    
    if launchpad is None:
        launchpad = get_launchpad(CONSUMER)
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

        self.distro = options['distro']
        self.arch_tag = 'need-%s-retrace' % apport.packaging.get_system_architecture()

        if cookie_file is None:
            raise RunTimeError
        self.launchpad = get_launchpad(CONSUMER, cred_file=cookie_file)
        self.__ubuntu = None
        
    @property
    def ubuntu(self):
        if self.__ubuntu is None:
            self.__ubuntu = self.launchpad.distributions["ubuntu"]
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

        ticket = launchpadbugs.storeblob.upload(mime, progress_callback)
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

        if report.has_key('SourcePackage'):
            return 'https://bugs.launchpad.net/%s/+source/%s/+filebug/%s?%s' % (
                self.distro, report['SourcePackage'], handle, urllib.urlencode(args))
        else:
            return 'https://bugs.launchpad.net/%s/+filebug/%s?%s' % (
                self.distro, handle, urllib.urlencode(args))

    def download(self, id):
        '''Download the problem report from given ID and return a Report.'''

        report = apport.Report()
        attachment_path = tempfile.mkdtemp() #not needed anymore
        try:
            b = self.launchpad.bugs[id]

            # parse out fields from summary
            m = re.search(r"(ProblemType:.*)$", b.description, re.S)
            if not m:
                m = re.search(r"^--- \r?$[\r\n]*(.*)", b.description, re.M | re.S)
            assert m, 'bug description must contain standard apport format data'

            description = m.group(1).encode("UTF-8").replace("\xc2\xa0", " ")
            
            report.load(StringIO(description))

            # Workaroud LP #309950
            date = parse_time(b.date_created)
            report['Date'] = date.ctime()
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
        finally:
            shutil.rmtree(attachment_path)

    def update(self, id, report, comment = ''):
        '''Update the given report ID with the retraced results from the report
        (Stacktrace, ThreadStacktrace, StacktraceTop; also Disassembly if
        desired) and an optional comment.'''

        bug = self.launchpad.bugs[id]

        comment += '\n\nStacktraceTop:' + report['StacktraceTop'].decode('utf-8',
            'replace').encode('utf-8')

        # we need properly named files here, otherwise they will be displayed
        # as '<fdopen>'
        tmpdir = tempfile.mkdtemp()
        try:
            bug.addAttachment(comment=comment,
                    #content_type=?
                    data=report['Stacktrace'],
                    description='Stacktrace.txt (retraced)',
                    filename='Stacktrace.txt',
                    is_patch=False)
                    
            bug.addAttachment(comment="", #some other comment here?
                    #content_type=?
                    data=report['ThreadStacktrace'],
                    description='ThreadStacktrace.txt (retraced)',
                    filename='ThreadStacktrace.txt',
                    is_patch=False)

            if report.has_key('StacktraceSource'):
                bug.addAttachment(comment="", #some other comment here?
                        #content_type=?
                        data=report['StacktraceSource'],
                        description='StacktraceSource.txt',
                        filename='StacktraceSource.txt',
                        is_patch=False)

            #~ if report.has_key('SourcePackage') and bug.sourcepackage == 'ubuntu':
                #~ bug.set_sourcepackage(report['SourcePackage']) #No API -->TODO
        finally:
            shutil.rmtree(tmpdir)

        # remove core dump if stack trace is usable
        if report.crash_signature():
            #~ bug.attachments.remove(
                    #~ func=lambda a: re.match('^CoreDump.gz$', a.lp_filename or a.description))
                    #No API -->TODO
            try:
                task = get_distro_tasks(bug.bug_tasks).next()
            except StopIteration:
                raise ValueError("no distro taks found")
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
        #   * the launchpadlib version does not consider the case of "rejected" tasks
        #     which status is meant here, did this ever work?
        #   * it is now possible to have multibel fixed task per distro. ATM, this raises an AssertionError
        
        try:
            b = self.launchpad.bugs[id]
        except KeyError:
            return 'invalid'
            
        if b.duplicate_of:
            return 'invalid'
            
        distro_identifier = "(%s)" %self.distro.lower()
        fixed_tasks = filter(lambda task: task.status == "Fix Released" and \
                distro_identifier in task.bug_target_display_name.lower(), b.bug_tasks)
        
        if not fixed_tasks:
            fixed_distro = filter(lambda task: task.status == "Fix Released" and \
                    task.bug_target_name.lower() == self.distro.lower(), b.bug_tasks)
            if fixed_distro:
                # fixed in distro inself (without source package)
                return ''
            else:
                # not fixed in distro
                return None
            
        # the version using py-lp-bugs did not consider the following case
        assert len(fixed_tasks) == 1, "There is more than one task fixed in %s" %self.distro

        task = fixed_tasks.pop()
        
        try:
            return get_source_version(self.distro, task.bug_target_display_name.split()[0])
        except ValueError: #TODO not sure about the error here
            return '' # broken bug

    def close_duplicate(self, id, master):
        '''Mark a crash id as duplicate of given master ID.'''

        bug = launchpad.bugs[id]

        # check whether the master itself is a dup
        master = launchpad.bugs[master]
        if master.duplicate_of:
            master = master.duplicate_of
        
        # TODO: removing attachments
        #~ bug.attachments.remove(
            #~ func=lambda a: re.match('^(CoreDump.gz$|Stacktrace.txt|ThreadStacktrace.txt|\
#~ Dependencies.txt$|ProcMaps.txt$|ProcStatus.txt$|Registers.txt$|\
#~ Disassembly.txt$)', a.lp_filename))
        # TODO: bug in API does not allow setting privacy
        #~ if bug.private:
            #~ bug.private = False
            #~ bug.lp_save()

        # set duplicate last, since we cannot modify already dup'ed bugs
        bug.duplicate_of = master
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
                raise ValueError("no distro taks found")
            task.transitionToStatus(status='Invalid')
            bug.newMessage(content=invalid_msg,
                    subject='Crash report cannot be processed')
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
        person = "%s~ubuntu-crashes-universe" %self.launchpad._root_uri
        bug.subscribe(person=person)

# some test code for future usage:

c = CrashDatabase('/home/martin/txt/lp-apport.cookie', '', {'distro': 'ubuntu'})

#~ r=c.download(89040)
#~ r['StacktraceTop'] = 'This is an invalid test StacktraceTop\nYes, Really!\nfoo'
#~ r['Stacktrace'] = 'long\ntrace'
#~ r['ThreadStacktrace'] = 'thread\neven longer\ntrace'
#~ 
#~ c.update(89040, r, 'arbitrary comment\nhere.')

#t=c.upload(r)
#print 'ticket:', t
#print c.get_comment_url(r, t)

#c.mark_regression(89040, 116026)
#c.close_duplicate(89040, 116026)

#c.mark_retrace_failed(89040)
## OR:
#c.mark_retrace_failed(89040, 'not properly frobnicated')

#~ print c.get_unfixed()
print '89040', c.get_fixed_version(89040)
print '114036', c.get_fixed_version(114036)
print '116026', c.get_fixed_version(116026)
print '118955 (dup)', c.get_fixed_version(118955)
print '999999 (N/E)', c.get_fixed_version(999999)
