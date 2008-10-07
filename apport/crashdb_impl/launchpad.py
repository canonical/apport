'''Crash database implementation for Launchpad.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import urllib, tempfile, shutil, os.path, re, gzip
from cStringIO import StringIO

import launchpadbugs.storeblob
import launchpadbugs.connector as Connector

import apport.crashdb
import apport

Bug = Connector.ConnectBug()
BugList = Connector.ConnectBugList()

def get_source_version(distro, package):
    '''Return the version of given source package in the latest release of
    given distribution.'''

    result = urllib.urlopen('https://launchpad.net/%s/+source/%s' % (distro, package)).read()
    m = re.search('href="/%s/\w+/\+source/%s/([^"]+)"' % (distro, re.escape(package)), result)
    if not m:
        raise ValueError, 'source package %s does not exist in %s' % (package, distro)
    return m.group(1)

class CrashDatabase(apport.crashdb.CrashDatabase):
    '''Launchpad implementation of crash database interface.'''

    def __init__(self, cookie_file, bugpattern_baseurl, options):
        '''Initialize Launchpad crash database connection. 
        
        You need to specify a Mozilla-style cookie file for download() and
        update(). For upload() and get_comment_url() you can use None.'''

        apport.crashdb.CrashDatabase.__init__(self, cookie_file,
            bugpattern_baseurl, options)

        self.distro = options['distro']
        self.arch_tag = 'need-%s-retrace' % apport.packaging.get_system_architecture()

        if cookie_file:
            Bug.authentication = cookie_file
            BugList.authentication = cookie_file

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
        attachment_path = tempfile.mkdtemp()
        Bug.content_types.append('application/x-gzip')
        try:
            b = Bug(id) 

            # parse out fields from summary
            m = re.search(r"(ProblemType:.*)$", b.description_raw, re.S)
            if not m:
                m = re.search(r"^--- \r?$[\r\n]*(.*)", b.description_raw, re.M | re.S)
            assert m, 'bug description must contain standard apport format data'

            description = m.group(1).replace("\xc2\xa0", " ")
            
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
                    "Dependencies.txt|CoreDump.gz|ProcMaps.txt|Traceback.txt",
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
        if report.crash_signature():
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
        bug = Bug(url='https://launchpad.net/bugs/' + str(id))
        m = re.search('DistroRelease: ([-a-zA-Z0-9.+/ ]+)', bug.description)
        if m:
            return m.group(1)
        raise ValueError, 'URL does not contain DistroRelease: field'

    def get_unretraced(self):
        '''Return an ID set of all crashes which have not been retraced yet and
        which happened on the current host architecture.'''

        bugs = BugList('https://bugs.launchpad.net/ubuntu/+bugs?field.tag=' + self.arch_tag)
        return set(int(i) for i in bugs)

    def get_dup_unchecked(self):
        '''Return an ID set of all crashes which have not been checked for
        being a duplicate.

        This is mainly useful for crashes of scripting languages such as
        Python, since they do not need to be retraced. It should not return
        bugs that are covered by get_unretraced().'''

        bugs = BugList('https://bugs.launchpad.net/ubuntu/+bugs?field.tag=need-duplicate-check')
        return set(int(i) for i in bugs)

    def get_unfixed(self):
        '''Return an ID set of all crashes which are not yet fixed.

        The list must not contain bugs which were rejected or duplicate.
        
        This function should make sure that the returned list is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).'''

        bugs = BugList('https://bugs.launchpad.net/ubuntu/+bugs?field.tag=apport-crash')
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
                    return get_source_version(self.distro, b.sourcepackage)
                except ValueError:
                    return '' # broken bug
            return ''
        if b.status == 'Rejected' or b.duplicate_of:
            return 'invalid'
        return None

    def close_duplicate(self, id, master):
        '''Mark a crash id as duplicate of given master ID.'''

        bug = Bug(id)

        # check whether the master itself is a dup
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

    def mark_retrace_failed(self, id):
        '''Mark crash id as 'failed to retrace'.'''

        b = Bug(id)
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

# some test code for future usage:

#c = CrashDatabase('/home/martin/txt/lp-apport.cookie', '', {'distro': 'ubuntu'})

#r=c.download(89040)
#r['StacktraceTop'] = 'This is an invalid test StacktraceTop\nYes, Really!\nfoo'
#r['Stacktrace'] = 'long\ntrace'
#r['ThreadStacktrace'] = 'thread\neven longer\ntrace'

#c.update(89040, r, 'arbitrary comment\nhere.')

#t=c.upload(r)
#print 'ticket:', t
#print c.get_comment_url(r, t)

#c.mark_regression(89040, 116026)
#c.close_duplicate(89040, 116026)
#c.mark_retrace_failed(89040)

#print c.get_unfixed()
#print '89040', c.get_fixed_version(89040)
#print '114036', c.get_fixed_version(114036)
#print '116026', c.get_fixed_version(116026)
#print '118955 (dup)', c.get_fixed_version(118955)
#print '999999 (N/E)', c.get_fixed_version(999999)
