'''Crash database implementation for Launchpad.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import urllib, tempfile, shutil, os.path, re, gzip, os

import launchpadBugs.storeblob
from launchpadBugs.HTMLOperations import Bug, BugList
from launchpadBugs.BughelperError import LPUrlError

import apport.crashdb
import apport

arch_tag_map = {
    'i386': 'need-i386-retrace',
    'i686': 'need-i386-retrace',
    'x86_64': 'need-amd64-retrace',
    'ppc': 'need-powerpc-retrace',
    'ppc64': 'need-powerpc-retrace',
}

def get_source_component(distro, package):
    '''Return the component of given source package in the latest release of
    given distribution.'''

    result = urllib.urlopen('https://launchpad.net/%s/+source/%s' % (distro, package)).read()
    m = re.search('<td>Published</td>.*?<td>.*?<td>.*?<td>(\w+)</td>', result, re.S)
    if not m:
        raise ValueError, 'source package %s does not exist in %s' % (package, distro)
    return m.group(1)

class _Struct:
    '''Convenience class for creating on-the-fly anonymous objects.'''

    def __init__(self, **entries): 
        self.__dict__.update(entries)

class CrashDatabase(apport.crashdb.CrashDatabase):
    '''Launchpad implementation of crash database interface.'''

    def __init__(self, cookie_file, bugpattern_baseurl, options):
        '''Initialize Launchpad crash database connection. 
        
        You need to specify a Mozilla-style cookie file for download() and
        update(). For upload() and get_comment_url() you can use None.'''

        apport.crashdb.CrashDatabase.__init__(self, cookie_file,
            bugpattern_baseurl, options)

        self.distro = options['distro']
        self.arch_tag = arch_tag_map[os.uname()[4]]

	# FIXME: do an authenticated Bug() call to initialize cookie handler in
	# p-lp-bugs; after that, BugList will return private bugs, too
	try:
	    self.download(2)
	except LPUrlError:
	    pass

    def upload(self, report):
        '''Upload given problem report return a handle for it. 
        
        This should happen noninteractively.'''

        # set reprocessing tags
        hdr = {}
        hdr['Tags'] = 'apport-%s' % report['ProblemType'].lower()
        if report.has_key('CoreDump') and report.has_key('PackageArchitecture'):
            a = report['PackageArchitecture']
            if a != 'all':
                hdr['Tags'] += ' need-%s-retrace' % a
        # set dup checking tag for Python crashes
        elif report.has_key('Traceback'):
            hdr['Tags'] += ' need-duplicate-check'

        # write MIME/Multipart version into temporary file
        mime = tempfile.TemporaryFile()
        report.write_mime(mime, extra_headers=hdr)
        mime.flush()
        mime.seek(0)

        ticket = launchpadBugs.storeblob.upload(mime)
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
            return 'https://launchpad.net/%s/+source/%s/+filebug/%s?%s' % (
                self.distro, report['SourcePackage'], handle, urllib.urlencode(args))
        else:
            return 'https://launchpad.net/%s/+filebug/%s?%s' % (
                self.distro, handle, urllib.urlencode(args))

    def download(self, id):
        '''Download the problem report from given ID and return a Report.'''

        report = apport.Report()
        attachment_dir = tempfile.mkdtemp()
        try:
            b = Bug(id, None, attachment_dir, ['application/x-gzip'],
                'Dependencies.txt|CoreDump.gz|ProcMaps.txt|Traceback.txt',
                cookie_file=self.auth_file)

            for att in b.attachments:
                if not att.filename:
                    continue # ignored attachments

                key = os.path.splitext(os.path.basename(att.filename))[0]

                if att.filename.endswith('.txt'):
                    report[key] = open(att.filename).read()
                elif att.filename.endswith('.gz'):
                    report[key] = gzip.open(att.filename).read()
                else:
                    raise Exception, 'Unknown attachment type: ' + att.filename

            # parse out other fields from summary
            for m in re.finditer('^([a-zA-Z]+): (.*)<', b.text, re.M):
                report[m.group(1)] = m.group(2)

            return report
        finally:
            shutil.rmtree(attachment_dir)

    def update(self, id, report, comment = ''):
        '''Update the given report ID with the retraced results from the report
        (Stacktrace, ThreadStacktrace, StacktraceTop; also Disassembly if
        desired) and an optional comment.'''

        bug = Bug(id, cookie_file=self.auth_file)

        comment += '\n\nStacktraceTop:' + report['StacktraceTop'].decode('utf-8',
            'replace').encode('utf-8')

        # we need properly named files here, otherwise they will be displayed
        # as '<fdopen>'
        tmpdir = tempfile.mkdtemp()
        try:
            t = open(os.path.join(tmpdir, 'Stacktrace.txt'), 'w+')
            t.write(report['Stacktrace'])
            t.flush()
            t.seek(0)
            bug.add_comment('Symbolic stack trace', comment, t, 
                'Stacktrace.txt (retraced)')
            t.close()

            t = open(os.path.join(tmpdir, 'ThreadStacktrace.txt'), 'w+')
            t.write(report['ThreadStacktrace'])
            t.flush()
            t.seek(0)
            bug.add_comment('Symbolic threaded stack trace', '', t, 
                'ThreadStacktrace.txt (retraced)')
            t.close()

            if report.has_key('StacktraceSource'):
                t = open(os.path.join(tmpdir, 'StacktraceSource.txt'), 'w+')
                t.write(report['StacktraceSource'])
                t.flush()
                t.seek(0)
                bug.add_comment('Stack trace with source code', '', t, 
                    'StacktraceSource.txt')
                t.close()
        finally:
            shutil.rmtree(tmpdir)

        # remove core dump if stack trace is usable
        if report.crash_signature():
            bug.delete_attachment('^CoreDump.gz$')

    def get_distro_release(self, id):
        '''Get 'DistroRelease: <release>' from the given report ID and return
        it.'''

        dr = re.compile('DistroRelease: ([-a-zA-Z0-9.+/ ]+)')
        for line in urllib.urlopen('https://launchpad.net/bugs/' + str(id)):
            m = dr.search(line)
            if m:
                return m.group(1)
        else:
            raise ValueError, 'URL does not contain DistroRelease: field'

    def get_unretraced(self):
        '''Return an ID set of all crashes which have not been retraced yet and
        which happened on the current host architecture.'''

        result = set()
        for b in BugList(_Struct(url = 'https://launchpad.net/ubuntu/+bugs?field.tag=' + 
            self.arch_tag, upstream = None, tag=None, minbug = None, 
            filterbug = None, status = '', importance = '', closed_bugs=None,
            duplicates = None, lastcomment = None)).bugs:
            # BugList returns a set of strings, which is bad set-wise, so we
            # have to convert them to ints.
            result.add(int(b))
        return result

    def get_dup_unchecked(self):
        '''Return an ID set of all crashes which have not been checked for
        being a duplicate.

        This is mainly useful for crashes of scripting languages such as
        Python, since they do not need to be retraced. It should not return
        bugs that are covered by get_unretraced().'''

        result = set()
        for b in BugList(_Struct(url = 'https://launchpad.net/ubuntu/+bugs?field.tag=need-duplicate-check',
            upstream = None, tag=None, minbug = None, 
            filterbug = None, status = '', importance = '', closed_bugs=None,
            duplicates = None, lastcomment = None)).bugs:
            result.add(int(b))
        return result

    def get_unfixed(self):
        '''Return an ID set of all crashes which are not yet fixed.

        The list must not contain bugs which were rejected or duplicate.
        
        This function should make sure that the returned list is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).'''

        result = set()
        for b in BugList(_Struct(url = 'https://launchpad.net/ubuntu/+bugs?field.tag=apport', 
            upstream = None, minbug = None, filterbug = None, status = '',
            importance = '', lastcomment = '', tag = None, closed_bugs=None,
	    duplicates=None)).bugs:
            result.add(int(b))
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

        # do not do version tracking yet; for that, we need to get the current
        # distrorelease and the current package version in that distrorelease
        # (or, of course, proper version tracking in Launchpad itself)
        try:
            b = Bug(id)
        except LPUrlError, e:
            if e.value.startswith('Page not found'):
                return 'invalid'
            else:
                raise

        if b.status == 'Fix Released':
            return ''
        if b.status == 'Rejected' or b.duplicate_of:
            return 'invalid'
        return None

    def close_duplicate(self, id, master):
        '''Mark a crash id as duplicate of given master ID.'''

        bug = Bug(id, cookie_file=self.auth_file)
        bug.mark_duplicate(master)

    def mark_regression(self, id, master):
        '''Mark a crash id as reintroducing an earlier crash which is
        already marked as fixed (having ID 'master').'''
        
        bug = Bug(id, cookie_file=self.auth_file)
        bug.add_comment('Possible regression detected', 
            'This crash has the same stack trace characteristics as bug #%i. \
However, the latter was already fixed in an earlier package version than the \
one in this report. This might be a regression or because the problem \
in a dependent package.' % master)

    def mark_retraced(self, id):
        '''Mark crash id as retraced.'''

        b = Bug(id, cookie_file=self.auth_file)
        b.get_metadata()
        if self.arch_tag in b.tags:
            b.tags.remove(self.arch_tag)
            b.set_metadata()

    def mark_retrace_failed(self, id):
        '''Mark crash id as 'failed to retrace'.'''

        b = Bug(id, cookie_file=self.auth_file)
        b.get_metadata()
        if 'apport-failed-retrace' not in b.tags:
            b.tags.append('apport-failed-retrace')
            b.set_metadata()

    def _mark_dup_checked(self, id, report):
        '''Mark crash id as checked for being a duplicate.'''

        b = Bug(id, cookie_file=self.auth_file)
        b.get_metadata()
        if 'need-duplicate-check' in b.tags:
            b.tags.remove('need-duplicate-check')
            b.set_metadata()

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

#c.mark_regression(89040, 1)
#c.close_duplicate(89040, 1)
#c.mark_retrace_failed(89040)

#print c.get_unfixed()
#print '89040', c.get_fixed_version(89040)
#print '114036', c.get_fixed_version(114036)
#print '116026', c.get_fixed_version(116026)
#print '118955 (dup)', c.get_fixed_version(118955)
#print '999999 (N/E)', c.get_fixed_version(999999)
