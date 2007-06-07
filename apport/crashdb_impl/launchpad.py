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

import launchpadBugs.storeblob
from launchpadBugs.HTMLOperations import Bug

import apport.crashdb
import apport

class CrashDatabase(apport.crashdb.CrashDatabase):
    '''Launchpad implementation of crash database interface.'''

    def __init__(self, cookie_file, bugpattern_baseurl, options):
        '''Initialize Launchpad crash database connection. 
        
        You need to specify a Mozilla-style cookie file for download() and
        update(). For upload() and get_comment_url() you can use None.'''

        apport.crashdb.CrashDatabase.__init__(self, cookie_file,
            bugpattern_baseurl, options)

        self.distro = options['distro']

    def upload(self, report):
        '''Upload given problem report return a handle for it. 
        
        This should happen noninteractively.'''

        # set retracing tag
        hdr = {}
        if report.has_key('CoreDump') and report.has_key('PackageArchitecture'):
            a = report['PackageArchitecture']
            if a != 'all':
                hdr['Tags'] = 'apport-%s need-%s-retrace' % (
                    report['ProblemType'].lower(), a)

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
                'Dependencies.txt|CoreDump.gz|ProcMaps.txt',
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

# some test code for future usage:

#from apport.crashdb_launchpad import LaunchpadCrashDatabase as CrashDatabase
#c = CrashDatabase('/home/martin/.mozilla/firefox/ifhuf9go.default/cookies.txt')
#r=c.download(89040)
#r['StacktraceTop'] = 'This is an invalid test StacktraceTop\nYes, Really!\nfoo'
#r['Stacktrace'] = 'long\ntrace'
#r['ThreadStacktrace'] = 'thread\neven longer\ntrace'

#c.update(89040, r, 'arbitrary comment\nhere.')

#t=c.upload(r)
#print 'ticket:', t
#print c.get_comment_url(r, t)
