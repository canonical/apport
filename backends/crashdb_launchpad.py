'''Crash database implementation for Launchpad.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import urllib, tempfile
import launchpadBugs.storeblob

from apport.crashdb import CrashDatabase

class LaunchpadCrashDatabase(CrashDatabase):
    '''Launchpad implementation of crash database interface.'''

    def upload(self, report):
        '''Upload given problem report return a handle for it. 
        
        This should happen noninteractively.'''

        # set retracing tag
        hdr = {}
        if report.has_key('CoreDump') and report.has_key('PackageArchitecture'):
            a = report['PackageArchitecture']
            hdr['Tags'] = 'need-%s-retrace' % a

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
        title = self.create_crash_bug_title()
        if title:
            args['field.title'] = title

        if report.has_key('SourcePackage'):
            return 'https://launchpad.net/ubuntu/+source/%s/+filebug/%s?%s' % (
                self.report['SourcePackage'], ticket, urllib.urlencode(args))
        else:
            return 'https://launchpad.net/ubuntu/+filebug/%s?%s' % (
                ticket, urllib.urlencode(args))
