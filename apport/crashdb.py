'''Abstract crash database interface.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

class CrashDatabase:
    def __init__(self, auth_file):
        '''Initialize Launchpad crash database connection. 
        
        You need to specify an implementation specific file with the
        authentication credentials for retracing access for download() and
        update(). For upload() and get_comment_url() you can use None.'''

        self.auth_file = auth_file

    def upload(self, report):
        '''Upload given problem report return a handle for it. 
        
        This should happen noninteractively.'''

        raise Exception, 'this method must be implemented by a concrete subclass'

    def get_comment_url(self, report, handle):
        '''Return an URL that should be opened after report has been uploaded
        and upload() returned handle.

        Should return None if no URL should be opened (anonymous filing without
        user comments); in that case this function should do whichever
        interactive steps it wants to perform.'''

        raise Exception, 'this method must be implemented by a concrete subclass'

    def download(self, id):
        '''Download the problem report from given ID and return a Report.'''

        raise Exception, 'this method must be implemented by a concrete subclass'

    def update(self, id, report, comment):
        '''Update the given report ID with the retraced results from the report
        (Stacktrace, ThreadStacktrace, StacktraceTop; also Disassembly if
        desired) and an optional comment.'''

        raise Exception, 'this method must be implemented by a concrete subclass'
