'''Simple in-memory CrashDatabase implementation, mainly useful for testing.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import apport.crashdb
import apport

class CrashDatabase(apport.crashdb.CrashDatabase):
    '''Simple implementation of crash database interface which keeps everything
    in memory.
    
    This is mainly useful for testing and debugging.'''

    def __init__(self, auth_file, bugpattern_baseurl, options):
        '''Initialize crash database connection.
        
        This class does not support bug patterns and authentication.'''

        apport.crashdb.CrashDatabase.__init__(self, auth_file,
            bugpattern_baseurl, options)

        self.reports = []
        self.comments = {}

    def upload(self, report):
        '''Store the report and return a handle number (starting from 0).'''

        self.reports.append(report)
        return len(self.reports)-1

    def get_comment_url(self, report, handle):
        '''Return http://<sourcepackage>.bug.net/<handle> for package bugs
        or http://bug.net/<handle> for reports without a SourcePackage.'''

        if report.has_key('SourcePackage'):
            return 'http://%s.bug.net/%i' % (report['SourcePackage'],
                handle)
        else:
            return 'http://bug.net/%i' % handle

    def download(self, id):
        '''Download the problem report from given ID and return a Report.'''

        return self.reports[id]

    def update(self, id, report, comment = ''):
        '''Update the given report ID with the retraced results from the report
        (Stacktrace, ThreadStacktrace, StacktraceTop; also Disassembly if
        desired) and an optional comment.'''

        self.reports[id] = report
        self.comments[id] = comment

    def get_distro_release(self, id):
        '''Get 'DistroRelease: <release>' from the given report ID and return
        it.'''

        return self.reports[id]['DistroRelease']

    def latest_id(self):
        '''Return the ID of the most recently filed report.'''

        return len(self.reports)-1
