'''Abstract crash database interface.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import os

class CrashDatabase:
    def __init__(self, auth_file, bugpattern_baseurl, options):
        '''Initialize crash database connection. 
        
        You need to specify an implementation specific file with the
        authentication credentials for retracing access for download() and
        update(). For upload() and get_comment_url() you can use None.
        
        options is a dictionary with additional settings from crashdb.conf; see
        get_crashdb() for details'''

        self.auth_file = auth_file
        self.options = options
        self.bugpattern_baseurl = bugpattern_baseurl

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

    def get_distro_release(self, id):
        '''Get 'DistroRelease: <release>' from the given report ID and return
        it.'''

        raise Exception, 'this method must be implemented by a concrete subclass'

    def get_bugpattern_baseurl(self):
        '''Return the base URL for bug patterns.

        See apport.report.Report.search_bug_patterns() for details. If this
        function returns None, bug patterns are disabled.'''

        return self.bugpattern_baseurl

#
# factory 
#

def get_crashdb(auth_file, name = None, conf = None):
    '''Return a CrashDatabase object for the given crash db name, as specified
    in the configuration file 'conf'.
    
    If name is None, it defaults to the 'default' value in conf.

    If conf is None, it defaults to the environment variable
    APPORT_CRASHDB_CONF; if that does not exist, the hardcoded default is
    /etc/apport/crashdb.conf. This Python syntax file needs to specify:

    - A string variable 'default', giving a default value for 'name' if that is
      None.

    - A dictionary 'databases' which maps names to crash db configuration
      dictionaries. These need to have at least the keys 'impl' (Python module
      in apport.crashdb_impl which contains a concrete 'CrashDatabase' class
      implementation for that crash db type) and 'bug_pattern_base', which
      specifies an URL for bug patterns (or None if those are not used for that
      crash db).'''

    if not conf:
        conf = os.environ.get('APPORT_CRASHDB_CONF', '/etc/apport/crashdb.conf')
    settings = {}
    execfile(conf, settings)

    if not name:
        name = settings['default']

    db = settings['databases'][name]

    m = __import__('apport.crashdb_impl.' + db['impl'], globals(), locals(), ['CrashDatabase'], -1)
    return m.CrashDatabase(auth_file, db['bug_pattern_base'], db)

