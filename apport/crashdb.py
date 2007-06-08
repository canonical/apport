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
        self.duplicate_db = None

    def get_bugpattern_baseurl(self):
        '''Return the base URL for bug patterns.

        See apport.report.Report.search_bug_patterns() for details. If this
        function returns None, bug patterns are disabled.'''

        return self.bugpattern_baseurl

    #
    # API for duplicate detection
    #

    def init_duplicate_db(self, path):
        '''Initialize duplicate database.

        path specifies an SQLite database. It will be created if it does not
        exist yet.'''

        from pysqlite2 import dbapi2

        assert dbapi2.paramstyle == 'qmark', \
            'this module assumes qmark dbapi parameter style'

        init = not os.path.exists(path)
        self.duplicate_db = dbapi2.connect(path)

        if init:
            cur = db.cursor()
            cur.execute('''CREATE TABLE crashes (
                signature VARCHAR(255) NOT NULL,
                crash_id INTEGER NOT NULL,
                fixed_version VARCHAR(50))''')
            self.duplicate_db.commit()

    def check_duplicate(self, report):
        '''Check whether the crash is already known.

        If the crash is new, it will be added to the duplicate database and the
        function returns None. If the crash is already known, the function
        returns a pair (crash_id, fixed_version), where fixed_version might be
        None if the crash is not fixed in the latest version yet.'''

        assert self.duplicate_db, 'init_duplicate_db() needs to be called before'

        raise Exception, 'not yet implemented'

    def duplicate_db_fixed(self, id, version):
        '''Mark given crash ID as fixed in the duplicate database.
        
        version specifies the package version the crash was fixed in.'''

        assert self.duplicate_db, 'init_duplicate_db() needs to be called before'

        raise Exception, 'not yet implemented'

    def duplicate_db_remove(self, id):
        '''Remove crash from the duplicate database (because it got rejected or
        manually duplicated).'''

        assert self.duplicate_db, 'init_duplicate_db() needs to be called before'

        raise Exception, 'not yet implemented'

    def duplicate_db_consolidate(self):
        '''Update the duplicate database status to the reality of the crash
        database.

        This uses get_status_list() to get the status of all crashes. IDs which
        do not occur there any more are removed from the duplicate db, and
        crashes which got fixed since the last run are marked as such in the
        database.'''

        assert self.duplicate_db, 'init_duplicate_db() needs to be called before'

        raise Exception, 'not yet implemented'

    #
    # Abstract functions that need to be implemented by subclasses
    #

    def upload(self, report):
        '''Upload given problem report return a handle for it. 
        
        This should happen noninteractively.'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_comment_url(self, report, handle):
        '''Return an URL that should be opened after report has been uploaded
        and upload() returned handle.

        Should return None if no URL should be opened (anonymous filing without
        user comments); in that case this function should do whichever
        interactive steps it wants to perform.'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def download(self, id):
        '''Download the problem report from given ID and return a Report.'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def update(self, id, report, comment):
        '''Update the given report ID with the retraced results from the report
        (Stacktrace, ThreadStacktrace, StacktraceTop; also Disassembly if
        desired) and an optional comment.'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_distro_release(self, id):
        '''Get 'DistroRelease: <release>' from the given report ID and return
        it.'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_status_list(self):
        '''Return a mapping 'id -> fixed_version' of all currently tracked crashes.

        The keys are integers (crash IDs), the values are 'None' for unfixed
        crashes or the package version the crash was fixed in for resolved
        crashes. The list must not contain bugs which were rejected or manually
        marked as duplicate.
        
        This is a very expensive operation and should not be used too often.
        
        This function should make sure that the returned map is consistent. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

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

