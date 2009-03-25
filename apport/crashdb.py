'''Abstract crash database interface.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import os, os.path, datetime

from packaging_impl import impl as packaging

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
    # Tests are in apport/crashdb_impl/memory.py.

    def init_duplicate_db(self, path):
        '''Initialize duplicate database.

        path specifies an SQLite database. It will be created if it does not
        exist yet.'''

        import sqlite3 as dbapi2

        assert dbapi2.paramstyle == 'qmark', \
            'this module assumes qmark dbapi parameter style'

        init = not os.path.exists(path) or path == ':memory:' or \
            os.path.getsize(path) == 0
        self.duplicate_db = dbapi2.connect(path, timeout=7200)

        if init:
            cur = self.duplicate_db.cursor()
            cur.execute('''CREATE TABLE crashes (
                signature VARCHAR(255) NOT NULL,
                crash_id INTEGER NOT NULL,
                fixed_version VARCHAR(50),
                last_change TIMESTAMP)''')

            cur.execute('''CREATE TABLE consolidation (
                last_update TIMESTAMP)''')
            cur.execute('''INSERT INTO consolidation VALUES (CURRENT_TIMESTAMP)''')
            self.duplicate_db.commit()

        # verify integrity
        cur = self.duplicate_db.cursor()
        cur.execute('PRAGMA integrity_check');
        result = cur.fetchall() 
        if result != [('ok',)]:
            raise SystemError, 'Corrupt duplicate db:' + str(result)

    def check_duplicate(self, id, report=None):
        '''Check whether a crash is already known.

        If the crash is new, it will be added to the duplicate database and the
        function returns None. If the crash is already known, the function
        returns a pair (crash_id, fixed_version), where fixed_version might be
        None if the crash is not fixed in the latest version yet. Depending on
        whether the version in report is smaller than/equal to the fixed
        version or larger, this calls close_duplicate() or mark_regression().
        
        If the report does not have a valid crash signature, this function does
        nothing and just returns None.
        
        By default, the report gets download()ed, but for performance reasons
        it can be explicitly passed to this function if it is already available.'''

        assert self.duplicate_db, 'init_duplicate_db() needs to be called before'

        if not report:
            report = self.download(id)

        self._mark_dup_checked(id, report)

        sig = report.crash_signature()
        if not sig:
            return None

        existing = self._duplicate_search_signature(sig)

        # sort existing in ascending order, with unfixed last, so that
        # version comparisons find the closest fix first
        def cmp(x, y):
            if x == y:
                return 0
            if x == '':
                if y == None:
                    return -1
                else:
                    return 1
            if y == '':
                if x == None:
                    return 1
                else:
                    return -1
            if x == None:
                return 1
            if y == None:
                return -1
            return packaging.compare_versions(x, y)

        existing.sort(cmp, lambda k: k[1])

        if not existing:
            # add a new entry
            cur = self.duplicate_db.cursor()
            cur.execute('INSERT INTO crashes VALUES (?, ?, ?, CURRENT_TIMESTAMP)', (sig, id, None))
            self.duplicate_db.commit()
            return None

        try:
            report_package_version = report['Package'].split()[1]
        except (KeyError, IndexError):
            report_package_version = None

        # search the newest fixed id or an unfixed id to check whether there is
        # a regression (crash happening on a later version than the latest
        # fixed one)
        for (ex_id, ex_ver) in existing:
            if not ex_ver or \
               not report_package_version or \
                packaging.compare_versions(report_package_version, ex_ver) < 0: 
                self.close_duplicate(id, ex_id)
                break
        else:
            # regression, mark it as such in the crash db
            self.mark_regression(id, ex_id)

            # create a new record
            cur = self.duplicate_db.cursor()
            cur.execute('INSERT INTO crashes VALUES (?, ?, ?, CURRENT_TIMESTAMP)', (sig, id, None))
            self.duplicate_db.commit()

        return (ex_id, ex_ver)

    def duplicate_db_fixed(self, id, version):
        '''Mark given crash ID as fixed in the duplicate database.
        
        version specifies the package version the crash was fixed in (None for
        'still unfixed').'''

        assert self.duplicate_db, 'init_duplicate_db() needs to be called before'

        cur = self.duplicate_db.cursor()
        n = cur.execute('UPDATE crashes SET fixed_version = ?, last_change = CURRENT_TIMESTAMP WHERE crash_id = ?',
            (version, id))
        assert n.rowcount == 1
        self.duplicate_db.commit()

    def duplicate_db_remove(self, id):
        '''Remove crash from the duplicate database (because it got rejected or
        manually duplicated).'''

        assert self.duplicate_db, 'init_duplicate_db() needs to be called before'

        cur = self.duplicate_db.cursor()
        cur.execute('DELETE FROM crashes WHERE crash_id = ?', [id])
        self.duplicate_db.commit()

    def duplicate_db_consolidate(self):
        '''Update the duplicate database status to the reality of the crash
        database.
        
        This uses get_unfixed() and get_fixed_version() to get the status of
        particular crashes. Invalid IDs get removed from the duplicate db, and
        crashes which got fixed since the last run are marked as such in the
        database.

        This is a very expensive operation and should not be used too often.'''

        assert self.duplicate_db, 'init_duplicate_db() needs to be called before'

        unfixed = self.get_unfixed()

        cur = self.duplicate_db.cursor()
        cur.execute('SELECT crash_id, fixed_version FROM crashes')

        cur2 = self.duplicate_db.cursor()
        for (id, ver) in cur:
            # crash got reopened
            if id in unfixed:
                if ver != None:
                    cur2.execute('UPDATE crashes SET fixed_version = NULL, last_change = CURRENT_TIMESTAMP WHERE crash_id = ?', [id])
                continue

            if ver != None:
                continue # skip get_fixed_version(), we already know its fixed

            # crash got fixed/rejected
            fixed_ver = self.get_fixed_version(id)
            if fixed_ver == 'invalid':
                print 'DEBUG: bug %i was invalidated, removing from database' % id
                cur2.execute('DELETE FROM crashes WHERE crash_id = ?', [id])
            elif not fixed_ver:
                print 'WARNING: inconsistency detected: bug #%i does not appear in get_unfixed(), but is not fixed yet' % id
            else:
                cur2.execute('UPDATE crashes SET fixed_version = ?, last_change = CURRENT_TIMESTAMP WHERE crash_id = ?',
                    (fixed_ver, id))

        # poke consolidation.last_update
        cur.execute('UPDATE consolidation SET last_update = CURRENT_TIMESTAMP')
        self.duplicate_db.commit()

    def duplicate_db_last_consolidation(self, absolute=False):
        '''Return the date and time of last consolidation.
        
        By default, this returns the number of seconds since the last
        consolidation. If absolute is True, the date and time of last
        consolidation will be returned as a string instead.'''

        assert self.duplicate_db, 'init_duplicate_db() needs to be called before'

        cur = self.duplicate_db.cursor()
        cur.execute('SELECT last_update FROM consolidation')
        if absolute:
            return cur.fetchone()[0]
        else:
            last_run = datetime.datetime.strptime(cur.fetchone()[0], '%Y-%m-%d %H:%M:%S')
            delta = (datetime.datetime.utcnow() - last_run)
            return delta.days * 86400 + delta.seconds

    def duplicate_db_needs_consolidation(self, interval=86400):
        '''Check whether the last duplicate_db_consolidate() happened more than
        'interval' seconds ago (default: one day).'''

        return self.duplicate_db_last_consolidation() >= interval

    def duplicate_db_change_master_id(self, old_id, new_id):
        '''Change a crash ID.'''

        assert self.duplicate_db, 'init_duplicate_db() needs to be called before'

        cur = self.duplicate_db.cursor()
        cur.execute('UPDATE crashes SET crash_id = ?, last_change = CURRENT_TIMESTAMP WHERE crash_id = ?',
            [new_id, old_id])
        self.duplicate_db.commit()

    def _duplicate_search_signature(self, sig):
        '''Look up signature in the duplicate db and return an [(id,
        fixed_version)] tuple list.
        
        There might be several matches if a crash has been reintroduced in a
        later version.'''

        cur = self.duplicate_db.cursor()
        cur.execute('SELECT crash_id, fixed_version FROM crashes WHERE signature = ?', [sig])
        return cur.fetchall()

    def _duplicate_db_dump(self, with_timestamps=False):
        '''Return the entire duplicate database as a dictionary signature ->
           (crash_id, fixed_version).

           If with_timestamps is True, then the map will contain triples
           (crash_id, fixed_version, last_change) instead.

           This is mainly useful for debugging and test suites.'''

        assert self.duplicate_db, 'init_duplicate_db() needs to be called before'

        dump = {}
        cur = self.duplicate_db.cursor()
        cur.execute('SELECT * FROM crashes')
        for (sig, id, ver, last_change) in cur:
            if with_timestamps:
                dump[sig] = (id, ver, last_change)
            else:
                dump[sig] = (id, ver)
        return dump

    #
    # Abstract functions that need to be implemented by subclasses
    #

    def upload(self, report, progress_callback = None):
        '''Upload given problem report return a handle for it. 
        
        This should happen noninteractively. 
        
        If the implementation supports it, and a function progress_callback is
        passed, that is called repeatedly with two arguments: the number of
        bytes already sent, and the total number of bytes to send. This can be
        used to provide a proper upload progress indication on frontends.'''

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

    def get_unretraced(self):
        '''Return an ID set of all crashes which have not been retraced yet and
        which happened on the current host architecture.'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_dup_unchecked(self):
        '''Return an ID set of all crashes which have not been checked for
        being a duplicate.

        This is mainly useful for crashes of scripting languages such as
        Python, since they do not need to be retraced. It should not return
        bugs that are covered by get_unretraced().'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_unfixed(self):
        '''Return an ID set of all crashes which are not yet fixed.

        The list must not contain bugs which were rejected or duplicate.
        
        This function should make sure that the returned list is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def get_fixed_version(self, id):
        '''Return the package version that fixes a given crash.

        Return None if the crash is not yet fixed, or an empty string if the
        crash is fixed, but it cannot be determined by which version. Return
        'invalid' if the crash report got invalidated, such as closed a
        duplicate or rejected.

        This function should make sure that the returned result is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def duplicate_of(self, id):
        '''Return master ID for a duplicate bug.

        If the bug is not a duplicate, return None.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def close_duplicate(self, id, master):
        '''Mark a crash id as duplicate of given master ID.
        
        If master is None, id gets un-duplicated.
        '''
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def mark_regression(self, id, master):
        '''Mark a crash id as reintroducing an earlier crash which is
        already marked as fixed (having ID 'master').'''
        
        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def mark_retraced(self, id):
        '''Mark crash id as retraced.'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def mark_retrace_failed(self, id, invalid_msg=None):
        '''Mark crash id as 'failed to retrace'.

        If invalid_msg is given, the bug should be closed as invalid with given
        message, otherwise just marked as a failed retrace.
        
        This can be a no-op if you are not interested in this.'''

        raise NotImplementedError, 'this method must be implemented by a concrete subclass'

    def _mark_dup_checked(self, id, report):
        '''Mark crash id as checked for being a duplicate
        
        This is an internal method that should not be called from outside.'''

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

    # Load third parties crashdb.conf
    confdDir = conf + '.d'
    if os.path.isdir(confdDir):
        for cf in os.listdir(confdDir):
            cfpath = os.path.join(confdDir, cf)
            if os.path.isfile(cfpath) and cf.endswith('.conf'):
                try:
                    execfile(cfpath, settings['databases'])
                except:
                    # ignore broken files
                    pass
    
    if not name:
        name = settings['default']

    db = settings['databases'][name]

    m = __import__('apport.crashdb_impl.' + db['impl'], globals(), locals(), ['CrashDatabase'])
    return m.CrashDatabase(auth_file, db['bug_pattern_base'], db)

