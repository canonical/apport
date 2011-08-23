# vim: set fileencoding=UTF-8 :
'''Crash database implementation for Launchpad.'''

# Copyright (C) 2007 - 2009 Canonical Ltd.
# Authors: Martin Pitt <martin.pitt@ubuntu.com> and Markus Korn <thekorn@gmx.de>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import urllib, tempfile, os.path, re, gzip, sys
import email
try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

from launchpadlib.errors import HTTPError
from launchpadlib.launchpad import Launchpad

import apport.crashdb
import apport

default_credentials_path = os.path.expanduser('~/.cache/apport/launchpad.credentials')

def filter_filename(attachments):
    for attachment in attachments:
        try:
            f = attachment.data.open()
        except HTTPError:
            apport.error('Broken attachment on bug, ignoring')
            continue
        name = f.filename
        if name.endswith('.txt') or name.endswith('.gz'):
            yield f
            
def id_set(tasks):
    # same as set(int(i.bug.id) for i in tasks) but faster
    return set(int(i.self_link.split('/').pop()) for i in tasks)
    

class CrashDatabase(apport.crashdb.CrashDatabase):
    '''Launchpad implementation of crash database interface.'''

    def __init__(self, auth, bugpattern_baseurl, options):
        '''Initialize Launchpad crash database. 
        
        You need to specify a launchpadlib-style credentials file to
        access launchpad. If you supply None, it will use
        default_credentials_path (~/.cache/apport/launchpad.credentials).

        Recognized options are:
        - distro: Name of the distribution in Launchpad
        - project: Name of the project in Launchpad
        (Note that exactly one of "distro" or "project" must be given.)
        - launchpad_instance: If set, this uses the given launchpad instance
          instead of production (optional). This can be overriden or set by
          $APPORT_LAUNCHPAD_INSTANCE environment.
        - cache_dir: Path to a permanent cache directory; by default it uses a
          temporary one. (optional). This can be overridden or set by
          $APPORT_LAUNCHPAD_CACHE environment.
        - escalation_subscription: This subscribes the given person or team to
          a bug once it gets the 10th duplicate.
        - escalation_tag: This adds the given tag to a bug once it gets more
          than 10 duplicates.
        '''
        if os.getenv('APPORT_LAUNCHPAD_INSTANCE'):
            options['launchpad_instance'] = os.getenv(
                'APPORT_LAUNCHPAD_INSTANCE')
        if not auth:
            lp_instance = options.get('launchpad_instance')
            if lp_instance:
                auth = default_credentials_path + '.' + lp_instance.split('://', 1)[-1]
            else:
                auth = default_credentials_path
        apport.crashdb.CrashDatabase.__init__(self, auth,
            bugpattern_baseurl, options)

        self.distro = options.get('distro')
        if self.distro:
            assert 'project' not in options, 'Must not set both "project" and "distro" option'
        else:
            assert 'project' in options, 'Need to have either "project" or "distro" option'

        self.arch_tag = 'need-%s-retrace' % apport.packaging.get_system_architecture()
        self.options = options
        self.auth = auth
        assert self.auth

        self.__launchpad = None
        self.__lp_distro = None
        self.__lpcache = os.getenv('APPORT_LAUNCHPAD_CACHE', options.get('cache_dir'))
        
    @property
    def launchpad(self):
        '''Return Launchpad instance.'''

        if self.__launchpad:
            return self.__launchpad

        if self.options.get('launchpad_instance'):
            launchpad_instance = self.options.get('launchpad_instance')
        else:
            launchpad_instance = 'production'

        auth_dir = os.path.dirname(self.auth)
        if auth_dir and not os.path.isdir(auth_dir):
            os.makedirs(auth_dir)

        try:
            self.__launchpad = Launchpad.login_with('apport-collect',
                    launchpad_instance, launchpadlib_dir=self.__lpcache,
                    allow_access_levels=['WRITE_PRIVATE'],
                    credentials_file = self.auth,
                    version='1.0')
        except Exception as e:
            if hasattr(e, 'content'):
                msg = e.content
            else:
                msg = str(e)
            apport.error('connecting to Launchpad failed: %s\nYou can reset the credentials by removing the file "%s"', msg, self.auth)
            sys.exit(99) # transient error

        return self.__launchpad

    def _get_distro_tasks(self, tasks):
        if not self.distro:
            raise StopIteration

        for t in tasks:
            if t.bug_target_name.lower() == self.distro or \
                    re.match('^.+\(%s.*\)$' % self.distro, t.bug_target_name.lower()):
                yield t
    
    @property
    def lp_distro(self):
        if not self.distro:
            return None
        if self.__lp_distro is None:
            self.__lp_distro = self.launchpad.distributions[self.distro]
        return self.__lp_distro

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
        if a:
            hdr['Tags'] += ' ' + a
        if report.has_key('Tags'):
            hdr['Tags'] += ' ' + report['Tags']

        # privacy/retracing for distro reports
        # FIXME: ugly hack until LP has a real crash db
        if 'DistroRelease' in report:
            if a and ('VmCore' in report or 'CoreDump' in report):
                hdr['Private'] = 'yes'
                hdr['Subscribers'] = 'apport'
                hdr['Tags'] += ' need-%s-retrace' % a
            elif 'Traceback' in report:
                hdr['Private'] = 'yes'
                hdr['Subscribers'] = 'apport'
                hdr['Tags'] += ' need-duplicate-check'
        if 'DuplicateSignature' in report and 'need-duplicate-check' not in hdr['Tags']:
                hdr['Tags'] += ' need-duplicate-check'

        # if we have checkbox submission key, link it to the bug; keep text
        # reference until the link is shown in Launchpad's UI
        if report.has_key('CheckboxSubmission'):
            hdr['HWDB-Submission'] = report['CheckboxSubmission']

        # order in which keys should appear in the temporary file
        order = [ 'ProblemType', 'DistroRelease', 'Package', 'Regression', 'Reproducible', 
        'TestedUpstream', 'ProcVersionSignature', 'Uname', 'NonfreeKernelModules' ]

        # write MIME/Multipart version into temporary file
        mime = tempfile.TemporaryFile()
        report.write_mime(mime, extra_headers=hdr, skip_keys=['Tags'], priority_fields=order)
        mime.flush()
        mime.seek(0)

        ticket = upload_blob(mime, progress_callback,
                hostname=self.get_hostname())
        assert ticket
        return ticket

    def get_hostname(self):
        '''Return the hostname for the Launchpad instance.'''

        launchpad_instance = self.options.get('launchpad_instance')
        if launchpad_instance:
            if launchpad_instance == 'staging':
                hostname = 'staging.launchpad.net'
            else:
                hostname = 'launchpad.dev'
        else:
            hostname = 'launchpad.net'
        return hostname

    def get_comment_url(self, report, handle):
        '''Return an URL that should be opened after report has been uploaded
        and upload() returned handle.

        Should return None if no URL should be opened (anonymous filing without
        user comments); in that case this function should do whichever
        interactive steps it wants to perform.'''

        args = {}
        title = report.get('Title', report.standard_title())
        if title:
            args['field.title'] = title

        hostname = self.get_hostname()

        project = self.options.get('project')

        if not project:
            if report.has_key('SourcePackage'):
                return 'https://bugs.%s/%s/+source/%s/+filebug/%s?%s' % (
                    hostname, self.distro, report['SourcePackage'], handle, urllib.urlencode(args))
            else:
                return 'https://bugs.%s/%s/+filebug/%s?%s' % (
                    hostname, self.distro, handle, urllib.urlencode(args))
        else:
            return 'https://bugs.%s/%s/+filebug/%s?%s' % (
                hostname, project, handle, urllib.urlencode(args))

    def download(self, id):
        '''Download the problem report from given ID and return a Report.'''

        report = apport.Report()
        b = self.launchpad.bugs[id]

        # parse out fields from summary
        m = re.search(r'(ProblemType:.*)$', b.description, re.S)
        if not m:
            m = re.search(r'^--- \r?$[\r\n]*(.*)', b.description, re.M | re.S)
        assert m, 'bug description must contain standard apport format data'

        description = m.group(1).encode('UTF-8').replace('\xc2\xa0', ' ').replace('\r\n', '\n')
        
        if '\n\n' in description:
            # this often happens, remove all empty lines between top and
            # 'Uname'
            if 'Uname:' in description:
                # this will take care of bugs like LP #315728 where stuff
                # is added after the apport data
                (part1, part2) = description.split('Uname:', 1)
                description = part1.replace('\n\n', '\n') + 'Uname:' \
                    + part2.split('\n\n', 1)[0]
            else:
                # just parse out the Apport block; e. g. LP #269539
                description = description.split('\n\n', 1)[0]

        report.load(StringIO(description))

        if 'Date' not in report:
            # We had not submitted this field for a while, claiming it
            # redundant. But it is indeed required for up-to-the-minute
            # comparison with log files, etc. For backwards compatibility with
            # those reported bugs, read the creation date
            try:
                report['Date'] = b.date_created.ctime()
            except AttributeError:
                # support older wadllib API which returned strings
                report['Date'] = b.date_created
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
                raise ValueError('cannot determine ProblemType from tags: ' + str(b.tags))

        report['Tags'] = ' '.join(b.tags)

        if 'Title' in report:
            report['OriginalTitle'] = report['Title']

        report['Title'] = b.title

        for attachment in filter_filename(b.attachments):
            key, ext = os.path.splitext(attachment.filename)
            # ignore attachments with invalid keys
            try:
                report[key] = ''
            except:
                continue
            if ext == '.txt':
                report[key] = attachment.read()
            elif ext == '.gz':
                try:
                    report[key] = gzip.GzipFile(fileobj=attachment).read()
                except IOError as e:
                    # some attachments are only called .gz, but are
                    # uncompressed (LP #574360)
                    if 'Not a gzip' not in str(e):
                        raise
                    attachment.seek(0)
                    report[key] = attachment.read()
            else:
                raise Exception('Unknown attachment type: ' + attachment.filename)
        return report

    def update(self, id, report, comment, change_description=False,
            attachment_comment=None, key_filter=None):
        '''Update the given report ID with all data from report.

        This creates a text comment with the "short" data (see
        ProblemReport.write_mime()), and creates attachments for all the
        bulk/binary data. 
        
        If change_description is True, and the crash db implementation supports
        it, the short data will be put into the description instead (like in a
        new bug).

        comment will be added to the "short" data. If attachment_comment is
        given, it will be added to the attachment uploads.

        If key_filter is a list or set, then only those keys will be added.
        '''
        bug = self.launchpad.bugs[id]

        if key_filter:
            skip_keys = set(report.keys()) - set(key_filter)
        else:
            skip_keys = None

        # we want to reuse the knowledge of write_mime() with all its different input
        # types and output formatting; however, we have to dissect the mime ourselves,
        # since we can't just upload it as a blob
        mime = tempfile.TemporaryFile()
        report.write_mime(mime, skip_keys=skip_keys)
        mime.flush()
        mime.seek(0)
        msg = email.message_from_file(mime)
        msg_iter = msg.walk()

        # first part is the multipart container
        part = msg_iter.next()
        assert part.is_multipart()

        # second part should be an inline text/plain attachments with all short
        # fields
        part = msg_iter.next()
        assert not part.is_multipart()
        assert part.get_content_type() == 'text/plain'

        if not key_filter:
            # when we update a complete report, we are updating an existing bug
            # with apport-collect
            x = bug.tags[:] # LP#254901 workaround
            x.append('apport-collected')
            # add any tags (like the release) to the bug
            if report.has_key('Tags'):
                x += report['Tags'].split()
            bug.tags = x
            bug.lp_save()
            bug = self.launchpad.bugs[id] # fresh bug object, LP#336866 workaround
        
        # short text data
        if change_description:
            bug.description = bug.description + '\n--- \n' + part.get_payload(decode=True).decode('UTF-8', 'replace')
            bug.lp_save()
        else:
            bug.newMessage(content=part.get_payload(decode=True), 
                subject=comment)

        # other parts are the attachments:
        for part in msg_iter:
            # print '   attachment: %s...' % part.get_filename()
            bug.addAttachment(comment=attachment_comment or '',
                description=part.get_filename(),
                content_type=None,
                data=part.get_payload(decode=True),
                filename=part.get_filename(), is_patch=False)

    def update_traces(self, id, report, comment=''):
        '''Update the given report ID for retracing results.
        
        This updates Stacktrace, ThreadStacktrace, StacktraceTop,
        and StacktraceSource. You can also supply an additional comment.
        '''
        apport.crashdb.CrashDatabase.update_traces(self, id, report, comment)

        bug = self.launchpad.bugs[id]
        # ensure it's assigned to a package
        if report.has_key('SourcePackage'):
            for task in bug.bug_tasks:
                if task.target.resource_type_link.endswith('#distribution'):
                    task.target = self.lp_distro.getSourcePackage(name=report['SourcePackage'])
                    task.lp_save()
                    bug = self.launchpad.bugs[id]
                    break

        # remove core dump if stack trace is usable
        if report.has_useful_stacktrace():
            for a in bug.attachments:
                if a.title == 'CoreDump.gz':
                    try:
                        a.removeFromBug()
                    except HTTPError:
                        pass # LP#249950 workaround
            try:
                task = self._get_distro_tasks(bug.bug_tasks).next()
                task.importance = 'Medium'
                task.lp_save()
            except StopIteration:
                pass # no distro tasks
        self._subscribe_triaging_team(bug, report)

    def get_distro_release(self, id):
        '''Get 'DistroRelease: <release>' from the given report ID and return
        it.'''
        bug = self.launchpad.bugs[id]
        m = re.search('DistroRelease: ([-a-zA-Z0-9.+/ ]+)', bug.description)
        if m:
            return m.group(1)
        raise ValueError('URL does not contain DistroRelease: field')

    def get_affected_packages(self, id):
        '''Return list of affected source packages for given ID.'''

        bug_target_re = re.compile(
                    r'/%s/(?:(?P<suite>[^/]+)/)?\+source/(?P<source>[^/]+)$' %
                    self.distro)

        bug = self.launchpad.bugs[id]
        result = []

        for task in bug.bug_tasks:
            match = bug_target_re.search(task.target.self_link)
            if not match:
                continue
            if task.status in ('Invalid', "Won't Fix", 'Fix Released'):
                continue
            result.append(match.group('source'))
        return result

    def is_reporter(self, id):
        '''Check whether the user is the reporter of given ID.'''

        bug = self.launchpad.bugs[id]
        return bug.owner.name == self.launchpad.me.name

    def can_update(self, id):
        '''Check whether the user is eligible to update a report.

        A user should add additional information to an existing ID if (s)he is
        the reporter or subscribed, the bug is open, not a duplicate, etc. The
        exact policy and checks should be done according to  the particular
        implementation.
        '''
        bug = self.launchpad.bugs[id]
        if bug.duplicate_of:
            return False

        if bug.owner.name == self.launchpad.me.name:
            return True

        # check subscription
        me = self.launchpad.me.self_link
        for sub in bug.subscriptions.entries:
            if sub['person_link'] == me:
                return True

        return False

    def get_unretraced(self):
        '''Return an ID set of all crashes which have not been retraced yet and
        which happened on the current host architecture.'''
        try:
            bugs = self.lp_distro.searchTasks(tags=self.arch_tag)
            return id_set(bugs)
        except Exception, e:
            if hasattr(e, 'content'):
                msg = e.content
            else:
                msg = str(e)
            apport.error('connecting to Launchpad failed: %s', msg)
            sys.exit(99) # transient error

    def get_dup_unchecked(self):
        '''Return an ID set of all crashes which have not been checked for
        being a duplicate.

        This is mainly useful for crashes of scripting languages such as
        Python, since they do not need to be retraced. It should not return
        bugs that are covered by get_unretraced().'''
        
        try:
            bugs = self.lp_distro.searchTasks(tags='need-duplicate-check')
            return id_set(bugs)
        except Exception, e:
            if hasattr(e, 'content'):
                msg = e.content
            else:
                msg = str(e)
            apport.error('connecting to Launchpad failed: %s', msg)
            sys.exit(99) # transient error

    def get_unfixed(self):
        '''Return an ID set of all crashes which are not yet fixed.

        The list must not contain bugs which were rejected or duplicate.
        
        This function should make sure that the returned list is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).'''
        
        bugs = self.lp_distro.searchTasks(tags='apport-crash')
        return id_set(bugs)

    def _get_source_version(self, package):
        '''Return the version of given source package in the latest release of
        given distribution.

        If 'distro' is None, we will look for a launchpad project . 
        '''
        sources = self.lp_distro.main_archive.getPublishedSources(
            exact_match=True,
            source_name=package,
            distro_series=self.lp_distro.current_series
        )
        # first element is the latest one
        return sources[0].source_package_version

    def get_fixed_version(self, id):
        '''Return the package version that fixes a given crash.

        Return None if the crash is not yet fixed, or an empty string if the
        crash is fixed, but it cannot be determined by which version. Return
        'invalid' if the crash report got invalidated, such as closed a
        duplicate or rejected.

        This function should make sure that the returned result is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably IOError).
        '''
        # do not do version tracking yet; for that, we need to get the current
        # distrorelease and the current package version in that distrorelease
        # (or, of course, proper version tracking in Launchpad itself)
        
        try:
            b = self.launchpad.bugs[id]
        except KeyError:
            return 'invalid'
            
        if b.duplicate_of:
            return 'invalid'

        tasks = list(b.bug_tasks) # just fetch it once

        if self.distro:
            distro_identifier = '(%s)' %self.distro.lower()
            fixed_tasks = filter(lambda task: task.status == 'Fix Released' and \
                    distro_identifier in task.bug_target_display_name.lower(), tasks)
            
            if not fixed_tasks:
                fixed_distro = filter(lambda task: task.status == 'Fix Released' and \
                        task.bug_target_name.lower() == self.distro.lower(), tasks)
                if fixed_distro:
                    # fixed in distro inself (without source package)
                    return ''
                
            if len(fixed_tasks) > 1: 
                apport.warning('There is more than one task fixed in %s %s, using first one to determine fixed version', self.distro, id)
                return ''

            if fixed_tasks:
                task = fixed_tasks.pop()
                try:
                    return self._get_source_version(task.bug_target_display_name.split()[0])
                except IndexError:
                    # source does not exist any more
                    return 'invalid'
            else:
                # check if there only invalid ones
                invalid_tasks = filter(lambda task: task.status in ('Invalid', "Won't Fix") and \
                        distro_identifier in task.bug_target_display_name.lower(), tasks)
                if invalid_tasks:
                    non_invalid_tasks = filter(lambda task: task.status not in ('Invalid', "Won't Fix") and \
                        distro_identifier in task.bug_target_display_name.lower(), tasks)
                    if not non_invalid_tasks:
                        return 'invalid'
        else:
            fixed_tasks = filter(lambda task: task.status == 'Fix Released',
                    tasks)
            if fixed_tasks:
                # TODO: look for current series
                return ''
            # check if there any invalid ones
            if filter(lambda task: task.status == 'Invalid', tasks):
                return 'invalid'

        return None

    def duplicate_of(self, id):
        '''Return master ID for a duplicate bug.

        If the bug is not a duplicate, return None.
        '''
        b = self.launchpad.bugs[id].duplicate_of
        if b:
            return b.id
        else:
            return None

    def close_duplicate(self, id, master_id):
        '''Mark a crash id as duplicate of given master ID.
        
        If master is None, id gets un-duplicated.
        '''
        bug = self.launchpad.bugs[id]

        if master_id:
            assert id != master_id, 'cannot mark bug %s as a duplicate of itself' % str(id)

            # check whether the master itself is a dup
            master = self.launchpad.bugs[master_id]
            if master.duplicate_of:
                master = master.duplicate_of
            
            for a in bug.attachments:
                if a.title in ('CoreDump.gz', 'Stacktrace.txt',
                    'ThreadStacktrace.txt', 'Dependencies.txt', 'ProcMaps.txt',
                    'ProcStatus.txt', 'Registers.txt', 'Disassembly.txt'):
                    try:
                        a.removeFromBug()
                    except HTTPError:
                        pass # LP#249950 workaround

            bug = self.launchpad.bugs[id] # fresh bug object, LP#336866 workaround
            bug.newMessage(content='Thank you for taking the time to report this crash and helping \
to make Ubuntu better.  This particular crash has already been reported and \
is a duplicate of bug #%i, so is being marked as such.  Please look at the \
other bug report to see if there is any missing information that you can \
provide, or to see if there is a workaround for the bug.  Additionally, any \
further discussion regarding the bug should occur in the other report.  \
Please continue to report any other bugs you may find.' % master_id,
                subject='This bug is a duplicate')

            bug = self.launchpad.bugs[id] # refresh, LP#336866 workaround
            if bug.private:
                bug.private = False

            # set duplicate last, since we cannot modify already dup'ed bugs
            if not bug.duplicate_of:
                bug.duplicate_of = master

            if len(master.duplicates) == 10:
                if 'escalation_tag' in self.options and \
                    self.options['escalation_tag'] not in master.tags and \
                    self.options.get('escalated_tag', ' invalid ') not in master.tags:
                        master.tags = master.tags + [self.options['escalation_tag']] # LP#254901 workaround
                        master.lp_save()

                if 'escalation_subscription' in self.options and \
                    self.options.get('escalated_tag', ' invalid ') not in master.tags:
                    p = self.launchpad.people[self.options['escalation_subscription']]
                    master.subscribe(person=p)
        else:
            if bug.duplicate_of:
                bug.duplicate_of = None

        if bug._dirty_attributes: # LP#336866 workaround
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
        bug = self.launchpad.bugs[id] # fresh bug object, LP#336866 workaround
        bug.tags = bug.tags + ['regression-retracer'] # LP#254901 workaround
        bug.lp_save()

    def mark_retraced(self, id):
        '''Mark crash id as retraced.'''

        bug = self.launchpad.bugs[id]
        if self.arch_tag in bug.tags:
            x = bug.tags[:] # LP#254901 workaround
            x.remove(self.arch_tag)
            bug.tags = x
            try:
                bug.lp_save()
            except HTTPError:
                pass # LP#336866 workaround

    def mark_retrace_failed(self, id, invalid_msg=None):
        '''Mark crash id as 'failed to retrace'.'''

        bug = self.launchpad.bugs[id]
        if invalid_msg:
            try:
                task = self._get_distro_tasks(bug.bug_tasks).next()
            except StopIteration:
                # no distro task, just use the first one
                task = bug.bug_tasks[0]
            task.status = 'Invalid'
            task.lp_save()
            bug.newMessage(content=invalid_msg,
                    subject='Crash report cannot be processed')
            
            for a in bug.attachments:
                if a.title == 'CoreDump.gz':
                    try:
                        a.removeFromBug()
                    except HTTPError:
                        pass # LP#249950 workaround
        else:
            if 'apport-failed-retrace' not in bug.tags:
                bug.tags = bug.tags + ['apport-failed-retrace'] # LP#254901 workaround
                bug.lp_save()

    def _mark_dup_checked(self, id, report):
        '''Mark crash id as checked for being a duplicate.'''

        bug = self.launchpad.bugs[id]

        # if we have a distro task without a package, fix it
        if report.has_key('SourcePackage'):
            for task in bug.bug_tasks:
                if task.target.resource_type_link.endswith('#distribution'):
                    task.target = self.lp_distro.getSourcePackage(
                        name=report['SourcePackage'])
                    task.lp_save()
                    bug = self.launchpad.bugs[id]
                    break

        if 'need-duplicate-check' in bug.tags:
            x = bug.tags[:] # LP#254901 workaround
            x.remove('need-duplicate-check')
            bug.tags = x
            bug.lp_save()        
        self._subscribe_triaging_team(bug, report)

    def _subscribe_triaging_team(self, bug, report):
        '''Subscribe the right triaging team to the bug.'''

        #FIXME: this entire function is an ugly Ubuntu specific hack until LP
        #gets a real crash db; see https://wiki.ubuntu.com/CrashReporting

        if report.get('DistroRelease', '').split()[0] != 'Ubuntu':
            return # only Ubuntu bugs are filed private
        
        #use a url hack here, it is faster
        person = '%s~ubuntu-crashes-universe' %self.launchpad._root_uri
        bug.subscribe(person=person)

#
# Launchpad storeblob API (should go into launchpadlib, see LP #315358)
#

import multipartpost_handler, urllib2, time, httplib

_https_upload_callback = None

#
# This progress code is based on KodakLoader by Jason Hildebrand
# <jason@opensky.ca>. See http://www.opensky.ca/~jdhildeb/software/kodakloader/
# for details.
class HTTPSProgressConnection(httplib.HTTPSConnection):
    '''Implement a HTTPSConnection with an optional callback function for
    upload progress.'''

    def send(self, data):
        global _https_upload_callback

        # if callback has not been set, call the old method
        if not _https_upload_callback:
            httplib.HTTPSConnection.send(self, data)
            return

        sent = 0
        total = len(data)
        chunksize = 1024
        while sent < total:
            _https_upload_callback(sent, total)
            t1 = time.time()
            httplib.HTTPSConnection.send(self, data[sent:sent+chunksize])
            sent += chunksize
            t2 = time.time()

            # adjust chunksize so that it takes between .5 and 2 
            # seconds to send a chunk
            if t2 - t1 < .5:
                chunksize *= 2
            elif t2 - t1 > 2:
                chunksize /= 2

class HTTPSProgressHandler(urllib2.HTTPSHandler):

    def https_open(self, req):
        return self.do_open(HTTPSProgressConnection, req)

def upload_blob(blob, progress_callback = None, hostname='launchpad.net'):
    '''Upload blob (file-like object) to Launchpad.

    progress_callback can be set to a function(sent, total) which is regularly
    called with the number of bytes already sent and total number of bytes to
    send. It is called every 0.5 to 2 seconds (dynamically adapted to upload
    bandwidth).

    Return None on error, or the ticket number on success.

    By default this uses the production Launchpad hostname. Set
    hostname to 'launchpad.dev' or 'staging.launchpad.net' to use another
    instance for testing.
    '''
    ticket = None

    global _https_upload_callback
    _https_upload_callback = progress_callback

    opener = urllib2.build_opener(HTTPSProgressHandler, multipartpost_handler.MultipartPostHandler)
    url = 'https://%s/+storeblob' % hostname
    result = opener.open(url,
        { 'FORM_SUBMIT': '1', 'field.blob': blob })
    ticket = result.info().get('X-Launchpad-Blob-Token')

    return ticket

#
# Unit tests
#

if __name__ == '__main__':
    import unittest, urllib2

    crashdb = None
    segv_report = None
    python_report = None

    class _T(unittest.TestCase):
        # this assumes that a source package 'coreutils' exists and builds a
        # binary package 'coreutils'
        test_package = 'coreutils'
        test_srcpackage = 'coreutils'

        #
        # Generic tests, should work for all CrashDB implementations
        #

        def setUp(self):
            global crashdb
            if not crashdb:
                crashdb = self._get_instance()
            self.crashdb = crashdb

            # create a local reference report so that we can compare
            # DistroRelease, Architecture, etc.
            self.ref_report = apport.Report()
            self.ref_report.add_os_info()
            self.ref_report.add_user_info()
            self.ref_report['SourcePackage'] = 'coreutils'

            # Objects tests rely on.
            self.uncommon_description_bug = self._file_uncommon_description_bug()
            self._create_project('langpack-o-matic')

            # XXX Should create new bug reports, not reuse those.
            self.known_test_id = self.uncommon_description_bug.id
            self.known_test_id2 = self._file_uncommon_description_bug().id

        def _create_project(self, name):
            '''Create a project using launchpadlib to be used by tests.'''

            project = self.crashdb.launchpad.projects[name]
            if not project:
                self.crashdb.launchpad.projects.new_project(
                    description=name + 'description',
                    display_name=name,
                    name=name,
                    summary=name + 'summary',
                    title=name + 'title')

        def _file_uncommon_description_bug(self):
            '''File a bug report with an uncommon description.

            Example taken from real LP bug 269539. It contains only
            ProblemType/Architecture/DistroRelease in the description, and has
            free-form description text after the Apport data.
            '''
            desc = '''problem

ProblemType: Package
Architecture: amd64
DistroRelease: Ubuntu 8.10

more text

and more
'''
            return self.crashdb.launchpad.bugs.createBug(
                title=u'mixed description bug',
                description=desc,
                target=self.crashdb.lp_distro)

        @property
        def hostname(self):
            '''Get the Launchpad hostname for the given crashdb.'''

            return self.crashdb.get_hostname()

        def _file_segv_report(self):
            '''File a SEGV crash report.

            Return crash ID.
            '''
            r = apport.report._T._generate_sigsegv_report()
            r.add_package_info(self.test_package)
            r.add_os_info()
            r.add_gdb_info()
            r.add_user_info()
            self.assertEqual(r.standard_title(), 'crash crashed with SIGSEGV in f()')

            # add some binary gibberish which isn't UTF-8
            r['ShortGibberish'] = ' "]\xb6"\n'
            r['LongGibberish'] = 'a\nb\nc\nd\ne\n\xff\xff\xff\n\f'

            handle = self.crashdb.upload(r)
            self.assertTrue(handle)
            bug_target = self._get_bug_target(self.crashdb, r)
            self.assertTrue(bug_target)

            id = self._file_bug(bug_target, r, handle)
            self.assertTrue(id > 0)
            return id

        def test_1_report_segv(self):
            '''upload() and get_comment_url() for SEGV crash
            
            This needs to run first, since it sets segv_report.
            '''
            global segv_report
            id = self._file_segv_report()
            segv_report = id
            sys.stderr.write('(https://%s/bugs/%i) ' % (self.hostname, id))

        def test_1_report_python(self):
            '''upload() and get_comment_url() for Python crash
            
            This needs to run early, since it sets python_report.
            '''
            r = apport.Report('Crash')
            r['ExecutablePath'] = '/bin/foo'
            r['Traceback'] = '''Traceback (most recent call last):
  File "/bin/foo", line 67, in fuzz
    print(weird)
NameError: global name 'weird' is not defined'''
            r['Tags'] = 'boogus pybogus'
            r.add_package_info(self.test_package)
            r.add_os_info()
            r.add_user_info()
            self.assertEqual(r.standard_title(), 
                "foo crashed with NameError in fuzz(): global name 'weird' is not defined")

            handle = self.crashdb.upload(r)
            self.assertTrue(handle)
            bug_target = self._get_bug_target(self.crashdb, r)
            self.assertTrue(bug_target)

            id = self._file_bug(bug_target, r, handle)
            self.assertTrue(id > 0)
            global python_report
            python_report = id
            sys.stderr.write('(https://%s/bugs/%i) ' % (self.hostname, id))

        def test_2_download(self):
            '''download()'''

            r = self.crashdb.download(segv_report)
            self.assertEqual(r['ProblemType'], 'Crash')
            self.assertEqual(r['Title'], 'crash crashed with SIGSEGV in f()')
            self.assertEqual(r['DistroRelease'], self.ref_report['DistroRelease'])
            self.assertEqual(r['Architecture'], self.ref_report['Architecture'])
            self.assertEqual(r['Uname'], self.ref_report['Uname'])
            self.assertEqual(r.get('NonfreeKernelModules'),
                self.ref_report.get('NonfreeKernelModules'))
            self.assertEqual(r.get('UserGroups'), self.ref_report.get('UserGroups'))
            tags = set(r['Tags'].split())
            self.assertEqual(tags, set([self.crashdb.arch_tag, 'apport-crash', 
                apport.packaging.get_system_architecture()]))

            self.assertEqual(r['Signal'], '11')
            self.assertTrue(r['ExecutablePath'].endswith('/crash'))
            self.assertEqual(r['SourcePackage'], self.test_srcpackage)
            self.assertTrue(r['Package'].startswith(self.test_package + ' '))
            self.assertTrue('f (x=42)' in r['Stacktrace'])
            self.assertTrue('f (x=42)' in r['StacktraceTop'])
            self.assertTrue('f (x=42)' in r['ThreadStacktrace'])
            self.assertTrue(len(r['CoreDump']) > 1000)
            self.assertTrue('Dependencies' in r)
            self.assertTrue('Disassembly' in r)
            self.assertTrue('Registers' in r)

            # check tags
            r = self.crashdb.download(python_report)
            tags = set(r['Tags'].split())
            self.assertEqual(tags, set(['apport-crash', 'boogus', 'pybogus',
                'need-duplicate-check', apport.packaging.get_system_architecture()]))

        def test_3_update_traces(self):
            '''update_traces()'''

            r = self.crashdb.download(segv_report)
            self.assertTrue('CoreDump' in r)
            self.assertTrue('Dependencies' in r)
            self.assertTrue('Disassembly' in r)
            self.assertTrue('Registers' in r)
            self.assertTrue('Stacktrace' in r)
            self.assertTrue('ThreadStacktrace' in r)

            # updating with an useless stack trace retains core dump
            r['StacktraceTop'] = '?? ()'
            r['Stacktrace'] = 'long\ntrace'
            r['ThreadStacktrace'] = 'thread\neven longer\ntrace'
            r['FooBar'] = 'bogus'
            self.crashdb.update_traces(segv_report, r, 'I can has a better retrace?')
            r = self.crashdb.download(segv_report)
            self.assertTrue('CoreDump' in r)
            self.assertTrue('Dependencies' in r)
            self.assertTrue('Disassembly' in r)
            self.assertTrue('Registers' in r)
            self.assertTrue('Stacktrace' in r) # TODO: ascertain that it's the updated one
            self.assertTrue('ThreadStacktrace' in r)
            self.assertFalse('FooBar' in r)

            tags = self.crashdb.launchpad.bugs[segv_report].tags
            self.assertTrue('apport-crash' in tags)
            self.assertFalse('apport-collected' in tags)

            # updating with an useful stack trace removes core dump
            r['StacktraceTop'] = 'read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so'
            r['Stacktrace'] = 'long\ntrace'
            r['ThreadStacktrace'] = 'thread\neven longer\ntrace'
            self.crashdb.update_traces(segv_report, r, 'good retrace!')
            r = self.crashdb.download(segv_report)
            self.assertFalse('CoreDump' in r)
            self.assertTrue('Dependencies' in r)
            self.assertTrue('Disassembly' in r)
            self.assertTrue('Registers' in r)
            self.assertTrue('Stacktrace' in r)
            self.assertTrue('ThreadStacktrace' in r)
            self.assertFalse('FooBar' in r)

            # test various situations which caused crashes
            r['Stacktrace'] = '' # empty file
            r['ThreadStacktrace'] = '"]\xb6"\n' # not interpretable as UTF-8, LP #353805
            r['StacktraceSource'] = 'a\nb\nc\nd\ne\n\xff\xff\xff\n\f'
            self.crashdb.update_traces(segv_report, r, 'tests')

        def test_update_description(self):
            '''update() with changing description'''

            bug_target = self.crashdb.lp_distro.getSourcePackage(name='bash')
            bug = self.crashdb.launchpad.bugs.createBug(
                description='test description for test bug.',
                target=bug_target,
                title='testbug')
            id = bug.id
            self.assertTrue(id > 0)
            sys.stderr.write('(https://%s/bugs/%i) ' % (self.hostname, id))

            r = apport.Report('Bug')

            r['OneLiner'] = 'bogus→'
            r['StacktraceTop'] = 'f()\ng()\nh(1)'
            r['ShortGoo'] = 'lineone\nlinetwo'
            r['DpkgTerminalLog'] = 'one\ntwo\nthree\nfour\nfive\nsix'
            r['VarLogDistupgradeBinGoo'] = '\x01' * 1024

            self.crashdb.update(id, r, 'NotMe', change_description=True)

            r = self.crashdb.download(id)

            self.assertEqual(r['OneLiner'], 'bogus→')
            self.assertEqual(r['ShortGoo'], 'lineone\nlinetwo')
            self.assertEqual(r['DpkgTerminalLog'], 'one\ntwo\nthree\nfour\nfive\nsix')
            self.assertEqual(r['VarLogDistupgradeBinGoo'], '\x01' * 1024)

            self.assertEqual(self.crashdb.launchpad.bugs[id].tags,
                ['apport-collected'])

        def test_update_comment(self):
            '''update() with appending comment'''

            bug_target = self.crashdb.lp_distro.getSourcePackage(name='bash')
            # we need to fake an apport description separator here, since we
            # want to be lazy and use download() for checking the result
            bug = self.crashdb.launchpad.bugs.createBug(
                description='Pr0blem\n\n--- \nProblemType: Bug',
                target=bug_target,
                title='testbug')
            id = bug.id
            self.assertTrue(id > 0)
            sys.stderr.write('(https://%s/bugs/%i) ' % (self.hostname, id))

            r = apport.Report('Bug')

            r['OneLiner'] = 'bogus→'
            r['StacktraceTop'] = 'f()\ng()\nh(1)'
            r['ShortGoo'] = 'lineone\nlinetwo'
            r['DpkgTerminalLog'] = 'one\ntwo\nthree\nfour\nfive\nsix'
            r['VarLogDistupgradeBinGoo'] = '\x01' * 1024

            self.crashdb.update(id, r, 'meow', change_description=False)

            r = self.crashdb.download(id)

            self.assertFalse('OneLiner' in r)
            self.assertFalse('ShortGoo' in r)
            self.assertEqual(r['ProblemType'], 'Bug')
            self.assertEqual(r['DpkgTerminalLog'], 'one\ntwo\nthree\nfour\nfive\nsix')
            self.assertEqual(r['VarLogDistupgradeBinGoo'], '\x01' * 1024)

            self.assertEqual(self.crashdb.launchpad.bugs[id].tags,
                ['apport-collected'])

        def test_update_filter(self):
            '''update() with a key filter'''

            bug_target = self.crashdb.lp_distro.getSourcePackage(name='bash')
            bug = self.crashdb.launchpad.bugs.createBug(
                description='test description for test bug',
                target=bug_target,
                title='testbug')
            id = bug.id
            self.assertTrue(id > 0)
            sys.stderr.write('(https://%s/bugs/%i) ' % (self.hostname, id))

            r = apport.Report('Bug')

            r['OneLiner'] = 'bogus→'
            r['StacktraceTop'] = 'f()\ng()\nh(1)'
            r['ShortGoo'] = 'lineone\nlinetwo'
            r['DpkgTerminalLog'] = 'one\ntwo\nthree\nfour\nfive\nsix'
            r['VarLogDistupgradeBinGoo'] = '\x01' * 1024

            self.crashdb.update(id, r, 'NotMe', change_description=True,
                    key_filter=['ProblemType', 'ShortGoo', 'DpkgTerminalLog'])

            r = self.crashdb.download(id)

            self.assertFalse('OneLiner' in r)
            self.assertEqual(r['ShortGoo'], 'lineone\nlinetwo')
            self.assertEqual(r['ProblemType'], 'Bug')
            self.assertEqual(r['DpkgTerminalLog'], 'one\ntwo\nthree\nfour\nfive\nsix')
            self.assertFalse('VarLogDistupgradeBinGoo' in r)

            self.assertEqual(self.crashdb.launchpad.bugs[id].tags, [])

        def test_get_distro_release(self):
            '''get_distro_release()'''

            self.assertEqual(self.crashdb.get_distro_release(segv_report),
                    self.ref_report['DistroRelease'])

        def test_get_affected_packages(self):
            '''get_affected_packages()'''

            self.assertEqual(self.crashdb.get_affected_packages(segv_report),
                    [self.ref_report['SourcePackage']])

        def test_is_reporter(self):
            '''is_reporter()'''

            self.assertTrue(self.crashdb.is_reporter(segv_report))
            self.assertFalse(self.crashdb.is_reporter(1))

        def test_can_update(self):
            '''can_update()'''

            self.assertTrue(self.crashdb.can_update(segv_report))
            self.assertFalse(self.crashdb.can_update(1))

        def test_duplicates(self):
            '''duplicate handling'''

            # initially we have no dups
            self.assertEqual(self.crashdb.duplicate_of(segv_report), None)
            self.assertEqual(self.crashdb.get_fixed_version(segv_report), None)

            # dupe our segv_report and check that it worked; then undupe it
            self.crashdb.close_duplicate(segv_report, self.known_test_id)
            self.assertEqual(self.crashdb.duplicate_of(segv_report), self.known_test_id)

            # this should be a no-op
            self.crashdb.close_duplicate(segv_report, self.known_test_id)
            self.assertEqual(self.crashdb.duplicate_of(segv_report), self.known_test_id)

            self.assertEqual(self.crashdb.get_fixed_version(segv_report), 'invalid')
            self.crashdb.close_duplicate(segv_report, None)
            self.assertEqual(self.crashdb.duplicate_of(segv_report), None)
            self.assertEqual(self.crashdb.get_fixed_version(segv_report), None)

            # this should have removed attachments; note that Stacktrace is
            # short, and thus inline
            r = self.crashdb.download(segv_report)
            self.assertFalse('CoreDump' in r)
            self.assertFalse('Dependencies' in r)
            self.assertFalse('Disassembly' in r)
            self.assertFalse('Registers' in r)

            # now try duplicating to a duplicate bug; this should automatically
            # transition to the master bug
            self.crashdb.close_duplicate(self.known_test_id,
                    self.known_test_id2)
            self.crashdb.close_duplicate(segv_report, self.known_test_id)
            self.assertEqual(self.crashdb.duplicate_of(segv_report),
                    self.known_test_id2)

            self.crashdb.close_duplicate(self.known_test_id, None)
            self.crashdb.close_duplicate(self.known_test_id2, None)
            self.crashdb.close_duplicate(segv_report, None)

            # this should be a no-op
            self.crashdb.close_duplicate(self.known_test_id, None)
            self.assertEqual(self.crashdb.duplicate_of(self.known_test_id), None)

            self.crashdb.mark_regression(segv_report, self.known_test_id)
            self._verify_marked_regression(segv_report)

        def test_marking_segv(self):
            '''processing status markings for signal crashes'''

            # mark_retraced()
            unretraced_before = self.crashdb.get_unretraced()
            self.assertTrue(segv_report in unretraced_before)
            self.assertFalse(python_report in unretraced_before)
            self.crashdb.mark_retraced(segv_report)
            unretraced_after = self.crashdb.get_unretraced()
            self.assertFalse(segv_report in unretraced_after)
            self.assertEqual(unretraced_before,
                    unretraced_after.union(set([segv_report])))
            self.assertEqual(self.crashdb.get_fixed_version(segv_report), None)

            # mark_retrace_failed()
            self._mark_needs_retrace(segv_report)
            self.crashdb.mark_retraced(segv_report)
            self.crashdb.mark_retrace_failed(segv_report)
            unretraced_after = self.crashdb.get_unretraced()
            self.assertFalse(segv_report in unretraced_after)
            self.assertEqual(unretraced_before,
                    unretraced_after.union(set([segv_report])))
            self.assertEqual(self.crashdb.get_fixed_version(segv_report), None)

            # mark_retrace_failed() of invalid bug
            self._mark_needs_retrace(segv_report)
            self.crashdb.mark_retraced(segv_report)
            self.crashdb.mark_retrace_failed(segv_report, "I don't like you")
            unretraced_after = self.crashdb.get_unretraced()
            self.assertFalse(segv_report in unretraced_after)
            self.assertEqual(unretraced_before,
                    unretraced_after.union(set([segv_report])))
            self.assertEqual(self.crashdb.get_fixed_version(segv_report),
                    'invalid')

        def test_marking_python(self):
            '''processing status markings for interpreter crashes'''

            unchecked_before = self.crashdb.get_dup_unchecked()
            self.assertTrue(python_report in unchecked_before)
            self.assertFalse(segv_report in unchecked_before)
            self.crashdb._mark_dup_checked(python_report, self.ref_report)
            unchecked_after = self.crashdb.get_dup_unchecked()
            self.assertFalse(python_report in unchecked_after)
            self.assertEqual(unchecked_before,
                    unchecked_after.union(set([python_report])))
            self.assertEqual(self.crashdb.get_fixed_version(python_report),
                    None)

        def test_update_traces_invalid(self):
            '''updating an invalid crash
            
            This simulates a race condition where a crash being processed gets
            invalidated by marking it as a duplicate.
            '''
            id = self._file_segv_report()
            sys.stderr.write('(https://%s/bugs/%i) ' % (self.hostname, id))

            r = self.crashdb.download(id)

            self.crashdb.close_duplicate(id, segv_report)

            # updating with an useful stack trace removes core dump
            r['StacktraceTop'] = 'read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so'
            r['Stacktrace'] = 'long\ntrace'
            r['ThreadStacktrace'] = 'thread\neven longer\ntrace'
            self.crashdb.update_traces(id, r, 'good retrace!')

            r = self.crashdb.download(id)
            self.assertFalse('CoreDump' in r)

        def test_get_fixed_version(self):
            '''get_fixed_version() for fixed bugs

            Other cases are already checked in test_marking_segv() (invalid
            bugs) and test_duplicates (duplicate bugs) for efficiency.
            '''
            self._mark_report_fixed(segv_report)
            fixed_ver = self.crashdb.get_fixed_version(segv_report)
            self.assertNotEqual(fixed_ver, None)
            self.assertTrue(fixed_ver[0].isdigit())
            self._mark_report_new(segv_report)
            self.assertEqual(self.crashdb.get_fixed_version(segv_report), None)

        #
        # Launchpad specific implementation and tests
        #

        @classmethod
        def _get_instance(klass):
            '''Create a CrashDB instance'''

            launchpad_instance = os.environ.get('APPORT_LAUNCHPAD_INSTANCE') or 'staging'

            return CrashDatabase(os.environ.get('LP_CREDENTIALS'), '',
                    {'distro': 'ubuntu',
                     'launchpad_instance': launchpad_instance})

        @classmethod
        def _get_bug_target(klass, db, report):
            '''Return the bug_target for this report.'''

            project = db.options.get('project')
            if report.has_key('SourcePackage'):
                return db.lp_distro.getSourcePackage(name=report['SourcePackage'])
            elif project:
                return db.launchpad.projects[project]
            else:
                return self.lp_distro

        def _get_librarian_hostname(self):
            '''Return the librarian hostname according to the LP hostname used.'''

            hostname = self.crashdb.get_hostname()
            if 'staging' in hostname:
                return 'staging.launchpadlibrarian.net'
            else:
                return 'launchpad.dev:58080'

        def _file_bug(self, bug_target, report, handle, comment=None):
            '''File a bug report.'''

            bug_title = report.get('Title', report.standard_title())

            blob_info = self.crashdb.launchpad.temporary_blobs.fetch(
                token=handle)
            # XXX 2010-08-03 matsubara bug=612990:
            #     Can't fetch the blob directly, so let's load it from the
            #     representation.
            blob = self.crashdb.launchpad.load(blob_info['self_link'])
            #XXX Need to find a way to trigger the job that process the blob
            # rather polling like this. This makes the test suite take forever
            # to run.
            while not blob.hasBeenProcessed():
                time.sleep(1)

            # processed_blob contains info about privacy, additional comments
            # and attachments.
            processed_blob = blob.getProcessedData()

            bug = self.crashdb.launchpad.bugs.createBug(
                description=processed_blob['extra_description'],
                private=processed_blob['private'],
                tags=processed_blob['initial_tags'],
                target=bug_target,
                title=bug_title)

            for comment in processed_blob['comments']:
                bug.newMessage(content=comment)

            # Ideally, one would be able to retrieve the attachment content
            # from the ProblemReport object or from the processed_blob.
            # Unfortunately the processed_blob only give us the Launchpad
            # librarian file_alias_id, so that's why we need to
            # download it again and upload to the bug report. It'd be even
            # better if addAttachment could work like linkAttachment, the LP
            # api used in the +filebug web UI, but there are security concerns
            # about the way linkAttachment works.
            librarian_url = 'http://%s' % self._get_librarian_hostname()
            for attachment in processed_blob['attachments']:
                filename = description = attachment['description']
                # Download the attachment data.
                data = urllib.urlopen(urllib.basejoin(librarian_url,
                    str(attachment['file_alias_id']) + '/' + filename)).read()
                # Add the attachment to the newly created bug report.
                bug.addAttachment(
                    comment=filename,
                    data=data,
                    filename=filename,
                    description=description)

            for subscriber in processed_blob['subscribers']:
                sub = self.crashdb.launchpad.people[subscriber]
                if sub:
                    bug.subscribe(person=sub)

            for submission_key in processed_blob['hwdb_submission_keys']:
                # XXX 2010-08-04 matsubara bug=628889:
                #     Can't fetch the submission directly, so let's load it
                #     from the representation.
                submission = self.crashdb.launchpad.load(
                    'https://api.%s/beta/+hwdb/+submission/%s'
                    % (self.crashdb.get_hostname(), submission_key))
                bug.linkHWSubmission(submission=submission)
            return int(bug.id)

        def _mark_needs_retrace(self, id):
            '''Mark a report ID as needing retrace.'''

            bug = self.crashdb.launchpad.bugs[id]
            if self.crashdb.arch_tag not in bug.tags:
                bug.tags = bug.tags + [self.crashdb.arch_tag]
                bug.lp_save()

        def _mark_needs_dupcheck(self, id):
            '''Mark a report ID as needing duplicate check.'''

            bug = self.crashdb.launchpad.bugs[id]
            if 'need-duplicate-check' not in bug.tags:
                bug.tags = bug.tags + ['need-duplicate-check']
                bug.lp_save()

        def _mark_report_fixed(self, id):
            '''Close a report ID as "fixed".'''

            bug = self.crashdb.launchpad.bugs[id]
            tasks = list(bug.bug_tasks)
            assert len(tasks) == 1
            t = tasks[0]
            t.status = 'Fix Released'
            t.lp_save()

        def _mark_report_new(self, id):
            '''Reopen a report ID as "new".'''

            bug = self.crashdb.launchpad.bugs[id]
            tasks = list(bug.bug_tasks)
            assert len(tasks) == 1
            t = tasks[0]
            t.status = 'New'
            t.lp_save()

        def _verify_marked_regression(self, id):
            '''Verify that report ID is marked as regression.'''

            bug = self.crashdb.launchpad.bugs[id]
            self.assertTrue('regression-retracer' in bug.tags)

        def test_project(self):
            '''reporting crashes against a project instead of a distro'''

            launchpad_instance = os.environ.get('APPORT_LAUNCHPAD_INSTANCE') or 'staging'
            # crash database for langpack-o-matic project (this does not have
            # packages in any distro)
            crashdb = CrashDatabase(os.environ.get('LP_CREDENTIALS'), '',
                {'project': 'langpack-o-matic',
                 'launchpad_instance': launchpad_instance})
            self.assertEqual(crashdb.distro, None)

            # create Python crash report
            r = apport.Report('Crash')
            r['ExecutablePath'] = '/bin/foo'
            r['Traceback'] = '''Traceback (most recent call last):
  File "/bin/foo", line 67, in fuzz
    print(weird)
NameError: global name 'weird' is not defined'''
            r.add_os_info()
            r.add_user_info()
            self.assertEqual(r.standard_title(), 
                    "foo crashed with NameError in fuzz(): global name 'weird' is not defined")

            # file it
            handle = crashdb.upload(r)
            self.assertTrue(handle)
            bug_target = self._get_bug_target(crashdb, r)
            self.assertEqual(bug_target.name, 'langpack-o-matic')

            id = self._file_bug(bug_target, r, handle)
            self.assertTrue(id > 0)
            sys.stderr.write('(https://%s/bugs/%i) ' % (self.hostname, id))

            # update
            r = crashdb.download(id)
            r['StacktraceTop'] = 'read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so'
            r['Stacktrace'] = 'long\ntrace'
            r['ThreadStacktrace'] = 'thread\neven longer\ntrace'
            crashdb.update_traces(id, r, 'good retrace!')
            r = crashdb.download(id)

            # test fixed version
            self.assertEqual(crashdb.get_fixed_version(id), None)
            crashdb.close_duplicate(id, self.known_test_id)
            self.assertEqual(crashdb.duplicate_of(id), self.known_test_id)
            self.assertEqual(crashdb.get_fixed_version(id), 'invalid')
            crashdb.close_duplicate(id, None)
            self.assertEqual(crashdb.duplicate_of(id), None)
            self.assertEqual(crashdb.get_fixed_version(id), None)

        def test_download_robustness(self):
            '''download() of uncommon description formats'''

            # only ProblemType/Architecture/DistroRelease in description
            r = self.crashdb.download(self.uncommon_description_bug.id)
            self.assertEqual(r['ProblemType'], 'Package')
            self.assertEqual(r['Architecture'], 'amd64')
            self.assertTrue(r['DistroRelease'].startswith('Ubuntu '))

        def test_escalation(self):
            '''Escalating bugs with more than 10 duplicates'''

            assert segv_report, 'you need to run test_1_report_segv() first'

            launchpad_instance = os.environ.get('APPORT_LAUNCHPAD_INSTANCE') or 'staging'
            db = CrashDatabase(os.environ.get('LP_CREDENTIALS'), '',
                    {'distro': 'ubuntu',
                     'launchpad_instance': launchpad_instance,
                     'escalation_tag': 'omgkittens',
                     'escalation_subscription': 'apport-hackers'})

            count = 0
            p = db.launchpad.people[db.options['escalation_subscription']].self_link
            first_dup = 59
            try:
                for b in range(first_dup, first_dup+13):
                    count += 1
                    sys.stderr.write('%i ' % b)
                    db.close_duplicate(b, segv_report)
                    b = db.launchpad.bugs[segv_report]
                    has_escalation_tag = db.options['escalation_tag'] in b.tags
                    has_escalation_subscription = any([s.person_link == p for s in b.subscriptions])
                    if count <= 10:
                        self.assertFalse(has_escalation_tag)
                        self.assertFalse(has_escalation_subscription)
                    else:
                        self.assertTrue(has_escalation_tag)
                        self.assertTrue(has_escalation_subscription)
            finally:
                for b in range(first_dup, first_dup+count):
                    sys.stderr.write('R%i ' % b)
                    db.close_duplicate(b, None)
            sys.stderr.write('\n')

        def test_marking_python_task_mangle(self):
            '''source package task fixup for marking interpreter crashes'''

            self._mark_needs_dupcheck(python_report)
            unchecked_before = self.crashdb.get_dup_unchecked()
            self.assertTrue(python_report in unchecked_before)

            # add an upstream task, and remove the package name from the
            # package task; _mark_dup_checked is supposed to restore the
            # package name
            b = self.crashdb.launchpad.bugs[python_report]
            t = b.bug_tasks[0]
            t.target = self.crashdb.launchpad.distributions['ubuntu'].getSourcePackage(name='bash')
            t.status = 'Invalid'
            t.lp_save()
            b.addTask(target=self.crashdb.launchpad.projects['coreutils'])
            b.addTask(target=self.crashdb.launchpad.distributions['ubuntu'])

            self.crashdb._mark_dup_checked(python_report, self.ref_report)

            unchecked_after = self.crashdb.get_dup_unchecked()
            self.assertFalse(python_report in unchecked_after)
            self.assertEqual(unchecked_before,
                    unchecked_after.union(set([python_report])))

            # upstream task should be unmodified
            b = self.crashdb.launchpad.bugs[python_report]
            self.assertEqual(b.bug_tasks[0].bug_target_name, 'coreutils')
            self.assertEqual(b.bug_tasks[0].status, 'New')

            # package-less distro task should have package name fixed
            self.assertEqual(b.bug_tasks[2].bug_target_name, 'coreutils (Ubuntu)')
            self.assertEqual(b.bug_tasks[2].status, 'New')

            # invalid bash task should be unmodified
            self.assertEqual(b.bug_tasks[1].bug_target_name, 'bash (Ubuntu)')
            self.assertEqual(b.bug_tasks[1].status, 'Invalid')

            # the invalid task should not confuse get_fixed_version()
            self.assertEqual(self.crashdb.get_fixed_version(python_report),
                    None)

    unittest.main()
