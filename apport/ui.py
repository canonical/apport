'''Abstract Apport user interface.

This encapsulates the workflow and common code for any user interface
implementation (like GTK, Qt, or CLI).

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import glob, sys, os.path, optparse, time, traceback, locale, gettext
import pwd, errno, urllib, zlib
import subprocess, threading, webbrowser
from gettext import gettext as _

import apport, apport.fileutils, REThread

from apport.crashdb import get_crashdb

def thread_collect_info(report, reportfile, package):
    '''Encapsulate call to add_*_info() and update given report,
    so that this function is suitable for threading.

    If reportfile is not None, the file is written back with the new data.'''

    report.add_gdb_info()
    if not package:
        if report.has_key('ExecutablePath'):
            package = apport.fileutils.find_file_package(report['ExecutablePath'])
        else:
            raise KeyError, 'called without a package, and report does not have ExecutablePath'
    report.add_package_info(package)
    report.add_hooks_info()
    report.add_os_info()

    # add title
    title = report.standard_title()
    if title:
        report['Title'] = title

    # check package origin
    if not apport.packaging.is_distro_package(report['Package'].split()[0]):
        #TRANS: %s is the name of the operating system
        report['UnreportableReason'] = _('This is not a genuine %s package') % \
            report['DistroRelease'].split()[0]

    # check obsolete packages
    if report['ProblemType'] == 'Crash' and \
        'APPORT_IGNORE_OBSOLETE_PACKAGES' not in os.environ:
        old_pkgs = report.obsolete_packages()
        if old_pkgs:
            report['UnreportableReason'] = _('You have some obsolete package \
versions installed. Please upgrade the following packages and check if the \
problem still occurs:\n\n%s') % ', '.join(old_pkgs)

    report.anonymize()

    if reportfile:
        f = open(reportfile, 'a')
        os.chmod (reportfile, 0)
        report.write(f, only_new=True)
        f.close()
        apport.fileutils.mark_report_seen(reportfile)
        os.chmod (reportfile, 0600)

class UserInterface:
    '''Abstract base class for encapsulating the workflow and common code for
       any user interface implementation (like GTK, Qt, or CLI).

       A concrete subclass must implement all the abstract ui_* methods.'''

    def __init__(self):
        '''Initialize program state and parse command line options.'''

        self.gettext_domain = 'apport'
        self.report = None
        self.report_file = None
        self.cur_package = None

        try:
            self.crashdb = get_crashdb(None)
        except ImportError, e:
            # this can happen while upgrading python packages
            print >> sys.stderr, 'Could not import module, is a package upgrade in progress? Error:', e
            sys.exit(1)

        gettext.textdomain(self.gettext_domain)
        self.parse_argv()

    #
    # main entry points
    #

    def run_crashes(self):
        '''Present all currently pending crash reports to the user, ask him
        what to do about them, and offer to file bugs for them.
        
        Return True if at least one crash report was processed, False
        otherwise.'''

        result = False

        for f in apport.fileutils.get_new_reports():
            self.run_crash(f)
            result = True

        return result

    def run_crash(self, report_file, confirm=True):
        '''Present given crash report to the user, ask him what to do about it,
        and offer to file a bug for it.
        
        If confirm is False, the user will not be asked whether to report the
        problem.'''

        self.report_file = report_file

        try:
            apport.fileutils.mark_report_seen(report_file)
            if not self.load_report(report_file):
                return

            # check for absent CoreDumps (removed if they exceed size limit)
            if self.report.get('ProblemType') == 'Crash' and \
                'Signal' in self.report and 'CoreDump' not in self.report and \
                'Stacktrace' not in self.report:
                subject = os.path.basename(self.report.get('ExecutablePath',
                    _('unknown program')))
                heading = _('Sorry, the program "%s" closed unexpectedly') % subject
                self.ui_error_message(_('Problem in %s') % subject,
                    "%s\n\n%s" % (heading, _('Your computer does not have enough \
free memory to automatically analyze the problem and send a report to the developers.')))
                return

            # check unsupportable flag
            if self.report.has_key('UnsupportableReason'):
                if self.report.get('ProblemType') == 'Kernel':
                    subject = _('kernel')
                elif self.report.get('ProblemType') == 'Package':
                    subject = self.report['Package']
                else:
                    subject = os.path.basename(self.report.get(
                        'ExecutablePath', _('unknown program')))
                self.ui_info_message(_('Problem in %s') % subject,
                    _('The current configuration cannot be supported:\n\n%s') %
                    self.report['UnsupportableReason'])
                return

            # ask the user about what to do with the current crash
            if not confirm:
                pass
            elif self.report.get('ProblemType') == 'Package':
                response = self.ui_present_package_error()
                if response == 'cancel':
                    return
                assert response == 'report'
            elif self.report.get('ProblemType') == 'Kernel':
                response = self.ui_present_kernel_error()
                if response == 'cancel':
                    return
                assert response == 'report'
            else:
                try:
                    desktop_entry = self.get_desktop_entry()
                except ValueError: # package does not exist
                    self.ui_error_message(_('Invalid problem report'),
                        _('The report belongs to a package that is not installed.'))
                    self.ui_shutdown()
                    return

                response = self.ui_present_crash(desktop_entry)
                assert response.has_key('action')
                assert response.has_key('blacklist')

                if response['blacklist']:
                    self.report.mark_ignore()

                if response['action'] == 'cancel':
                    return
                if response['action'] == 'restart':
                    self.restart()
                    return
                assert response['action'] == 'report'

            # we want to file a bug now
            try:
                self.collect_info()
            except (IOError, zlib.error):
                # can happen with broken core dumps
                self.report = None
                self.ui_error_message(_('Invalid problem report'),
                    _('This problem report is damaged and cannot be processed.'))
                return False
            except ValueError: # package does not exist
                self.ui_error_message(_('Invalid problem report'),
                    _('The report belongs to a package that is not installed.'))
                self.ui_shutdown()
                return

            # check unreportable flag
            if self.report.has_key('UnreportableReason'):
                self.ui_info_message(_('Problem in %s') % self.report['Package'].split()[0],
                    _('The problem cannot be reported:\n\n%s') %
                    self.report['UnreportableReason'])
                return

            if self.handle_duplicate():
                return

            if self.report.get('ProblemType') in ['Crash', 'Kernel']:
                response = self.ui_present_report_details()
                if response == 'cancel':
                    return
                if response == 'reduced':
                    try:
                        del self.report['CoreDump']
                    except KeyError:
                        pass # Huh? Should not happen, but did in https://launchpad.net/bugs/86007
                else:
                    assert response == 'full'

            self.file_report()
        except IOError, e:
            # fail gracefully if file is not readable for us
            if e.errno in (errno.EPERM, errno.EACCES):
                self.ui_error_message(_('Invalid problem report'),
                    _('You are not allowed to access this problem report.'))
                sys.exit(1)
            elif e.errno == errno.ENOSPC:
                self.ui_error_message(_('Error'),
                    _('There is not enough disk space available to process this report.'))
                sys.exit(1)
            else:
                raise
        except OSError, e:
            # fail gracefully on ENOMEM
            if e.errno == errno.ENOMEM:
                print >> sys.stderr, 'Out of memory, aborting'
                sys.exit(1)
            else:
                raise

    def run_report_bug(self):
        '''Report a bug.

        If a pid is given on the command line, the report will contain runtime
        debug information. If neither a package or a pid is specified, a
        generic distro bug is filed.'''

        self.report = apport.Report('Bug')
        try:
            if self.options.pid:
                self.report.add_proc_info(self.options.pid)
            else:
                self.report.add_proc_environ()
        except OSError, e:
            # silently ignore nonexisting PIDs; the user must not close the
            # application prematurely
            if e.errno == errno.ENOENT:
                return
            elif e.errno == errno.EACCES:
                self.ui_error_message(_('Permission denied'), 
                    _('The specified process does not belong to you. Please run this program as the process owner or as root.'))
                return
            else:
                raise
        self.cur_package = self.options.package

        try:
            self.collect_info()
        except ValueError, e:
            if e.message == 'package does not exist':
                self.ui_error_message(_('Invalid problem report'), 
                    _('Package %s does not exist') % self.cur_package)
                return
            else:
                raise

        if not self.handle_duplicate():
            # we do not confirm contents of bug reports, this might have
            # sensitive data
            try:
                del self.report['ProcCmdline']
            except KeyError:
                pass
            self.file_report()

    def run_argv(self):
        '''Call appopriate run_* method according to command line arguments.
        
        Return True if at least one report has been processed, and False
        otherwise.'''

        if self.options.filebug:
            self.run_report_bug()
            return True
        elif self.options.crash_file:
            try:
                self.run_crash(self.options.crash_file, False)
            except OSError, e:
                self.ui_error_message(_('Invalid problem report'), str(e))
            return True
        else:
            return self.run_crashes()

    #
    # functions that implement workflow bits
    #

    def parse_argv(self):
        '''Parse command line options and return (options,
        args) tuple.'''

        optparser = optparse.OptionParser('%prog [options]')
        optparser.add_option('-f', '--file-bug',
            help='Start in bug filing mode. Requires --package and an optional --pid, or just a --pid',
            action='store_true', dest='filebug', default=False)
        optparser.add_option('-p', '--package',
            help='Specify package name in --file-bug mode. This is optional if a --pid is specified.',
            action='store', type='string', dest='package', default=None)
        optparser.add_option('-P', '--pid',
            help='Specify a running program in --file-bug mode. If this is specified, the bug report will contain more information.',
            action='store', type='int', dest='pid', default=None)
        optparser.add_option('-c', '--crash-file',
            help='Report the crash from given .crash file instead of the pending ones in ' + apport.fileutils.report_dir,
            action='store', type='string', dest='crash_file', default=None, metavar='PATH')

        (self.options, self.args) = optparser.parse_args()

    def format_filesize(self, size):
        '''Format the given integer as humanly readable and i18n'ed file size.'''

        if size < 1048576:
            return locale.format('%.1f KiB', size/1024.)
        if size < 1024 * 1048576:
            return locale.format('%.1f MiB', size / 1048576.)
        return locale.format('%.1f GiB', size / float(1024 * 1048576))

    def get_complete_size(self):
        '''Return the size of the complete report.'''

        return self.complete_size

    def get_reduced_size(self):
        '''Return the size of the reduced report.'''

        size = 0
        for k in self.report:
            if k != 'CoreDump':
                if self.report[k]:
                    size += len(self.report[k])

        return size

    def restart(self):
        '''Reopen the crashed application.'''

        assert self.report.has_key('ProcCmdline')

        if os.fork() == 0:
            os.setsid()
            os.execlp('sh', 'sh', '-c', self.report.get('RespawnCommand', self.report['ProcCmdline']))
            sys.exit(1)

    def collect_info(self):
        '''Collect missing information about the report from the system and
        display a progress dialog in the meantime.

        In particular, this adds OS, package and gdb information and checks bug
        patterns.'''

        if not self.cur_package and not self.report.has_key('ExecutablePath'):
            # this happens if we file a bug without specifying a PID or a
            # package
            self.report.add_os_info()
        else:
            # report might already be pre-processed by apport-retrace
            if self.report['ProblemType'] == 'Crash' and 'Stacktrace' in self.report:
                return

            # since this might take a while, create separate threads and
            # display a progress dialog
            self.ui_start_info_collection_progress()

            if self.report['ProblemType'] != 'Kernel' and not self.report.has_key('Stacktrace'):
                icthread = REThread.REThread(target=thread_collect_info,
                    name='thread_collect_info',
                    args=(self.report, self.report_file, self.cur_package))
                icthread.start()
                while icthread.isAlive():
                    self.ui_pulse_info_collection_progress()
                    try:
                        icthread.join(0.1)
                    except KeyboardInterrupt:
                        sys.exit(1)
                icthread.exc_raise()

            if self.report['ProblemType'] == 'Kernel' or self.report.has_key('Package'):
                bpthread = REThread.REThread(target=self.report.search_bug_patterns,
                    args=(self.crashdb.get_bugpattern_baseurl(),))
                bpthread.start()
                while bpthread.isAlive():
                    self.ui_pulse_info_collection_progress()
                    try:
                        bpthread.join(0.1)
                    except KeyboardInterrupt:
                        sys.exit(1)
                bpthread.exc_raise()
                if bpthread.return_value():
                    self.report['BugPatternURL'] = bpthread.return_value()

            self.ui_stop_info_collection_progress()

            # check that we were able to determine package names
            if not self.report.has_key('SourcePackage') or \
                (self.report['ProblemType'] != 'Kernel' and not self.report.has_key('Package')):
                self.ui_error_message(_('Invalid problem report'),
                    _('Could not determine the package or source package name.'))
                # TODO This is not called consistently, is it really needed?
                self.ui_shutdown()
                sys.exit(1)

    def open_url(self, url):
        '''Open the given URL in a new browser window.

        Display an error dialog if everything fails.'''

        (r, w) = os.pipe()
        if os.fork() > 0:
            os.close(w)
            (pid, status) = os.wait()
            if status:
                title = _('Unable to start web browser')
                error = _('Unable to start web browser to open %s.' % url)
                message = os.fdopen(r).readline()
                if message:
                    error += '\n' + message
                self.ui_error_message(title, error)
            try:
                os.close(r)
            except OSError:
                pass
            return

        os.setsid()
        os.close(r)

        # If we are called through sudo, determine the real user id and run the
        # browser with it to get the user's web browser settings.
        try:
            uid = int(os.getenv('SUDO_UID'))
            gid = int(os.getenv('SUDO_GID'))
            sudo_prefix = ['sudo', '-H', '-u', '#'+str(uid)]
        except (TypeError):
            uid = os.getuid()
            gid = None
            sudo_prefix = []

        # figure out appropriate web browser
        try:
            # if ksmserver is running, try kfmclient
            try:
                if os.getenv('DISPLAY') and \
                        subprocess.call(['pgrep', '-x', '-u', str(uid), 'ksmserver'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
                    subprocess.call(sudo_prefix + ['kfmclient', 'openURL', url])
                    sys.exit(0)
            except OSError:
                pass

            # if gnome-session is running, try gnome-open; special-case firefox
            # to open a new window
            try:
                if os.getenv('DISPLAY') and \
                        subprocess.call(['pgrep', '-x', '-u', str(uid), 'gnome-session'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
                    gct = subprocess.Popen(sudo_prefix + ['gconftool', '--get',
                        '/desktop/gnome/url-handlers/http/command'],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if 'firefox' in gct.communicate()[0] and gct.returncode == 0:
                        subprocess.call(sudo_prefix + ['firefox', '-new-window', url])
                        sys.exit(0)
                    else:
                        if subprocess.call(sudo_prefix + ['gnome-open', url]) == 0:
                            sys.exit(0)
            except OSError:
                pass

            # fall back to webbrowser
            if uid and gid:
                os.setgroups([gid])
                os.setgid(gid)
                os.setuid(uid)
                os.unsetenv('SUDO_USER') # to make firefox not croak
                os.environ['HOME'] = pwd.getpwuid(uid).pw_dir

            webbrowser.open(url, new=True, autoraise=True)
            sys.exit(0)

        except Exception, e:
            os.write(w, str(e))
            sys.exit(1)

    def file_report(self):
        '''Upload the current report to the tracking system and guide the user
        to its web page.'''

        global __upload_progress
        __upload_progress = None

        def progress_callback(sent, total):
            global __upload_progress
            __upload_progress = float(sent)/total

        self.ui_start_upload_progress()
        upthread = REThread.REThread(target=self.crashdb.upload,
            args=(self.report, progress_callback))
        upthread.start()
        while upthread.isAlive():
            self.ui_set_upload_progress(__upload_progress)
            try:
                upthread.join(0.1)
            except KeyboardInterrupt:
                sys.exit(1)
        if upthread.exc_info():
            self.ui_error_message(_('Network problem'),
                "%s:\n\n%s" % (
                    _('Could not upload report data to crash database'),
                    str(upthread.exc_info()[1])
                ))
            return

        ticket = upthread.return_value()
        self.ui_stop_upload_progress()

        url = self.crashdb.get_comment_url(self.report, ticket)
        if url:
            self.open_url(url)

    def load_report(self, path):
        '''Load report from given path and do some consistency checks.

        This might issue an error message and return False if the report cannot
        be processed, otherwise self.report is initialized and True is
        returned.'''

        try:
            self.report = apport.Report()
            self.report.load(open(path), binary='compressed')
        except MemoryError:
            self.report = None
            self.ui_error_message(_('Memory exhaustion'),
                _('Your system does not have enough memory to process this crash report.'))
            return False
        except (TypeError, ValueError, IOError, zlib.error):
            self.report = None
            self.ui_error_message(_('Invalid problem report'),
                _('This problem report is damaged and cannot be processed.'))
            return False

        if self.report.has_key('Package'):
            self.cur_package = self.report['Package'].split()[0]
        else:
            self.cur_package = apport.fileutils.find_file_package(self.report.get('ExecutablePath', ''))

        exe_path = self.report.get('InterpreterPath', self.report.get('ExecutablePath'))
        if not self.cur_package and self.report['ProblemType'] != 'Kernel' or (
            exe_path and not os.path.exists(exe_path)):
            msg = _('This problem report does not apply to a packaged program.')
            if self.report.has_key('ExecutablePath'):
                msg = '%s (%s)' % (msg, self.report['ExecutablePath'])
            self.report = None
            self.ui_info_message(_('Invalid problem report'), msg)
            return False

        self.complete_size = os.path.getsize(path)

        return True

    def get_desktop_entry(self):
        '''Try to get a matching .desktop file entry (xdg.DesktopEntry) for the
        current self.report and return it.'''

        if self.report.has_key('DesktopFile') and os.path.exists(self.report['DesktopFile']):
            desktop_file = self.report['DesktopFile']
        else:
            desktop_file = apport.fileutils.find_package_desktopfile(self.cur_package)
        if desktop_file:
            try:
                import xdg.DesktopEntry
                return xdg.DesktopEntry.DesktopEntry(desktop_file)
            except:
                return None

    def handle_duplicate(self):
        '''Check whether the current bug report is already known as a bug
        pattern, and if so, tell the user about it, open the existing bug, and
        return True.'''

        if not self.report.has_key('BugPatternURL'):
            return False

        self.ui_info_message(_('Problem already known'),
            _('This problem was already reported in the bug report displayed \
in the web browser. Please check if you can add any further information that \
might be helpful for the developers.'))

        self.open_url(self.report['BugPatternURL'])
        return True

    #
    # abstract UI methods that must be implemented in derived classes
    #

    def ui_present_crash(self, desktopentry):
        '''Inform that a crash has happened for self.report and
        self.cur_package and ask about an action.

        If the package can be mapped to a desktop file, an xdg.DesktopEntry is
        passed as an argument; this can be used for enhancing strings, etc.

        Return the action and options as a dictionary:

        - Valid values for the 'action' key: ignore the crash ('cancel'), restart
          the crashed application ('restart'), or report a bug about the crash
          ('report').
        - Valid values for the 'blacklist' key: True or False (True will cause
          the invocation of report.mark_ignore()).'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_present_package_error(self, desktopentry):
        '''Inform that a package installation/upgrade failure has happened for
        self.report and self.cur_package and ask about an action.

        Return the action: ignore ('cancel'), or report a bug about the problem
        ('report').'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_present_kernel_error(self, desktopentry):
        '''Inform that a kernel Oops has happened for self.report and
        ask about an action.

        Return the action: ignore ('cancel'), or report a bug about the problem
        ('report').'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_present_report_details(self):
        '''Show details of the bug report and choose between sending a complete
        or reduced report.

        This function can use the get_complete_size() and get_reduced_size()
        methods to determine the respective size of the data to send, and
        format_filesize() to convert it to a humanly readable form.

        Return the action: send full report ('full'), send reduced report
        ('reduced'), or do not send anything ('cancel').'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_info_message(self, title, text):
        '''Show an information message box with given title and text.'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_error_message(self, title, text):
        '''Show an error message box with given title and text.'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_start_info_collection_progress(self):
        '''Open a window with an indefinite progress bar, telling the user to
        wait while debug information is being collected.'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_pulse_info_collection_progress(self):
        '''Advance the progress bar in the debug data collection progress
        window.

        This function is called every 100 ms.'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_stop_info_collection_progress(self):
        '''Close debug data collection progress window.'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_start_upload_progress(self):
        '''Open a window with an definite progress bar, telling the user to
        wait while debug information is being uploaded.'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_set_upload_progress(self, progress):
        '''Set the progress bar in the debug data upload progress
        window to the given ratio (between 0 and 1, or None for indefinite
        progress).

        This function is called every 100 ms.'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_stop_upload_progress(self):
        '''Close debug data upload progress window.'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_shutdown(self):
        '''This is called right before terminating the program and can be used
        for cleaning up.'''

        pass

#
# Test suite
#

if  __name__ == '__main__':
    import unittest, shutil, signal, tempfile
    from cStringIO import StringIO

    class _TestSuiteUserInterface(UserInterface):
        '''Concrete UserInterface suitable for automatic testing.'''

        def __init__(self):
            # use our dummy crashdb
            self.crashdb_conf = tempfile.NamedTemporaryFile()
            print >> self.crashdb_conf, '''default = 'testsuite'
databases = {
    'testsuite': { 
        'impl': 'memory',
        'bug_pattern_base': None
    }
}
'''
            self.crashdb_conf.flush()

            os.environ['APPORT_CRASHDB_CONF'] = self.crashdb_conf.name

            UserInterface.__init__(self)

            # state of progress dialogs
            self.ic_progress_active = False
            self.ic_progress_pulses = 0 # count the pulses
            self.upload_progress_active = False
            self.upload_progress_pulses = 0

            # these store the choices the ui_present_* calls do
            self.present_crash_response = None
            self.present_package_error_response = None
            self.present_kernel_error_response = None
            self.present_details_response = None

            self.opened_url = None

            self.clear_msg()

        def clear_msg(self):
            # last message box
            self.msg_title = None
            self.msg_text = None
            self.msg_severity = None # 'warning' or 'error'

        def ui_present_crash(self, desktopentry):
            return self.present_crash_response

        def ui_present_package_error(self):
            return self.present_package_error_response

        def ui_present_kernel_error(self):
            return self.present_kernel_error_response

        def ui_present_report_details(self):
            return self.present_details_response

        def ui_info_message(self, title, text):
            self.msg_title = title
            self.msg_text = text
            self.msg_severity = 'info'

        def ui_error_message(self, title, text):
            self.msg_title = title
            self.msg_text = text
            self.msg_severity = 'error'

        def ui_start_info_collection_progress(self):
            self.ic_progress_pulses = 0
            self.ic_progress_active = True

        def ui_pulse_info_collection_progress(self):
            assert self.ic_progress_active
            self.ic_progress_pulses += 1

        def ui_stop_info_collection_progress(self):
            self.ic_progress_active = False

        def ui_start_upload_progress(self):
            self.upload_progress_pulses = 0
            self.upload_progress_active = True

        def ui_set_upload_progress(self, progress):
            assert self.upload_progress_active
            self.upload_progress_pulses += 1

        def ui_stop_upload_progress(self):
            self.upload_progress_active = False

        def open_url(self, url):
            self.opened_url = url

    class _UserInterfaceTest(unittest.TestCase):
        def setUp(self):
            # we test a few strings, don't get confused by translations
            for v in ['LANG', 'LANGUAGE', 'LC_MESSAGES', 'LC_ALL']:
                try:
                    del os.environ[v]
                except KeyError:
                    pass

            self.orig_report_dir = apport.fileutils.report_dir
            apport.fileutils.report_dir = tempfile.mkdtemp()
            self.orig_ignore_file = apport.report._ignore_file
            (fd, apport.report._ignore_file) = tempfile.mkstemp()
            os.close(fd)

            # need to do this to not break ui's ctor
            self.orig_argv = sys.argv
            sys.argv = ['ui-test']
            self.ui = _TestSuiteUserInterface()

            # demo report
            self.report = apport.Report()
            self.report['Package'] = 'libfoo1 1-1'
            self.report['SourcePackage'] = 'foo'
            self.report['Foo'] = 'A' * 1000
            self.report['CoreDump'] = 'A' * 100000

            # write demo report into temporary file
            self.report_file = tempfile.NamedTemporaryFile()
            self.update_report_file()

        def update_report_file(self):
            self.report_file.seek(0)
            self.report_file.truncate()
            self.report.write(self.report_file)
            self.report_file.flush()

        def tearDown(self):
            sys.argv = self.orig_argv
            shutil.rmtree(apport.fileutils.report_dir)
            apport.fileutils.report_dir = self.orig_report_dir
            self.orig_report_dir = None

            os.unlink(apport.report._ignore_file)
            apport.report._ignore_file = self.orig_ignore_file

            self.ui = None
            self.report_file.close()

            self.assertEqual(subprocess.call(['pidof', '/bin/cat']), 1, 'no stray cats')
            self.assertEqual(subprocess.call(['pidof', '/bin/sleep']), 1, 'no stray sleeps')

        def test_format_filesize(self):
            '''Test format_filesize().'''

            self.assertEqual(self.ui.format_filesize(0), '0.0 KiB')
            self.assertEqual(self.ui.format_filesize(2048), '2.0 KiB')
            self.assertEqual(self.ui.format_filesize(2560), '2.5 KiB')
            self.assertEqual(self.ui.format_filesize(1000000), '976.6 KiB')
            self.assertEqual(self.ui.format_filesize(1048576), '1.0 MiB')
            self.assertEqual(self.ui.format_filesize(2.7*1048576), '2.7 MiB')
            self.assertEqual(self.ui.format_filesize(1024*1048576), '1.0 GiB')
            self.assertEqual(self.ui.format_filesize(2560*1048576), '2.5 GiB')

        def test_get_size(self):
            '''Test get_complete_size() and get_reduced_size().'''

            self.ui.load_report(self.report_file.name)

            self.assertEqual(self.ui.get_complete_size(),
                os.path.getsize(self.report_file.name))
            rs = self.ui.get_reduced_size()
            self.assert_(rs > 1000)
            self.assert_(rs < 10000)

        def test_load_report(self):
            '''Test load_report().'''

            # valid report
            self.ui.load_report(self.report_file.name)
            self.assertEqual(self.ui.report, self.report)
            self.assertEqual(self.ui.msg_title, None)

            # report without Package
            del self.report['Package']
            del self.report['SourcePackage']
            self.update_report_file()
            self.ui.load_report(self.report_file.name)

            self.assert_(self.ui.report == None)
            self.assertEqual(self.ui.msg_title, _('Invalid problem report'))
            self.assertEqual(self.ui.msg_severity, 'info')

            self.ui.clear_msg()

            # invalid base64 encoding
            self.report_file.seek(0)
            self.report_file.truncate()
            self.report_file.write('''Type: test
Package: foo 1-1
CoreDump: base64
 bOgUs=
''')
            self.report_file.flush()

            self.ui.load_report(self.report_file.name)
            self.assert_(self.ui.report == None)
            self.assertEqual(self.ui.msg_title, _('Invalid problem report'))
            self.assertEqual(self.ui.msg_severity, 'error')

        def test_restart(self):
            '''Test restart().'''

            # test with only ProcCmdline
            p = os.path.join(apport.fileutils.report_dir, 'ProcCmdline')
            r = os.path.join(apport.fileutils.report_dir, 'Custom')
            self.report['ProcCmdline'] = 'touch ' + p
            self.update_report_file()
            self.ui.load_report(self.report_file.name)

            self.ui.restart()
            time.sleep(1) # FIXME: race condition
            self.assert_(os.path.exists(p))
            self.assert_(not os.path.exists(r))
            os.unlink(p)

            # test with RespawnCommand
            self.report['RespawnCommand'] = 'touch ' + r
            self.update_report_file()
            self.ui.load_report(self.report_file.name)

            self.ui.restart()
            time.sleep(1) # FIXME: race condition
            self.assert_(not os.path.exists(p))
            self.assert_(os.path.exists(r))
            os.unlink(r)

            # test that invalid command does not make us fall apart
            del self.report['RespawnCommand']
            self.report['ProcCmdline'] = '/nonexisting'
            self.update_report_file()
            self.ui.load_report(self.report_file.name)

        def test_collect_info_distro(self):
            '''Test collect_info() on report without information (distro bug).'''

            # report without any information (distro bug)
            self.ui.report = apport.Report()
            self.ui.collect_info()
            self.assert_(set(['Date', 'Uname', 'DistroRelease', 'ProblemType']).issubset(
                set(self.ui.report.keys())))
            self.assertEqual(self.ui.ic_progress_pulses, 0,
                'no progress dialog for distro bug info collection')

        def test_collect_info_exepath(self):
            '''Test collect_info() on report with only ExecutablePath.'''

            # report with only package information
            self.report = apport.Report()
            self.report['ExecutablePath'] = '/bin/bash'
            self.update_report_file()
            self.ui.load_report(self.report_file.name)
            self.ui.collect_info()
            self.assert_(set(['SourcePackage', 'Package', 'ProblemType',
                'Uname', 'Dependencies', 'DistroRelease', 'Date',
                'ExecutablePath']).issubset(set(self.ui.report.keys())))
            self.assert_(self.ui.ic_progress_pulses > 0,
                'progress dialog for package bug info collection')
            self.assertEqual(self.ui.ic_progress_active, False,
                'progress dialog for package bug info collection finished')

        def test_collect_info_package(self):
            '''Test collect_info() on report with a package.'''

            # report with only package information
            self.ui.report = apport.Report()
            self.ui.cur_package = 'bash'
            self.ui.collect_info()
            self.assert_(set(['SourcePackage', 'Package', 'ProblemType',
                'Uname', 'Dependencies', 'DistroRelease',
                'Date']).issubset(set(self.ui.report.keys())))
            self.assert_(self.ui.ic_progress_pulses > 0,
                'progress dialog for package bug info collection')
            self.assertEqual(self.ui.ic_progress_active, False,
                'progress dialog for package bug info collection finished')

        def test_handle_duplicate(self):
            '''Test handle_duplicate().'''

            self.ui.load_report(self.report_file.name)
            self.assertEqual(self.ui.handle_duplicate(), False)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)

            demo_url = 'http://example.com/1'
            self.report['BugPatternURL'] = demo_url
            self.update_report_file()
            self.ui.load_report(self.report_file.name)
            self.assertEqual(self.ui.handle_duplicate(), True)
            self.assertEqual(self.ui.msg_severity, 'info')
            self.assertEqual(self.ui.opened_url, demo_url)

        def test_run_nopending(self):
            '''Test running the frontend without any pending reports.'''

            sys.argv = []
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), False)

        def test_run_report_bug_distro(self):
            '''Test run_report_bug() for a general distro bug.'''

            self.ui.run_report_bug()
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, 'http://bug.net/%i' % self.ui.crashdb.latest_id())

            self.assert_(set(['Date', 'Uname', 'DistroRelease', 'ProblemType', 'ProcEnviron']).issubset(
                set(self.ui.report.keys())), 'report has required fields')

        def test_run_report_bug_package(self):
            '''Test run_report_bug() for a package.'''

            sys.argv = ['ui-test', '-f', '-p', 'bash']
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), True)

            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, 'http://bash.bug.net/%i' % self.ui.crashdb.latest_id())

            self.assert_(self.ui.ic_progress_pulses > 0)
            self.assertEqual(self.ui.report['SourcePackage'], 'bash')
            self.assert_('Dependencies' in self.ui.report.keys())
            self.assert_('ProcEnviron' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Bug')

            # should not crash on nonexisting package
            sys.argv = ['ui-test', '-f', '-p', 'nonexisting_gibberish']
            self.ui = _TestSuiteUserInterface()
            self.ui.run_argv()

            self.assertEqual(self.ui.msg_severity, 'error')

        def test_run_report_bug_pid(self):
            '''Test run_report_bug() for a pid.'''

            # fork a test process
            pid = os.fork()
            if pid == 0:
                os.execv('/bin/sleep', ['sleep', '10000'])
                assert False, 'Could not execute /bin/sleep'

            time.sleep(0.5)

            try:
                # report a bug on cat process
                sys.argv = ['ui-test', '-f', '-P', str(pid)]
                self.ui = _TestSuiteUserInterface()
                self.assertEqual(self.ui.run_argv(), True)
            finally:
                # kill test process
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

            self.assert_('SourcePackage' in self.ui.report.keys())
            self.assert_('Dependencies' in self.ui.report.keys())
            self.assert_('ProcMaps' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ExecutablePath'], '/bin/sleep')
            self.failIf(self.ui.report.has_key('ProcCmdline')) # privacy!
            self.assert_('ProcEnviron' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Bug')

            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, 'http://coreutils.bug.net/%i' % self.ui.crashdb.latest_id())
            self.assert_(self.ui.ic_progress_pulses > 0)

        def test_run_report_bug_wrong_pid(self):
            '''Test run_report_bug() for a nonexisting pid.'''

            # search an unused pid
            pid = 1
            while True:
                pid += 1
                try:
                    os.kill(pid, 0)
                except OSError, e:
                    if e.errno == errno.ESRCH:
                        break

            # silently ignore missing PID; this happens when the user closes
            # the application prematurely
            sys.argv = ['ui-test', '-f', '-P', str(pid)]
            self.ui = _TestSuiteUserInterface()
            self.ui.run_argv()

        def test_run_report_bug_noperm_pid(self):
            '''Test run_report_bug() for a pid which runs as a different user.'''

            assert os.getuid() > 0, 'this test must not be run as root'

            # silently ignore missing PID; this happens when the user closes
            # the application prematurely
            sys.argv = ['ui-test', '-f', '-P', '1']
            self.ui = _TestSuiteUserInterface()
            self.ui.run_argv()

            self.assertEqual(self.ui.msg_severity, 'error')

        def _gen_test_crash(self):
            '''Generate a Report with real crash data.'''

            # create a test executable
            test_executable = '/bin/cat'
            assert os.access(test_executable, os.X_OK), test_executable + ' is not executable'
            pid = os.fork()
            if pid == 0:
                os.setsid()
                os.execv(test_executable, [test_executable])
                assert False, 'Could not execute ' + test_executable

            try:
                # generate a core dump
                time.sleep(0.5)
                coredump = os.path.join(apport.fileutils.report_dir, 'core')
                assert subprocess.call(['gdb', '--batch', '--ex', 'generate-core-file '
                    + coredump, test_executable, str(pid)], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE) == 0

                # generate crash report
                r = apport.Report()
                r['ExecutablePath'] = test_executable
                r['CoreDump'] = (coredump,)
                r['Signal'] = '11'
                r.add_proc_info(pid)
                r.add_user_info()
            finally:
                # kill test executable
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

            return r

        def test_run_crash(self):
            '''Test run_crash().'''

            r = self._gen_test_crash()

            # write crash report
            report_file = os.path.join(apport.fileutils.report_dir, 'test.crash')

            # cancel crash notification dialog
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_crash_response = {'action': 'cancel', 'blacklist': False }
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertEqual(self.ui.ic_progress_pulses, 0)

            # report in crash notification dialog, cancel details report
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_crash_response = {'action': 'report', 'blacklist': False }
            self.ui.present_details_response = 'cancel'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None, 'has %s message: %s: %s' % (
                self.ui.msg_severity, str(self.ui.msg_title), str(self.ui.msg_text)))
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertNotEqual(self.ui.ic_progress_pulses, 0)

            # report in crash notification dialog, send full report
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_crash_response = {'action': 'report', 'blacklist': False }
            self.ui.present_details_response = 'full'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, 'http://coreutils.bug.net/%i' % self.ui.crashdb.latest_id())
            self.assertNotEqual(self.ui.ic_progress_pulses, 0)

            self.assert_('SourcePackage' in self.ui.report.keys())
            self.assert_('Dependencies' in self.ui.report.keys())
            self.assert_('Stacktrace' in self.ui.report.keys())
            self.assert_('ProcEnviron' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Crash')
            self.assert_(len(self.ui.report['CoreDump']) > 10000)
            self.assert_(self.ui.report['Title'].startswith('cat crashed with SIGSEGV'))

            # report in crash notification dialog, send reduced report
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_crash_response = {'action': 'report', 'blacklist': False }
            self.ui.present_details_response = 'reduced'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, 'http://coreutils.bug.net/%i' % self.ui.crashdb.latest_id())
            self.assertNotEqual(self.ui.ic_progress_pulses, 0)

            self.assert_('SourcePackage' in self.ui.report.keys())
            self.assert_('Dependencies' in self.ui.report.keys())
            self.assert_('Stacktrace' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Crash')
            self.assert_(not self.ui.report.has_key('CoreDump'))

            # so far we did not blacklist, verify that
            self.assert_(not self.ui.report.check_ignored())

            # cancel crash notification dialog and blacklist
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_crash_response = {'action': 'cancel', 'blacklist': True }
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertEqual(self.ui.ic_progress_pulses, 0)

            self.assert_(self.ui.report.check_ignored())

        def test_run_crash_argv_file(self):
            '''Test run_crash() through a file specified on the command line.'''

            self.report['Package'] = 'bash'
            self.report['UnsupportableReason'] = 'It stinks.'
            self.update_report_file()

            sys.argv = ['ui-test', '-c', self.report_file.name]
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), True)

            self.assert_('It stinks.' in self.ui.msg_text, '%s: %s' %
                (self.ui.msg_title, self.ui.msg_text))
            self.assertEqual(self.ui.msg_severity, 'info')

            # should not die with an exception on an invalid name
            sys.argv = ['ui-test', '-c', '/nonexisting.crash' ]
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), True)
            self.assertEqual(self.ui.msg_severity, 'error')
            self.assert_('/nonexisting.crash' in self.ui.msg_text, self.ui.msg_text)

        def test_run_crash_unsupportable(self):
            '''Test run_crash() on a crash with the UnsupportableReason
            field.'''

            self.report['UnsupportableReason'] = 'It stinks.'
            self.report['Package'] = 'bash'
            self.update_report_file()

            self.ui.run_crash(self.report_file.name)

            self.assert_('It stinks.' in self.ui.msg_text, '%s: %s' %
                (self.ui.msg_title, self.ui.msg_text))
            self.assertEqual(self.ui.msg_severity, 'info')

        def test_run_crash_unreportable(self):
            '''Test run_crash() on a crash with the UnreportableReason
            field.'''

            self.report['UnreportableReason'] = 'It stinks.'
            self.report['ExecutablePath'] = '/bin/bash'
            self.report['Package'] = 'bash 1'
            self.update_report_file()
            self.ui.present_crash_response = {'action': 'report', 'blacklist': False }
            self.ui.present_details_response = 'full'

            self.ui.run_crash(self.report_file.name)

            self.assert_('It stinks.' in self.ui.msg_text, '%s: %s' %
                (self.ui.msg_title, self.ui.msg_text))
            self.assertEqual(self.ui.msg_severity, 'info')

        def test_run_crash_nocore(self):
            '''Test run_crash() for a crash dump without CoreDump.'''

            # create a test executable
            test_executable = '/bin/cat'
            assert os.access(test_executable, os.X_OK), test_executable + ' is not executable'
            pid = os.fork()
            if pid == 0:
                os.setsid()
                os.execv(test_executable, [test_executable])
                assert False, 'Could not execute ' + test_executable

            try:
                time.sleep(0.5)
                # generate crash report
                r = apport.Report()
                r['ExecutablePath'] = test_executable
                r['Signal'] = '42'
                r.add_proc_info(pid)
                r.add_user_info()
            finally:
                # kill test executable
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

            # write crash report
            report_file = os.path.join(apport.fileutils.report_dir, 'test.crash')
            r.write(open(report_file, 'w'))

            # run
            self.ui = _TestSuiteUserInterface()
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, 'error')
            self.assert_('memory' in self.ui.msg_text, '%s: %s' %
                (self.ui.msg_title, self.ui.msg_text))

        def test_run_crash_preretraced(self):
            '''Test run_crash() pre-retraced reports.
            
            This happens with crashes which are pre-processed by
            apport-retrace.'''

            r = self._gen_test_crash()

            #  effect of apport-retrace -c
            r.add_gdb_info()
            del r['CoreDump']

            # write crash report
            report_file = os.path.join(apport.fileutils.report_dir, 'test.crash')

            # report in crash notification dialog, cancel details report
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_crash_response = {'action': 'report', 'blacklist': False }
            self.ui.present_details_response = 'cancel'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None, 'has %s message: %s: %s' % (
                self.ui.msg_severity, str(self.ui.msg_title), str(self.ui.msg_text)))
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertEqual(self.ui.ic_progress_pulses, 0)
           
        def test_run_crash_errors(self):
            '''Test run_crash() on various error conditions.'''

            # crash report with invalid Package name
            r = apport.Report()
            r['ExecutablePath'] = '/bin/bash'
            r['Package'] = 'foobarbaz'
            r['SourcePackage'] = 'foobarbaz'
            report_file = os.path.join(apport.fileutils.report_dir, 'test.crash')
            r.write(open(report_file, 'w'))

            self.ui.run_crash(report_file)

            self.assertEqual(self.ui.msg_title, _('Invalid problem report'))
            self.assertEqual(self.ui.msg_severity, 'error')

        def test_run_crash_uninstalled(self):
            '''Test run_crash() on reports with subsequently uninstalled packages'''

            # program got uninstalled between crash and report
            r = self._gen_test_crash()
            r['ExecutablePath'] = '/bin/nonexisting'
            r['Package'] = 'bash'
            report_file = os.path.join(apport.fileutils.report_dir, 'test.crash')
            r.write(open(report_file, 'w'))

            self.ui.present_crash_response = {'action': 'report', 'blacklist': False }
            self.ui.run_crash(report_file)

            self.assertEqual(self.ui.msg_title, _('Invalid problem report'))
            self.assertEqual(self.ui.msg_severity, 'info')

            # interpreted program got uninstalled between crash and report
            r = apport.Report()
            r['ExecutablePath'] = '/bin/nonexisting'
            r['InterpreterPath'] = '/usr/bin/python'
            r['Traceback'] = 'ZeroDivisionError: integer division or modulo by zero'

            self.ui.run_crash(report_file)

            self.assertEqual(self.ui.msg_title, _('Invalid problem report'))
            self.assertEqual(self.ui.msg_severity, 'info')

            # interpreter got uninstalled between crash and report
            r = apport.Report()
            r['ExecutablePath'] = '/bin/sh'
            r['InterpreterPath'] = '/usr/bin/nonexisting'
            r['Traceback'] = 'ZeroDivisionError: integer division or modulo by zero'

            self.ui.run_crash(report_file)

            self.assertEqual(self.ui.msg_title, _('Invalid problem report'))
            self.assertEqual(self.ui.msg_severity, 'info')

        def test_run_crash_package(self):
            '''Test run_crash() for a package error.'''

            # generate crash report
            r = apport.Report('Package')
            r['Package'] = 'bash'
            r['SourcePackage'] = 'bash'
            r['ErrorMessage'] = 'It broke'
            r['VarLogPackagerlog'] = 'foo\nbar'
            r.add_os_info()

            # write crash report
            report_file = os.path.join(apport.fileutils.report_dir, 'test.crash')

            # cancel crash notification dialog
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_package_error_response = 'cancel'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertEqual(self.ui.ic_progress_pulses, 0)

            # report in crash notification dialog, send report
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_package_error_response = 'report'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, 'http://bash.bug.net/%i' % self.ui.crashdb.latest_id())

            self.assert_('SourcePackage' in self.ui.report.keys())
            self.assert_('Package' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Package')

            # verify that additional information has been collected
            self.assert_('PackageArchitecture' in self.ui.report.keys())
            self.assert_('DistroRelease' in self.ui.report.keys())
            self.assert_('Uname' in self.ui.report.keys())

        def test_run_crash_kernel(self):
            '''Test run_crash() for a kernel error.'''

            # generate crash report
            r = apport.Report('Kernel')
            r['SourcePackage'] = 'linux-source-2.6.20'
            r.add_os_info()

            # write crash report
            report_file = os.path.join(apport.fileutils.report_dir, 'test.crash')

            # cancel crash notification dialog
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_kernel_error_response = 'cancel'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None, 'error: %s - %s' %
                (self.ui.msg_title, self.ui.msg_text))
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertEqual(self.ui.ic_progress_pulses, 0)

            # report in crash notification dialog, send report
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_kernel_error_response = 'report'
            self.ui.present_details_response = 'full'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, 'http://linux-source-2.6.20.bug.net/%i' % self.ui.crashdb.latest_id())

            self.assert_('SourcePackage' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Kernel')

        def test_run_crash_anonymity(self):
            '''Test run_crash() anonymization.'''

            r = self._gen_test_crash()
            report_file = os.path.join(apport.fileutils.report_dir, 'test.crash')
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_crash_response = {'action': 'report', 'blacklist': False }
            self.ui.present_details_response = 'cancel'
            self.ui.run_crash(report_file)

            self.failIf('ProcCwd' in self.ui.report)

            dump = StringIO()
            self.ui.report.write(dump)

            p = pwd.getpwuid(os.getuid())
            bad_strings = [os.uname()[1], p[0], p[4], p[5], os.getcwd()]

            for s in bad_strings:
                self.failIf(s in dump.getvalue(), 'dump contains sensitive string: %s' % s)


    unittest.main()

