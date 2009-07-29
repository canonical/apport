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

import glob, sys, os.path, optparse, time, traceback, locale, gettext, re
import pwd, errno, urllib, zlib
import subprocess, threading, webbrowser
from gettext import gettext as _

import apport, apport.fileutils, REThread

from apport.crashdb import get_crashdb, NeedsCredentials

symptom_script_dir = '/usr/share/apport/symptoms'

def thread_collect_info(report, reportfile, package, ui, symptom_script=None):
    '''Collect information about report.

    Encapsulate calls to add_*_info() and update given report, so that this
    function is suitable for threading.

    ui must be a HookUI instance, it gets passed to add_hooks_info().

    If reportfile is not None, the file is written back with the new data.

    If symptom_script is given, it will be run first (for run_symptom()).
    '''
    report.add_gdb_info()
    report.add_os_info()

    if symptom_script:
        symb = {}
        try:
            execfile(symptom_script, symb)
            package = symb['run'](report, ui)
            if not package:
                print >> sys.stderr, 'symptom script %s did not determine the affected package' % symptom_script
                return
            report['Symptom'] = os.path.splitext(os.path.basename(symptom_script))[0]
        except StopIteration:
            sys.exit(0)
        except:
            print >> sys.stderr, 'symptom script %s crashed:' % symptom_script
            traceback.print_exc()
            sys.exit(0)

    if not package:
        if report.has_key('ExecutablePath'):
            package = apport.fileutils.find_file_package(report['ExecutablePath'])
        else:
            raise KeyError, 'called without a package, and report does not have ExecutablePath'
    report.add_package_info(package)
    if report.add_hooks_info(ui):
        sys.exit(0)

    # add title
    if 'Title' not in report:
        title = report.standard_title()
        if title:
            report['Title'] = title

    # check package origin
    if ('Package' not in report or \
          not apport.packaging.is_distro_package(report['Package'].split()[0])) \
          and 'CrashDB' not in report:
        if 'APPORT_REPORT_THIRDPARTY' in os.environ or \
            apport.fileutils.get_config('main', 'thirdparty', False, bool=True):
            report['ThirdParty'] = 'True'
        else:
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
    '''Apport user interface API.

    This provides an abstract base class for encapsulating the workflow and
    common code for any user interface implementation (like GTK, Qt, or CLI).

    A concrete subclass must implement all the abstract ui_* methods.
    '''
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
        '''Present all currently pending crash reports.
        
        Ask the user what to do about them, and offer to file bugs for them.
        
        Return True if at least one crash report was processed, False
        otherwise.
        '''
        result = False

        for f in apport.fileutils.get_new_reports():
            self.run_crash(f)
            result = True

        return result

    def run_crash(self, report_file, confirm=True):
        '''Present and report a particular crash.

        If confirm is True, ask the user what to do about it, and offer to file
        a bug for it.
        
        If confirm is False, the user will not be asked, and the crash is
        reported right away.
        '''
        self.report_file = report_file

        try:
            try:
                apport.fileutils.mark_report_seen(report_file)
            except OSError:
                # not there any more? no problem, then it won't be regarded as
                # "seen" any more anyway
                pass
            if not self.load_report(report_file):
                return

            if 'Ignore' in self.report:
                return

            # check for absent CoreDumps (removed if they exceed size limit)
            if self.report.get('ProblemType') == 'Crash' and \
                'Signal' in self.report and 'CoreDump' not in self.report and \
                'Stacktrace' not in self.report:
                subject = os.path.basename(self.report.get('ExecutablePath',
                    _('unknown program')))
                heading = _('Sorry, the program "%s" closed unexpectedly') % subject
                self.ui_error_message(_('Problem in %s') % subject,
                    '%s\n\n%s' % (heading, _('Your computer does not have enough \
free memory to automatically analyze the problem and send a report to the developers.')))
                return

            # ask the user about what to do with the current crash
            if not confirm:
                pass
            elif self.report.get('ProblemType') == 'Package':
                response = self.ui_present_package_error()
                if response == 'cancel':
                    return
                assert response == 'report'
            elif self.report.get('ProblemType') == 'KernelCrash':
                response = self.ui_present_kernel_error()
                if response == 'cancel':
                    return
                assert response == 'report'
            elif self.report.get('ProblemType') == 'KernelOops':
                # XXX the string doesn't quite match this case
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
                if 'Dependencies' not in self.report:
                    self.collect_info()
            except (IOError, zlib.error), e:
                # can happen with broken core dumps
                self.report = None
                self.ui_error_message(_('Invalid problem report'),
                    '%s\n\n%s' % (
                        _('This problem report is damaged and cannot be processed.'),
                        repr(e)))
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

            if self.report.get('ProblemType') in ['Crash', 'KernelCrash',
                                                  'KernelOops']:
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
                self.ui_error_message(_('Invalid problem report'), e.strerror)
                sys.exit(1)
        except OSError, e:
            # fail gracefully on ENOMEM
            if e.errno == errno.ENOMEM:
                print >> sys.stderr, 'Out of memory, aborting'
                sys.exit(1)
            else:
                raise

    def run_report_bug(self, symptom_script=None):
        '''Report a bug.

        If a pid is given on the command line, the report will contain runtime
        debug information. Either a package or a pid must be specified.

        If a symptom script is given, this will be run first (used by
        run_symptom()).
        '''
        if not self.options.package and not self.options.pid and not symptom_script:
            self.ui_error_message(_('No package specified'), 
                _('You need to specify a package or a PID. See --help for more information.'))
            return False
        self.report = apport.Report('Bug')

        # if PID is given, add info
        if self.options.pid:
            try:
                self.report.add_proc_info(self.options.pid)
            except ValueError:
                self.ui_error_message(_('Invalid PID'),
                        _('The specified process ID does not belong to a program.'))
                return False
            except OSError, e:
                # silently ignore nonexisting PIDs; the user must not close the
                # application prematurely
                if e.errno == errno.ENOENT:
                    return False
                elif e.errno == errno.EACCES:
                    self.ui_error_message(_('Permission denied'), 
                        _('The specified process does not belong to you. Please run this program as the process owner or as root.'))
                    return False
                else:
                    raise
        else:
            self.report.add_proc_environ()

        if self.options.package:
            self.options.package = self.options.package.strip()
        # "Do what I mean" for filing against "linux"
        if self.options.package == 'linux':
            self.cur_package = apport.packaging.get_kernel_package()
        else:
            self.cur_package = self.options.package

        try:
            self.collect_info(symptom_script)
        except ValueError, e:
            if str(e) == 'package does not exist':
                self.ui_error_message(_('Invalid problem report'), 
                    _('Package %s does not exist') % self.cur_package)
                return False
            else:
                raise

        # check unreportable flag
        if self.report.has_key('UnreportableReason'):
            self.ui_info_message(_('Problem in %s') % self.report['Package'].split()[0],
                _('The problem cannot be reported:\n\n%s') %
                self.report['UnreportableReason'])
            return

        if not self.handle_duplicate():
            # we do not confirm contents of bug reports, this might have
            # sensitive data
            try:
                del self.report['ProcCmdline']
            except KeyError:
                pass

            # show what's being sent
            response = self.ui_present_report_details()
            if response != 'cancel':
                self.file_report()

        return True

    def run_symptom(self):
        '''Report a bug with a symptom script.'''

        script = os.path.join(symptom_script_dir, self.options.symptom + '.py')
        if not os.path.exists(script):
            self.ui_error_message(_('Unknown symptom'),
                    _('The symptom "%s" is not known.') % self.options.symptom)
            return

        self.run_report_bug(script)

    def run_argv(self):
        '''Call appopriate run_* method according to command line arguments.
        
        Return True if at least one report has been processed, and False
        otherwise.
        '''
        if self.options.filebug:
            return self.run_report_bug()
        elif self.options.symptom:
            self.run_symptom()
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
    # methods that implement workflow bits
    #

    def parse_argv(self):
        '''Parse command line options.
        
        Return (options, args).
        '''
        optparser = optparse.OptionParser('%prog [options]')
        optparser.add_option('-f', '--file-bug',
            help='Start in bug filing mode. Requires --package and an optional --pid, or just a --pid',
            action='store_true', dest='filebug', default=False)
        optparser.add_option('-s', '--symptom', metavar='SYMPTOM',
            help='File a bug report about a symptom.', dest='symptom')
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

        try:
            return self.complete_size
        except AttributeError:
            # report wasn't loaded, so count manually
            size = 0
            for k in self.report:
                if self.report[k]:
                    size += len(self.report[k])
            return size

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

    def collect_info(self, symptom_script=None):
        '''Collect additional information.

        Call all the add_*_info() methods and display a progress dialog during
        this.

        In particular, this adds OS, package and gdb information and checks bug
        patterns.

        If a symptom script is given, this will be run first (used by
        run_symptom()).
        '''
        if not self.cur_package and not self.report.has_key('ExecutablePath') \
                and not symptom_script:
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

            hookui = HookUI(self)

            if not self.report.has_key('Stacktrace'):
                icthread = REThread.REThread(target=thread_collect_info,
                    name='thread_collect_info',
                    args=(self.report, self.report_file, self.cur_package,
                        hookui, symptom_script))
                icthread.start()
                while icthread.isAlive():
                    self.ui_pulse_info_collection_progress()
                    try:
                        hookui.process_event()
                    except KeyboardInterrupt:
                        sys.exit(1)

                icthread.join()
                icthread.exc_raise()

            if self.report.has_key('CrashDB'):
                self.crashdb = get_crashdb(None, self.report['CrashDB']) 

            if self.report['ProblemType'] == 'KernelCrash' or self.report['ProblemType'] == 'KernelOops' or self.report.has_key('Package'):
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
            if 'SourcePackage' not in self.report or \
                (not self.report['ProblemType'].startswith('Kernel') and 'Package' not in self.report):
                self.ui_error_message(_('Invalid problem report'),
                    _('Could not determine the package or source package name.'))
                # TODO This is not called consistently, is it really needed?
                self.ui_shutdown()
                sys.exit(1)

    def open_url(self, url):
        '''Open the given URL in a new browser window.

        Display an error dialog if everything fails.
        '''
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
            # (and more generally, mozilla browsers) and epiphany to open a new window
            # with respectively -new-window and --new-window
            try:
                if os.getenv('DISPLAY') and \
                        subprocess.call(['pgrep', '-x', '-u', str(uid), 'gnome-panel|gconfd-2'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
                    gct = subprocess.Popen(sudo_prefix + ['gconftool', '--get',
                        '/desktop/gnome/url-handlers/http/command'],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if gct.returncode == 0:
                        preferred_browser = gct.communicate()[0]
                        browser = re.match('((firefox|seamonkey|flock)[^\s]*)', preferred_browser)
                        if browser:
                            subprocess.call(sudo_prefix + [browser.group(0), '-new-window', url])
                            sys.exit(0)
                        browser = re.match('(epiphany[^\s]*)', preferred_browser)
                        if browser:
                            subprocess.call(sudo_prefix + [browser.group(0), '--new-window', url])
                            sys.exit(0)
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
        '''Upload the current report and guide the user to the reporting web page.'''

        # drop PackageArchitecture if equal to Architecture
        if self.report.get('PackageArchitecture') == self.report.get('Architecture'):
            try:
                del self.report['PackageArchitecture']
            except KeyError:
                pass

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
            except NeedsCredentials, e:
                message = _('Please enter your account information for the '
                            '%s bug tracking system')
                data = self.ui_question_userpass(message % e.message)
                if data is not None:
                    user, password = data
                    self.crashdb.set_credentials(user, password)
                    upthread = REThread.REThread(target=self.crashdb.upload,
                                                 args=(self.report,
                                                       progress_callback))
                    upthread.start()
        if upthread.exc_info():
            self.ui_error_message(_('Network problem'),
                '%s:\n\n%s' % (
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
        returned.
        '''
        try:
            self.report = apport.Report()
            self.report.load(open(path), binary='compressed')
        except MemoryError:
            self.report = None
            self.ui_error_message(_('Memory exhaustion'),
                _('Your system does not have enough memory to process this crash report.'))
            return False
        except IOError, e:
            self.report = None
            self.ui_error_message(_('Invalid problem report'), e.strerror)
            return False
        except (TypeError, ValueError, zlib.error), e:
            self.report = None
            self.ui_error_message(_('Invalid problem report'),
                '%s\n\n%s' % (
                    _('This problem report is damaged and cannot be processed.'),
                    repr(e)))
            return False

        if self.report.has_key('Package'):
            self.cur_package = self.report['Package'].split()[0]
        else:
            self.cur_package = apport.fileutils.find_file_package(self.report.get('ExecutablePath', ''))

        exe_path = self.report.get('InterpreterPath', self.report.get('ExecutablePath'))
        if not self.cur_package and self.report['ProblemType'] != 'KernelCrash' and self.report['ProblemType'] != 'KernelOops' or (
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
        '''Return a matching xdg.DesktopEntry for the current report.
        
        Return None if report cannot be associated to a .desktop file.
        '''
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
        '''Check if current report matches a bug pattern.

        If so, tell the user about it, open the existing bug in a browser, and
        return True.
        '''
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
        '''Ask what to do with a crash.

        Inform that a crash has happened for self.report and self.cur_package
        and ask about an action.

        If the package can be mapped to a desktop file, an xdg.DesktopEntry is
        passed as an argument; this can be used for enhancing strings, etc.

        Return the action and options as a dictionary:

        - Valid values for the 'action' key: ignore the crash ('cancel'), restart
          the crashed application ('restart'), or report a bug about the crash
          ('report').
        - Valid values for the 'blacklist' key: True or False (True will cause
          the invocation of report.mark_ignore()).
        '''
        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_present_package_error(self, desktopentry):
        '''Ask what to do with a package failure.

        Inform that a package installation/upgrade failure has happened for
        self.report and self.cur_package and ask about an action.

        Return the action: ignore ('cancel'), or report a bug about the problem
        ('report').
        '''
        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_present_kernel_error(self, desktopentry):
        '''Ask what to do with a kernel error.

        Inform that a kernel crash has happened for self.report and ask about
        an action.

        Return the action: ignore ('cancel'), or report a bug about the problem
        ('report').
        '''
        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_present_report_details(self):
        '''Show details of the bug report.
        
        This lets the user choose between sending a complete or reduced report.

        This method can use the get_complete_size() and get_reduced_size()
        methods to determine the respective size of the data to send, and
        format_filesize() to convert it to a humanly readable form.

        Return the action: send full report ('full'), send reduced report
        ('reduced'), or do not send anything ('cancel').
        '''
        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_info_message(self, title, text):
        '''Show an information message box with given title and text.'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_error_message(self, title, text):
        '''Show an error message box with given title and text.'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_start_info_collection_progress(self):
        '''Open a indefinite progress bar for data collection.
        
        This tells the user to wait while debug information is being
        collected.
        '''
        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_pulse_info_collection_progress(self):
        '''Advance the data collection progress bar.

        This function is called every 100 ms.
        '''
        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_stop_info_collection_progress(self):
        '''Close debug data collection progress window.'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_start_upload_progress(self):
        '''Open progress bar for data upload.

        This tells the user to wait while debug information is being uploaded.
        '''
        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_set_upload_progress(self, progress):
        '''Update data upload progress bar.

        Set the progress bar in the debug data upload progress window to the
        given ratio (between 0 and 1, or None for indefinite progress).

        This function is called every 100 ms.
        '''
        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_stop_upload_progress(self):
        '''Close debug data upload progress window.'''

        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_shutdown(self):
        '''Called right before terminating the program.
        
        This can be used for for cleaning up.
        '''
        pass

    #
    # Additional UI dialogs; these are not required by Apport itself, but can
    # be used by interactive package hooks
    #

    def ui_question_yesno(self, text):
        '''Show a yes/no question.

        Return True if the user selected "Yes", False if selected "No" or
        "None" on cancel/dialog closing.
        '''
        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_question_choice(self, text, options, multiple):
        '''Show an question with predefined choices.

        options is a list of strings to present. If multiple is True, they
        should be check boxes, if multiple is False they should be radio
        buttons.

        Return list of selected option indexes, or None if the user cancelled.
        If multiple == False, the list will always have one element.
        '''
        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_question_file(self, text):
        '''Show a file selector dialog.

        Return path if the user selected a file, or None if cancelled.
        '''
        raise NotImplementedError, 'this function must be overridden by subclasses'

    def ui_question_userpass(self, message):
        '''Request username and password from user.

        message is the text to be presented to the user when requesting for
        username and password information.

        Return a tuple (username, password), or None if cancelled.
        '''
        raise NotImplementedError, 'this function must be overridden by subclasses'

class HookUI:
    '''Interactive functions which can be used in package hooks.

    This provides an interface for package hooks which need to ask interactive
    questions. Directly passing the UserInterface instance to the hooks needs
    to be avoided, since we need to call the UI methods in a different thread,
    and also don't want hooks to be able to poke in the UI.
    '''
    def __init__(self, ui):
        '''Create a HookUI object.

        ui is the UserInterface instance to wrap.
        '''
        self.ui = ui

        # variables for communicating with the UI thread
        self._request_event = threading.Event()
        self._response_event = threading.Event()
        self._request_fn = None
        self._request_args = None
        self._response = None

    #
    # API for hooks
    #

    def information(self, text):
        '''Show an information with OK/Cancel buttons.

        This can be used for asking the user to perform a particular action,
        such as plugging in a device which does not work.
        '''
        return self._trigger_ui_request('ui_info_message', '', text)

    def yesno(self, text):
        '''Show a yes/no question.

        Return True if the user selected "Yes", False if selected "No" or
        "None" on cancel/dialog closing.
        '''
        return self._trigger_ui_request('ui_question_yesno', text)

    def choice(self, text, options, multiple=False):
        '''Show an question with predefined choices.

        options is a list of strings to present. If multiple is True, they
        should be check boxes, if multiple is False they should be radio
        buttons.

        Return list of selected option indexes, or None if the user cancelled.
        If multiple == False, the list will always have one element.
        '''
        return self._trigger_ui_request('ui_question_choice', text, options, multiple)

    def file(self, text):
        '''Show a file selector dialog.

        Return path if the user selected a file, or None if cancelled.
        '''
        return self._trigger_ui_request('ui_question_file', text)

    #
    # internal API for inter-thread communication
    #

    def _trigger_ui_request(self, fn, *args):
        '''Called by HookUi functions in info collection thread.'''

        # only one at a time
        assert not self._request_event.is_set()
        assert not self._response_event.is_set()
        assert self._request_fn == None

        self._response = None
        self._request_fn = fn
        self._request_args = args
        self._request_event.set()
        self._response_event.wait()

        self._request_fn = None
        self._response_event.clear()

        return self._response

    def process_event(self):
        '''Called by GUI thread to check and process hook UI requests.'''

        # sleep for 0.1 seconds to wait for events
        self._request_event.wait(0.1)
        if not self._request_event.is_set():
            return

        assert not self._response_event.is_set()
        self._request_event.clear()
        self._response = getattr(self.ui, self._request_fn)(*self._request_args)
        self._response_event.set()

#
# Test suite
#

if  __name__ == '__main__':
    import unittest, shutil, signal, tempfile
    from cStringIO import StringIO
    import apport.report
    import problem_report

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
            self.question_yesno_response = None
            self.question_choice_response = None
            self.question_file_response = None

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

        def ui_question_yesno(self, text):
            self.msg_text = text
            return self.question_yesno_response

        def ui_question_choice(self, text, options, multiple):
            self.msg_text = text
            return self.question_choice_response

        def ui_question_file(self, text):
            self.msg_text = text
            return self.question_file_response

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
            global symptom_script_dir
            self.orig_symptom_script_dir = symptom_script_dir
            symptom_script_dir = tempfile.mkdtemp()
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

            # set up our local hook directory
            self.hookdir = tempfile.mkdtemp()
            self.orig_hook_dir = apport.report._hook_dir
            apport.report._hook_dir = self.hookdir

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
            global symptom_script_dir
            shutil.rmtree(symptom_script_dir)
            symptom_script_dir = self.orig_symptom_script_dir
            self.orig_symptom_script_dir = None

            os.unlink(apport.report._ignore_file)
            apport.report._ignore_file = self.orig_ignore_file

            self.ui = None
            self.report_file.close()

            self.assertEqual(subprocess.call(['pidof', '/bin/cat']), 1, 'no stray cats')
            self.assertEqual(subprocess.call(['pidof', '/bin/sleep']), 1, 'no stray sleeps')

            shutil.rmtree(self.hookdir)
            apport.report._hook_dir = self.orig_hook_dir

        def test_format_filesize(self):
            '''format_filesize().'''

            self.assertEqual(self.ui.format_filesize(0), '0.0 KiB')
            self.assertEqual(self.ui.format_filesize(2048), '2.0 KiB')
            self.assertEqual(self.ui.format_filesize(2560), '2.5 KiB')
            self.assertEqual(self.ui.format_filesize(1000000), '976.6 KiB')
            self.assertEqual(self.ui.format_filesize(1048576), '1.0 MiB')
            self.assertEqual(self.ui.format_filesize(2.7*1048576), '2.7 MiB')
            self.assertEqual(self.ui.format_filesize(1024*1048576), '1.0 GiB')
            self.assertEqual(self.ui.format_filesize(2560*1048576), '2.5 GiB')

        def test_get_size_loaded(self):
            '''get_complete_size() and get_reduced_size() for loaded Reports.'''

            self.ui.load_report(self.report_file.name)

            self.assertEqual(self.ui.get_complete_size(),
                os.path.getsize(self.report_file.name))
            rs = self.ui.get_reduced_size()
            self.assert_(rs > 1000)
            self.assert_(rs < 10000)

        def test_get_size_constructed(self):
            '''get_complete_size() and get_reduced_size() for on-the-fly Reports.'''

            self.ui.report = apport.Report('Bug')
            self.ui.report['Hello'] = 'World'

            s = self.ui.get_complete_size()
            self.assert_(s > 5)
            self.assert_(s < 100)

            self.assertEqual(s, self.ui.get_reduced_size())

        def test_load_report(self):
            '''load_report().'''

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
            '''restart().'''

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
            '''collect_info() on report without information (distro bug).'''

            # report without any information (distro bug)
            self.ui.report = apport.Report()
            self.ui.collect_info()
            self.assert_(set(['Date', 'Uname', 'DistroRelease', 'ProblemType']).issubset(
                set(self.ui.report.keys())))
            self.assertEqual(self.ui.ic_progress_pulses, 0,
                'no progress dialog for distro bug info collection')

        def test_collect_info_exepath(self):
            '''collect_info() on report with only ExecutablePath.'''

            # report with only package information
            self.report = apport.Report()
            self.report['ExecutablePath'] = '/bin/bash'
            self.update_report_file()
            self.ui.load_report(self.report_file.name)
            # add some tuple values, for robustness testing (might be added by
            # apport hooks)
            self.ui.report['Fstab'] = ('/etc/fstab', True)
            self.ui.report['CompressedValue'] = problem_report.CompressedValue('Test')
            self.ui.collect_info()
            self.assert_(set(['SourcePackage', 'Package', 'ProblemType',
                'Uname', 'Dependencies', 'DistroRelease', 'Date',
                'ExecutablePath']).issubset(set(self.ui.report.keys())))
            self.assert_(self.ui.ic_progress_pulses > 0,
                'progress dialog for package bug info collection')
            self.assertEqual(self.ui.ic_progress_active, False,
                'progress dialog for package bug info collection finished')

        def test_collect_info_package(self):
            '''collect_info() on report with a package.'''

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
            '''handle_duplicate().'''

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
            '''running the frontend without any pending reports.'''

            sys.argv = []
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), False)

        def test_run_report_bug_noargs(self):
            '''run_report_bug() without specifying arguments.'''

            sys.argv = ['ui-test', '-f']
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), False)
            self.assertEqual(self.ui.msg_severity, 'error')

        def test_run_report_bug_package(self):
            '''run_report_bug() for a package.'''

            sys.argv = ['ui-test', '-f', '-p', 'bash']
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), True)

            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, 'http://bash.bugs.example.com/%i' % self.ui.crashdb.latest_id())

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
            '''run_report_bug() for a pid.'''

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
            self.assertEqual(self.ui.opened_url, 'http://coreutils.bugs.example.com/%i' % self.ui.crashdb.latest_id())
            self.assert_(self.ui.ic_progress_pulses > 0)

        def test_run_report_bug_wrong_pid(self):
            '''run_report_bug() for a nonexisting pid.'''

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
            '''run_report_bug() for a pid which runs as a different user.'''

            assert os.getuid() > 0, 'this test must not be run as root'

            sys.argv = ['ui-test', '-f', '-P', '1']
            self.ui = _TestSuiteUserInterface()
            self.ui.run_argv()

            self.assertEqual(self.ui.msg_severity, 'error')

        def test_run_report_bug_unpackaged_pid(self):
            '''run_report_bug() for a pid of an unpackaged program.'''

            # create unpackaged test program
            (fd, exename) = tempfile.mkstemp()
            os.write(fd, open('/bin/cat').read())
            os.close(fd)
            os.chmod(exename, 0755)

            # unpackaged test process
            pid = os.fork()
            if pid == 0:
                os.execv(exename, [exename])

            try:
                sys.argv = ['ui-test', '-f', '-P', str(pid)]
                self.ui = _TestSuiteUserInterface()
                self.assertRaises(SystemExit, self.ui.run_argv)
            finally:
                os.kill(pid, signal.SIGKILL)
                os.wait()
                os.unlink(exename)

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
            '''run_crash().'''

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
            self.assertEqual(self.ui.opened_url, 'http://coreutils.bugs.example.com/%i' % self.ui.crashdb.latest_id())
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
            self.assertEqual(self.ui.opened_url, 'http://coreutils.bugs.example.com/%i' % self.ui.crashdb.latest_id())
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
            '''run_crash() through a file specified on the command line.'''

            self.report['Package'] = 'bash'
            self.report['UnreportableReason'] = 'It stinks.'
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

        def test_run_crash_unreportable(self):
            '''run_crash() on a crash with the UnreportableReason
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

        def test_run_crash_ignore(self):
            '''run_crash() on a crash with the Ignore field.'''

            self.report['Ignore'] = 'True'
            self.report['ExecutablePath'] = '/bin/bash'
            self.report['Package'] = 'bash 1'
            self.update_report_file()

            self.ui.run_crash(self.report_file.name)
            self.assertEqual(self.ui.msg_severity, None)

        def test_run_crash_nocore(self):
            '''run_crash() for a crash dump without CoreDump.'''

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
            '''run_crash() pre-retraced reports.
            
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
            '''run_crash() on various error conditions.'''

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
            '''run_crash() on reports with subsequently uninstalled packages'''

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
            '''run_crash() for a package error.'''

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
            self.assertEqual(self.ui.opened_url, 'http://bash.bugs.example.com/%i' % self.ui.crashdb.latest_id())

            self.assert_('SourcePackage' in self.ui.report.keys())
            self.assert_('Package' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Package')

            # verify that additional information has been collected
            self.assert_('Architecture' in self.ui.report.keys())
            self.assert_('DistroRelease' in self.ui.report.keys())
            self.assert_('Uname' in self.ui.report.keys())

        def test_run_crash_kernel(self):
            '''run_crash() for a kernel error.'''

            # set up hook
            f = open(os.path.join(self.hookdir, 'source_linux.py'), 'w')
            f.write('''def add_info(report, ui): 
    report['KernelDebug'] = 'LotsMoreInfo'
''')
            f.close()

            # generate crash report
            r = apport.Report('KernelCrash')
            r['Package'] = apport.packaging.get_kernel_package()
            r['SourcePackage'] = 'linux'

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
            self.assertEqual(self.ui.msg_severity, None, str(self.ui.msg_title) + 
                ' ' + str(self.ui.msg_text))
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, 'http://linux.bugs.example.com/%i' % self.ui.crashdb.latest_id())

            self.assert_('SourcePackage' in self.ui.report.keys())
            # did we run the hooks properly?
            self.assert_('KernelDebug' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'KernelCrash')

        def test_run_crash_anonymity(self):
            '''run_crash() anonymization.'''

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

        def _run_hook(self, code):
            f = open(os.path.join(self.hookdir, 'coreutils.py'), 'w')
            f.write('def add_info(report, ui):\n%s\n' % 
                    '\n'.join(['    ' + l for l in code.splitlines()]))
            f.close()
            self.ui.options.package = 'coreutils'
            self.ui.run_report_bug()

        def test_interactive_hooks_information(self):
            '''interactive hooks: HookUI.information()'''

            self._run_hook('''report['begin'] = '1'
ui.information('InfoText')
report['end'] = '1'
''')
            self.assertEqual(self.ui.report['begin'], '1')
            self.assertEqual(self.ui.report['end'], '1')
            self.assertEqual(self.ui.msg_text, 'InfoText')

        def test_interactive_hooks_yesno(self):
            '''interactive hooks: HookUI.yesno()'''

            self.ui.question_yesno_response = True
            self._run_hook('''report['begin'] = '1'
report['answer'] = str(ui.yesno('YesNo?'))
report['end'] = '1'
''')
            self.assertEqual(self.ui.report['begin'], '1')
            self.assertEqual(self.ui.report['end'], '1')
            self.assertEqual(self.ui.msg_text, 'YesNo?')
            self.assertEqual(self.ui.report['answer'], 'True')

            self.ui.question_yesno_response = False
            self.ui.run_report_bug()
            self.assertEqual(self.ui.report['answer'], 'False')
            self.assertEqual(self.ui.report['end'], '1')

            self.ui.question_yesno_response = None
            self.ui.run_report_bug()
            self.assertEqual(self.ui.report['answer'], 'None')
            self.assertEqual(self.ui.report['end'], '1')

        def test_interactive_hooks_file(self):
            '''interactive hooks: HookUI.file()'''

            self.ui.question_file_response = '/etc/fstab'
            self._run_hook('''report['begin'] = '1'
report['answer'] = str(ui.file('YourFile?'))
report['end'] = '1'
''')
            self.assertEqual(self.ui.report['begin'], '1')
            self.assertEqual(self.ui.report['end'], '1')
            self.assertEqual(self.ui.msg_text, 'YourFile?')
            self.assertEqual(self.ui.report['answer'], '/etc/fstab')

            self.ui.question_file_response = None
            self.ui.run_report_bug()
            self.assertEqual(self.ui.report['answer'], 'None')
            self.assertEqual(self.ui.report['end'], '1')

        def test_interactive_hooks_choices(self):
            '''interactive hooks: HookUI.choice()'''

            self.ui.question_choice_response = [1]
            self._run_hook('''report['begin'] = '1'
report['answer'] = str(ui.choice('YourChoice?', ['foo', 'bar']))
report['end'] = '1'
''')
            self.assertEqual(self.ui.report['begin'], '1')
            self.assertEqual(self.ui.report['end'], '1')
            self.assertEqual(self.ui.msg_text, 'YourChoice?')
            self.assertEqual(self.ui.report['answer'], '[1]')

            self.ui.question_choice_response = None
            self.ui.run_report_bug()
            self.assertEqual(self.ui.report['answer'], 'None')
            self.assertEqual(self.ui.report['end'], '1')

        def test_interactive_hooks_cancel(self):
            '''interactive hooks: user cancels'''

            self.assertRaises(SystemExit, self._run_hook, 
                '''report['begin'] = '1'
raise StopIteration
report['end'] = '1'
''')

        def test_run_symptom(self):
            '''run_symptom()'''

            # unknown symptom
            sys.argv = ['ui-test', '-s', 'foobar' ]
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), True)
            self.assert_('foobar" is not known' in self.ui.msg_text)
            self.assertEqual(self.ui.msg_severity, 'error')

            # does not determine package
            f = open(os.path.join(symptom_script_dir, 'nopkg.py'), 'w')
            print >> f, 'def run(report, ui):\n    pass'
            f.close()
            orig_stderr = sys.stderr
            sys.argv = ['ui-test', '-s', 'nopkg' ]
            self.ui = _TestSuiteUserInterface()
            sys.stderr = StringIO()
            self.assertRaises(SystemExit, self.ui.run_argv)
            err = sys.stderr.getvalue()
            sys.stderr = orig_stderr
            self.assert_('did not determine the affected package' in err)

            # does not define run()
            f = open(os.path.join(symptom_script_dir, 'norun.py'), 'w')
            print >> f, 'def something(x, y):\n    return 1'
            f.close()
            sys.argv = ['ui-test', '-s', 'norun' ]
            self.ui = _TestSuiteUserInterface()
            sys.stderr = StringIO()
            self.assertRaises(SystemExit, self.ui.run_argv)
            err = sys.stderr.getvalue()
            sys.stderr = orig_stderr
            self.assert_('norun.py crashed:' in err)

            # crashing script
            f = open(os.path.join(symptom_script_dir, 'crash.py'), 'w')
            print >> f, 'def run(report, ui):\n    return 1/0'
            f.close()
            sys.argv = ['ui-test', '-s', 'crash' ]
            self.ui = _TestSuiteUserInterface()
            sys.stderr = StringIO()
            self.assertRaises(SystemExit, self.ui.run_argv)
            err = sys.stderr.getvalue()
            sys.stderr = orig_stderr
            self.assert_('crash.py crashed:' in err)
            self.assert_('ZeroDivisionError:' in err)

            # working noninteractive script
            f = open(os.path.join(symptom_script_dir, 'itching.py'), 'w')
            print >> f, 'def run(report, ui):\n  report["itch"] = "scratch"\n  return "bash"'
            f.close()
            sys.argv = ['ui-test', '-s', 'itching' ]
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), True)
            self.assertEqual(self.ui.msg_text, None)
            self.assertEqual(self.ui.msg_severity, None)

            self.assertEqual(self.ui.report['itch'], 'scratch')
            self.assert_('DistroRelease' in self.ui.report)
            self.assertEqual(self.ui.report['SourcePackage'], 'bash')
            self.assert_(self.ui.report['Package'].startswith('bash '))
            self.assertEqual(self.ui.report['ProblemType'], 'Bug')

            # working interactive script
            f = open(os.path.join(symptom_script_dir, 'itching.py'), 'w')
            print >> f, '''def run(report, ui):
    report['itch'] = 'slap'
    report['q'] = str(ui.yesno('do you?'))
    return 'bash'
'''
            f.close()
            sys.argv = ['ui-test', '-s', 'itching' ]
            self.ui = _TestSuiteUserInterface()
            self.ui.question_yesno_response = True
            self.assertEqual(self.ui.run_argv(), True)
            self.assertEqual(self.ui.msg_text, 'do you?')

            self.assertEqual(self.ui.report['itch'], 'slap')
            self.assert_('DistroRelease' in self.ui.report)
            self.assertEqual(self.ui.report['SourcePackage'], 'bash')
            self.assert_(self.ui.report['Package'].startswith('bash '))
            self.assertEqual(self.ui.report['ProblemType'], 'Bug')
            self.assertEqual(self.ui.report['q'], 'True')

    unittest.main()
