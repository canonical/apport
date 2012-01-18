'''Abstract Apport user interface.

This encapsulates the workflow and common code for any user interface
implementation (like GTK, Qt, or CLI).
'''

# Copyright (C) 2007 - 2011 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

__version__ = '1.91'

import glob, sys, os.path, optparse, time, traceback, locale, gettext, re
import pwd, errno, urllib, zlib
import subprocess, threading, webbrowser

import apport, apport.fileutils, apport.REThread

from apport.crashdb import get_crashdb, NeedsCredentials
from apport import unicode_gettext as _

symptom_script_dir = os.environ.get('APPORT_SYMPTOMS_DIR',
                                    '/usr/share/apport/symptoms')
PF_KTHREAD = 0x200000

def excstr(exception):
    '''Return exception message as unicode.'''
    
    return str(exception).decode(locale.getpreferredencoding(), 'replace')

def thread_collect_info(report, reportfile, package, ui, symptom_script=None,
        ignore_uninstalled=False):
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
            exec(compile(open(symptom_script).read(), symptom_script, 'exec'), symb)
            package = symb['run'](report, ui)
            if not package:
                apport.error('symptom script %s did not determine the affected package', symptom_script)
                return
            report['Symptom'] = os.path.splitext(os.path.basename(symptom_script))[0]
        except StopIteration:
            sys.exit(0)
        except:
            apport.error('symptom script %s crashed:', symptom_script)
            traceback.print_exc()
            sys.exit(0)

    if not package:
        if 'ExecutablePath' in report:
            package = apport.fileutils.find_file_package(report['ExecutablePath'])
        else:
            raise KeyError('called without a package, and report does not have ExecutablePath')
    try:
        report.add_package_info(package)
    except ValueError:
        # this happens if we are collecting information on an uninstalled
        # package
        if not ignore_uninstalled:
            raise
    except SystemError as e:
        report['UnreportableReason'] = excstr(e)
        return

    if report.add_hooks_info(ui):
        sys.exit(0)

    # check package origin; we do that after adding hooks, so that hooks have
    # the chance to set a third-party CrashDB.
    try:
        if 'CrashDB' not in report and 'APPORT_DISABLE_DISTRO_CHECK' not in os.environ:
            if 'Package' not in report:
                report['UnreportableReason'] = _('This package does not seem to be installed correctly')
            elif not apport.packaging.is_distro_package(report['Package'].split()[0]):
                #TRANS: %s is the name of the operating system
                report['UnreportableReason'] = _('This is not an official %s \
package. Please remove any third party package and try again.') % \
                    report['DistroRelease'].split()[0]
    except ValueError:
        # this happens if we are collecting information on an uninstalled
        # package
        if not ignore_uninstalled:
            raise

    report.anonymize()

    # add title
    if 'Title' not in report:
        title = report.standard_title()
        if title:
            report['Title'] = title

    # check obsolete packages
    if report['ProblemType'] == 'Crash' and \
        'APPORT_IGNORE_OBSOLETE_PACKAGES' not in os.environ:
        old_pkgs = report.obsolete_packages()
        if old_pkgs:
            report['UnreportableReason'] = _('You have some obsolete package \
versions installed. Please upgrade the following packages and check if the \
problem still occurs:\n\n%s') % ', '.join(old_pkgs)

    # disabled: if we have a SIGABRT without an assertion message, declare as unreportable
    #if report.get('Signal') == '6' and 'AssertionMessage' not in report:
    #    report['UnreportableReason'] = _('The program crashed on an assertion failure, but the message could not be retrieved. Apport does not support reporting these crashes.')

    if reportfile:
        f = open(reportfile, 'a')
        os.chmod (reportfile, 0)
        report.write(f, only_new=True)
        f.close()
        apport.fileutils.mark_report_seen(reportfile)
        os.chmod (reportfile, 0o600)

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
        except ImportError as e:
            # this can happen while upgrading python packages
            apport.fatal('Could not import module, is a package upgrade in progress? Error: %s', str(e))
        except KeyError:
            apport.fatal('/etc/apport/crashdb.conf is damaged: No default database')

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

        if os.geteuid() == 0:
            reports = apport.fileutils.get_new_system_reports()
        else:
            reports = apport.fileutils.get_new_reports()
        for f in reports:
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
                assert 'action' in response
                assert 'blacklist' in response

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
            except (IOError, zlib.error) as e:
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

            if self.check_unreportable():
                return

            if self.handle_duplicate():
                return

            # confirm what will be sent
            response = self.ui_present_report_details(False)
            if response == 'cancel':
                return
            if response == 'examine':
                self.examine()
                return
            if response == 'reduced':
                try:
                    del self.report['CoreDump']
                except KeyError:
                    pass # Huh? Should not happen, but did in https://launchpad.net/bugs/86007
            else:
                assert response == 'full'

            self.file_report()
        except IOError as e:
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
        except OSError as e:
            # fail gracefully on ENOMEM
            if e.errno == errno.ENOMEM:
                apport.fatal('Out of memory, aborting')
            else:
                raise

    def run_report_bug(self, symptom_script=None):
        '''Report a bug.

        If a pid is given on the command line, the report will contain runtime
        debug information. Either a package or a pid must be specified; if none
        is given, show a list of symptoms.

        If a symptom script is given, this will be run first (used by
        run_symptom()).
        '''
        if not self.options.package and not self.options.pid and \
                not symptom_script:
            if self.run_symptoms():
                return True
            else:
                self.ui_error_message(_('No package specified'), 
                    _('You need to specify a package or a PID. See --help for more information.'))
            return False

        self.report = apport.Report('Bug')

        # if PID is given, add info
        if self.options.pid:
            try:
                stat = open('/proc/%s/stat' % self.options.pid).read().split()
                flags = int(stat[8])
                if flags & PF_KTHREAD:
                    # this PID is a kernel thread
                    self.options.package = 'linux'
                else:
                    self.report.add_proc_info(self.options.pid)
            except (ValueError, IOError):
                self.ui_error_message(_('Invalid PID'),
                        _('The specified process ID does not belong to a program.'))
                return False
            except OSError as e:
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
        except ValueError as e:
            if str(e) == 'package does not exist':
                if not self.cur_package:
                    self.ui_error_message(_('Invalid problem report'), 
                        _('Symptom script %s did not determine an affected package') % symptom_script)
                else:
                    self.ui_error_message(_('Invalid problem report'), 
                        _('Package %s does not exist') % self.cur_package)
                return False
            else:
                raise

        if self.check_unreportable():
            return

        self.add_extra_tags()

        if self.handle_duplicate():
            return True

        # not useful for bug reports, and has potentially sensitive information
        try:
            del self.report['ProcCmdline']
        except KeyError:
            pass

        if self.options.save:
            try:
                f = open(os.path.expanduser(self.options.save), 'w')
                self.report.write(f)
                f.close()
            except (IOError, OSError) as e:
                self.ui_error_message(_('Cannot create report'), excstr(e))
        else:
            # show what's being sent
            response = self.ui_present_report_details(False)
            if response != 'cancel':
                self.file_report()

        return True

    def run_update_report(self):
        '''Update an existing bug with locally collected information.'''

        # avoid irrelevant noise
        if not self.crashdb.can_update(self.options.update_report):
            self.ui_error_message(_('Updating problem report'),
                _('You are not the reporter or subscriber of this '
                  'problem report, or the report is a duplicate or already '
                  'closed.\n\nPlease create a new report using "apport-bug".'))
            return False

        is_reporter = self.crashdb.is_reporter(self.options.update_report)

        if not is_reporter:
            r = self.ui_question_yesno(
                _('You are not the reporter of this problem report. It '
                  'is much easier to mark a bug as a duplicate of another '
                  'than to move your comments and attachments to a new bug.\n\n'
                  'Subsequently, we recommend that you file a new bug report '
                  'using "apport-bug" and make a comment in this bug about '
                  'the one you file.\n\n'
                  'Do you really want to proceed?'))
            if not r:
                return False

        # list of affected source packages
        self.report = apport.Report('Bug')
        if self.options.package:
            pkgs = [self.options.package.strip()]
        else:
            pkgs = self.crashdb.get_affected_packages(self.options.update_report)

        info_collected = False
        for p in pkgs:
            #print('Collecting apport information for source package %s...' % p)
            self.cur_package = p
            self.report['SourcePackage'] = p
            self.report['Package'] = p # no way to find this out

            # we either must have the package installed or a source package hook
            # available to collect sensible information
            try:
                apport.packaging.get_version(p)
            except ValueError:
                if not os.path.exists(os.path.join(apport.report._hook_dir, 'source_%s.py' % p)):
                    print('Package %s not installed and no hook available, ignoring' % p)
                    continue
            self.collect_info(ignore_uninstalled=True)
            info_collected = True

        if not info_collected:
            self.ui_info_message(_('Updating problem report'), 
                    _('No additional information collected.'))
            return False

        self.report.add_user_info()
        self.report.add_proc_environ()
        self.add_extra_tags()

        # delete the uninteresting keys
        del self.report['ProblemType']
        del self.report['Date']
        try:
            del self.report['SourcePackage']
        except KeyError:
            pass

        if len(self.report) == 0:
            self.ui_info_message(_('Updating problem report'), 
                    _('No additional information collected.'))
            return False

        # show what's being sent
        response = self.ui_present_report_details(True)
        if response != 'cancel':
            self.crashdb.update(self.options.update_report, self.report,
                    'apport information', change_description=is_reporter,
                    attachment_comment='apport information')
            return True

        return False

    def run_symptoms(self):
        '''Report a bug from a list of available symptoms.
        
        Return False if no symptoms are available.
        '''
        scripts = glob.glob(os.path.join(symptom_script_dir, '*.py'))

        symptom_names = []
        symptom_descriptions = []
        for script in scripts:
            # scripts with an underscore can be used for private libraries
            if os.path.basename(script).startswith('_'):
                continue
            symb = {}
            try:
                exec(compile(open(script).read(), script, 'exec'), symb)
            except:
                apport.error('symptom script %s is invalid', script)
                traceback.print_exc()
                continue
            if 'run' not in symb:
                apport.error('symptom script %s does not define run() function', script)
                continue
            symptom_names.append(os.path.splitext(os.path.basename(script))[0])
            symptom_descriptions.append(symb.get('description', symptom_names[-1]))

        if not symptom_names:
            return False

        symptom_descriptions, symptom_names = \
            zip(*sorted(zip(symptom_descriptions, symptom_names)))
        symptom_descriptions = list(symptom_descriptions)
        symptom_names = list(symptom_names)
        symptom_names.append(None)
        symptom_descriptions.append('Other problem')

        ch = self.ui_question_choice(_('What kind of problem do you want to report?'), 
                symptom_descriptions, False)

        if ch != None:
            symptom = symptom_names[ch[0]]
            if symptom:
                self.run_report_bug(os.path.join(symptom_script_dir, symptom + '.py'))
            else:
                return False

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
        if self.options.symptom:
            self.run_symptom()
            return True
        elif self.options.filebug:
            return self.run_report_bug()
        elif self.options.update_report:
            return self.run_update_report()
        elif self.options.version:
            print(__version__)
            return True
        elif self.options.crash_file:
            try:
                self.run_crash(self.options.crash_file, False)
            except OSError as e:
                self.ui_error_message(_('Invalid problem report'), excstr(e))
            return True
        elif self.options.window:
                self.ui_info_message('', _('After closing this message '
                    'please click on an application window to report a problem about it.'))
                xprop = subprocess.Popen(['xprop', '_NET_WM_PID'],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                (out, err) = xprop.communicate()
                if xprop.returncode == 0:
                    try:
                        self.options.pid = int(out.split()[-1])
                    except ValueError:
                        self.ui_error_message(_('Cannot create report'), 
                                _('xprop failed to determine process ID of the window'))
                        return True
                    return self.run_report_bug()
                else:
                    self.ui_error_message(_('Cannot create report'), 
                            _('xprop failed to determine process ID of the window') + '\n\n' + err)
                    return True
        else:
            return self.run_crashes()

    #
    # methods that implement workflow bits
    #

    def parse_argv_update(self):
        '''Parse command line options when being invoked in update mode.

        Return (options, args).
        '''
        optparser = optparse.OptionParser(_('%prog <report number>'))
        optparser.add_option('-p', '--package',
            help=_('Specify package name.'))
        optparser.add_option('--tag', action='append', default=[],
            help=_('Add an extra tag to the report. Can be specified multiple times.'))
        (self.options, self.args) = optparser.parse_args()

        if len(self.args) != 1 or not self.args[0].isdigit():
            optparser.error('You need to specify a report number to update')
            sys.exit(1)

        self.options.update_report = int(self.args[0])
        self.options.symptom = None
        self.options.filebug = False
        self.options.crash_file = None
        self.options.version = None
        self.args = []

    def parse_argv(self):
        '''Parse command line options.

        If a single argument is given without any options, this tries to "do
        what I mean".
        '''
        # invoked in update mode?
        if len(sys.argv) > 0:
            if 'APPORT_INVOKED_AS' in os.environ:
                sys.argv[0] = os.path.join(os.path.dirname(sys.argv[0]),
                    os.path.basename(os.environ['APPORT_INVOKED_AS']))
            cmd = sys.argv[0]
            if cmd.endswith('-update-bug') or cmd.endswith('-collect'):
                self.parse_argv_update()
                return

        optparser = optparse.OptionParser(_('%prog [options] [symptom|pid|package|program path|.apport/.crash file]'))
        optparser.add_option('-f', '--file-bug', action='store_true',
            dest='filebug', default=False,
            help=_('Start in bug filing mode. Requires --package and an optional --pid, or just a --pid. If neither is given, display a list of known symptoms. (Implied if a single argument is given.)'))
        optparser.add_option('-w', '--window', action='store_true', default=False,
            help=_('Click a window as a target for filing a problem report.'))
        optparser.add_option('-u', '--update-bug', type='int', dest='update_report',
            help=_('Start in bug updating mode. Can take an optional --package.'))
        optparser.add_option('-s', '--symptom', metavar='SYMPTOM',
            help=_('File a bug report about a symptom. (Implied if symptom name is given as only argument.)'))
        optparser.add_option('-p', '--package',
            help=_('Specify package name in --file-bug mode. This is optional if a --pid is specified. (Implied if package name is given as only argument.)'))
        optparser.add_option('-P', '--pid', type='int',
            help=_('Specify a running program in --file-bug mode. If this is specified, the bug report will contain more information.  (Implied if pid is given as only argument.)'))
        optparser.add_option('-c', '--crash-file', metavar='PATH',
            help=_('Report the crash from given .apport or .crash file instead of the pending ones in %s. (Implied if file is given as only argument.)') % apport.fileutils.report_dir)
        optparser.add_option('--save', metavar='PATH',
            help=_('In bug filing mode, save the collected information into a file instead of reporting it. This file can then be reported later on from a different machine.'))
        optparser.add_option('--tag', action='append', default=[],
            help=_('Add an extra tag to the report. Can be specified multiple times.'))
        optparser.add_option('-v', '--version', action='store_true',
            help=_('Print the Apport version number.'))

        if len(sys.argv) > 0 and cmd.endswith('-bug'):
            for o in ('-f', '-u', '-s', '-p', '-P', '-c'):
                optparser.get_option(o).help = optparse.SUPPRESS_HELP

        (self.options, self.args) = optparser.parse_args()

        # "do what I mean" for zero or one arguments
        if len(sys.argv) == 0:
            return

        # no argument: default to "show pending crashes" except when called in
        # bug mode
        # NOTE: uses sys.argv, since self.args if empty for all the options,
        # e.g. "-v" or "-u $BUG"
        if len(sys.argv) == 1 and cmd.endswith('-bug'):
            self.options.filebug = True
            return

        # one argument: guess "file bug" mode by argument type
        if len(self.args) != 1:
            return

        # symptom?
        if os.path.exists(os.path.join(symptom_script_dir, self.args[0] + '.py')):
            self.options.filebug = True
            self.options.symptom = self.args[0]
            self.args = []

        # .crash/.apport file?
        elif self.args[0].endswith('.crash') or self.args[0].endswith('.apport'):
            self.options.crash_file = self.args[0]
            self.args = []

        # PID?
        elif self.args[0].isdigit():
            self.options.filebug = True
            self.options.pid = self.args[0]
            self.args = []

        # executable?
        elif '/' in self.args[0]:
            pkg = apport.packaging.get_file_package(self.args[0])
            if not pkg:
                optparser.error('%s does not belong to a package.' % self.args[0])
                sys.exit(1)
            self.args = []
            self.options.filebug = True
            self.options.package = pkg

        # otherwise: package name
        else:
            self.options.filebug = True
            self.options.package = self.args[0]
            self.args = []

    def format_filesize(self, size):
        '''Format the given integer as humanly readable and i18n'ed file size.'''

        if size < 1000000:
            return locale.format('%.1f', size/1000.) + ' KB'
        if size < 1000000000:
            return locale.format('%.1f', size / 1000000.) + ' MB'
        return locale.format('%.1f', size / float(1000000000)) + ' GB'

    def get_complete_size(self):
        '''Return the size of the complete report.'''

        # report wasn't loaded, so count manually
        size = 0
        for k in self.report:
            if self.report[k]:
                try:
                    # if we have a compressed value, take its size, but take
                    # base64 overhead into account
                    size += len(self.report[k].gzipvalue) * 8 / 6
                except AttributeError:
                    size += len(self.report[k])
        return size

    def get_reduced_size(self):
        '''Return the size of the reduced report.'''

        size = 0
        for k in self.report:
            if k != 'CoreDump':
                if self.report[k]:
                    try:
                        # if we have a compressed value, take its size, but take
                        # base64 overhead into account
                        size += len(self.report[k].gzipvalue) * 8 / 6
                    except AttributeError:
                        size += len(self.report[k])

        return size

    def can_examine_locally(self):
        '''Check whether to offer the "Examine locally" button.

        This will be true if the report has a core dump, apport-retrace is
        installed and a terminal is available (see ui_run_terminal()).
        '''
        if not self.report or 'CoreDump' not in self.report:
            return False

        try:
            if subprocess.call(['apport-retrace', '--help'],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT) != 0:
                return False
        except OSError:
            return False

        try:
            return self.ui_run_terminal(None)
        except NotImplementedError:
            return False

    def restart(self):
        '''Reopen the crashed application.'''

        assert 'ProcCmdline' in self.report

        if os.fork() == 0:
            os.setsid()
            os.execlp('sh', 'sh', '-c', self.report.get('RespawnCommand', self.report['ProcCmdline']))
            sys.exit(1)

    def examine(self):
        '''Locally examine crash report.'''

        response = self.ui_question_choice(
            _('This will launch apport-retrace in a terminal window to examine the crash.'),
            [_('Run gdb session'),
             _('Run gdb session without downloading debug symbols'),
            #TRANSLATORS: %s contains the crash report file name
             _('Update %s with fully symbolic stack trace') % self.report_file,
            ],
            False)

        if response is None:
            return

        retrace_with_download = 'apport-retrace -S system -C ~/.cache/apport/retrace -v '
        retrace_no_download = 'apport-retrace '
        filearg = "'" + self.report_file.replace("'", "'\\''") + "'"

        cmds = {
            0: retrace_with_download + '--gdb ' + filearg,
            1: retrace_no_download + '--gdb ' + filearg,
            2: retrace_with_download + '--output ' + filearg + ' ' + filearg,
        }

        self.ui_run_terminal(cmds[response[0]])

    def collect_info(self, symptom_script=None, ignore_uninstalled=False):
        '''Collect additional information.

        Call all the add_*_info() methods and display a progress dialog during
        this.

        In particular, this adds OS, package and gdb information and checks bug
        patterns.

        If a symptom script is given, this will be run first (used by
        run_symptom()).
        '''
        # check if binary changed since the crash happened
        if 'ExecutablePath' in self.report and 'ExecutableTimestamp' in self.report:
            orig_time = int(self.report['ExecutableTimestamp'])
            del self.report['ExecutableTimestamp']
            cur_time = int(os.stat(self.report['ExecutablePath']).st_mtime)

            if orig_time != cur_time:
                self.report['UnreportableReason'] = _('The problem happened with the program %s which changed since then.') % self.report['ExecutablePath']
                return

        if not self.cur_package and 'ExecutablePath' not in self.report \
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

            if 'Stacktrace' not in self.report:
                # save original environment, in case hooks change it
                orig_env = os.environ.copy()

                icthread = apport.REThread.REThread(target=thread_collect_info,
                    name='thread_collect_info',
                    args=(self.report, self.report_file, self.cur_package,
                        hookui, symptom_script, ignore_uninstalled))
                icthread.start()
                while icthread.isAlive():
                    self.ui_pulse_info_collection_progress()
                    try:
                        hookui.process_event()
                    except KeyboardInterrupt:
                        sys.exit(1)

                icthread.join()

                # restore original environment
                os.environ.clear()
                os.environ.update(orig_env)

                icthread.exc_raise()

            if 'CrashDB' in self.report:
                self.crashdb = get_crashdb(None, self.report['CrashDB']) 

            # check bug patterns
            if self.report['ProblemType'] == 'KernelCrash' or self.report['ProblemType'] == 'KernelOops' or 'Package' in self.report:
                bpthread = apport.REThread.REThread(target=self.report.search_bug_patterns,
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
                    self.report['KnownReport'] = bpthread.return_value()

            # check crash database if problem is known
            if self.report['ProblemType'] != 'Bug':
                known_thread = apport.REThread.REThread(target=self.crashdb.known,
                    args=(self.report,))
                known_thread.start()
                while known_thread.isAlive():
                    self.ui_pulse_info_collection_progress()
                    try:
                        known_thread.join(0.1)
                    except KeyboardInterrupt:
                        sys.exit(1)
                known_thread.exc_raise()
                val = known_thread.return_value()
                if val is not None:
                    self.report['KnownReport'] = val

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
            os.setgroups([gid])
            os.setgid(gid)
            os.setuid(uid)
            os.unsetenv('SUDO_USER') # to make firefox not croak
            os.environ['HOME'] = pwd.getpwuid(uid).pw_dir
        except TypeError:
            pass

        try:
            try:
                subprocess.call(['xdg-open', url])
            except OSError:
                # fall back to webbrowser
                webbrowser.open(url, new=True, autoraise=True)
                sys.exit(0)
        except Exception as e:
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

        # StacktraceAddressSignature is redundant and does not need to clutter
        # the database
        try:
            del self.report['StacktraceAddressSignature']
        except KeyError:
            pass

        global __upload_progress
        __upload_progress = None

        def progress_callback(sent, total):
            global __upload_progress
            __upload_progress = float(sent)/total

        self.ui_start_upload_progress()
        upthread = apport.REThread.REThread(target=self.crashdb.upload,
            args=(self.report, progress_callback))
        upthread.start()
        while upthread.isAlive():
            self.ui_set_upload_progress(__upload_progress)
            try:
                upthread.join(0.1)
                upthread.exc_raise()
            except KeyboardInterrupt:
                sys.exit(1)
            except NeedsCredentials as e:
                message = _('Please enter your account information for the '
                            '%s bug tracking system')
                data = self.ui_question_userpass(message % excstr(e))
                if data is not None:
                    user, password = data
                    self.crashdb.set_credentials(user, password)
                    upthread = apport.REThread.REThread(target=self.crashdb.upload,
                                                 args=(self.report,
                                                       progress_callback))
                    upthread.start()
            except Exception as e:
                self.ui_error_message(_('Network problem'),
                        '%s\n\n%s' % (
                            _('Cannot connect to crash database, please check your Internet connection.'),
                             excstr(e)))
                return

        upthread.exc_raise()
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
            if 'ProblemType' not in self.report:
                raise ValueError('Report does not contain "ProblemType" field')
        except MemoryError:
            self.report = None
            self.ui_error_message(_('Memory exhaustion'),
                _('Your system does not have enough memory to process this crash report.'))
            return False
        except IOError as e:
            self.report = None
            self.ui_error_message(_('Invalid problem report'), e.strerror)
            return False
        except (TypeError, ValueError, AssertionError, zlib.error) as e:
            self.report = None
            self.ui_error_message(_('Invalid problem report'),
                '%s\n\n%s' % (
                    _('This problem report is damaged and cannot be processed.'),
                    repr(e)))
            return False

        if 'Package' in self.report:
            self.cur_package = self.report['Package'].split()[0]
        else:
            self.cur_package = apport.fileutils.find_file_package(self.report.get('ExecutablePath', ''))

        # ensure that the crashed program is still installed:
        if self.report['ProblemType'] == 'Crash':
            exe_path = self.report.get('ExecutablePath', '')
            if not os.path.exists(exe_path):
                msg = _('This problem report applies to a program which is not installed any more.')
                if exe_path:
                    msg = '%s (%s)' % (msg, self.report['ExecutablePath'])
                self.report = None
                self.ui_info_message(_('Invalid problem report'), msg)
                return False

            if 'InterpreterPath' in self.report:
                if not os.path.exists(self.report['InterpreterPath']):
                    msg = _('This problem report applies to a program which is not installed any more.')
                    self.ui_info_message(_('Invalid problem report'), '%s (%s)'
                            % (msg, self.report['InterpreterPath']))
                    return False

        return True

    def check_unreportable(self):
        '''Check if the current report is unreportable.

        If so, display an info message and return True.
        '''
        if 'UnreportableReason' in self.report:
            if isinstance(self.report['UnreportableReason'], str):
                self.report['UnreportableReason'] = self.report['UnreportableReason'].decode('UTF-8')
            if 'Package' in self.report:
                title = _('Problem in %s') % self.report['Package'].split()[0]
            else:
                title = ''
            self.ui_info_message(title, _('The problem cannot be reported:\n\n%s') %
                self.report['UnreportableReason'])
            return True
        return False

    def get_desktop_entry(self):
        '''Return a matching xdg.DesktopEntry for the current report.
        
        Return None if report cannot be associated to a .desktop file.
        '''
        if 'DesktopFile' in self.report and os.path.exists(self.report['DesktopFile']):
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
        if 'KnownReport' not in self.report:
            return False

        # if we have an URL, open it; otherwise this is just a marker that we
        # know about it
        if self.report['KnownReport'].startswith('http'):
            self.ui_info_message(_('Problem already known'),
                _('This problem was already reported in the bug report displayed \
in the web browser. Please check if you can add any further information that \
might be helpful for the developers.'))

            self.open_url(self.report['KnownReport'])
        else:
            self.ui_info_message(_('Problem already known'),
                _('This problem was already reported to developers. Thank you!'))

        return True

    def add_extra_tags(self):
        '''Add extra tags to report specified with --tags on CLI.'''

        assert self.report
        if self.options.tag:
            tags = self.report.get('Tags', '')
            if tags:
                tags += ' '
            self.report['Tags'] = tags + ' '.join(self.options.tag)

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
        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_present_package_error(self, desktopentry):
        '''Ask what to do with a package failure.

        Inform that a package installation/upgrade failure has happened for
        self.report and self.cur_package and ask about an action.

        Return the action: ignore ('cancel'), or report a bug about the problem
        ('report').
        '''
        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_present_kernel_error(self, desktopentry):
        '''Ask what to do with a kernel error.

        Inform that a kernel crash has happened for self.report and ask about
        an action.

        Return the action: ignore ('cancel'), or report a bug about the problem
        ('report').
        '''
        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_present_report_details(self, is_update):
        '''Show details of the bug report.
        
        This lets the user choose between sending a complete or reduced report,
        or examining the problem locally. This should only be offered if
        can_examine_locally() returns True.

        This method can use the get_complete_size() and get_reduced_size()
        methods to determine the respective size of the data to send, and
        format_filesize() to convert it to a humanly readable form.

        If is_update is True, the text should describe that an existing report is
        updated, otherwise a new report will be created.

        Return the action: send full report ('full'), send reduced report
        ('reduced'), examine locally ('examine'), or do not do anything ('cancel').
        '''
        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_info_message(self, title, text):
        '''Show an information message box with given title and text.'''

        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_error_message(self, title, text):
        '''Show an error message box with given title and text.'''

        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_start_info_collection_progress(self):
        '''Open a indefinite progress bar for data collection.
        
        This tells the user to wait while debug information is being
        collected.
        '''
        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_pulse_info_collection_progress(self):
        '''Advance the data collection progress bar.

        This function is called every 100 ms.
        '''
        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_stop_info_collection_progress(self):
        '''Close debug data collection progress window.'''

        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_start_upload_progress(self):
        '''Open progress bar for data upload.

        This tells the user to wait while debug information is being uploaded.
        '''
        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_set_upload_progress(self, progress):
        '''Update data upload progress bar.

        Set the progress bar in the debug data upload progress window to the
        given ratio (between 0 and 1, or None for indefinite progress).

        This function is called every 100 ms.
        '''
        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_stop_upload_progress(self):
        '''Close debug data upload progress window.'''

        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_shutdown(self):
        '''Called right before terminating the program.
        
        This can be used for for cleaning up.
        '''
        pass

    def ui_run_terminal(self, command):
        '''Run command in, or check for a terminal window.

        If command is given, run command in a terminal window; raise an exception
        if terminal cannot be opened. 
            
        If command is None, merely check if a terminal application is available
        and can be launched.
        '''
        raise NotImplementedError('this function must be overridden by subclasses')

    #
    # Additional UI dialogs; these are not required by Apport itself, but can
    # be used by interactive package hooks
    #

    def ui_question_yesno(self, text):
        '''Show a yes/no question.

        Return True if the user selected "Yes", False if selected "No" or
        "None" on cancel/dialog closing.
        '''
        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_question_choice(self, text, options, multiple):
        '''Show an question with predefined choices.

        options is a list of strings to present. If multiple is True, they
        should be check boxes, if multiple is False they should be radio
        buttons.

        Return list of selected option indexes, or None if the user cancelled.
        If multiple == False, the list will always have one element.
        '''
        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_question_file(self, text):
        '''Show a file selector dialog.

        Return path if the user selected a file, or None if cancelled.
        '''
        raise NotImplementedError('this function must be overridden by subclasses')

    def ui_question_userpass(self, message):
        '''Request username and password from user.

        message is the text to be presented to the user when requesting for
        username and password information.

        Return a tuple (username, password), or None if cancelled.
        '''
        raise NotImplementedError('this function must be overridden by subclasses')

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
    import unittest, shutil, signal, tempfile, resource
    try:
        from cStringIO import StringIO
    except ImportError:
        from io import StringIO
    import apport.report
    import problem_report
    import apport.crashdb_impl.memory

    class _TestSuiteUserInterface(UserInterface):
        '''Concrete UserInterface suitable for automatic testing.'''

        def __init__(self):
            # use our dummy crashdb
            self.crashdb_conf = tempfile.NamedTemporaryFile()
            self.crashdb_conf.write('''default = 'testsuite'
databases = {
    'testsuite': { 
        'impl': 'memory',
        'bug_pattern_url': None
    }
}
''')
            self.crashdb_conf.flush()

            os.environ['APPORT_CRASHDB_CONF'] = self.crashdb_conf.name

            UserInterface.__init__(self)

            self.crashdb = apport.crashdb_impl.memory.CrashDatabase(None,
                    {'dummy_data': 1})

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
            self.present_details_shown = False

            self.clear_msg()

        def clear_msg(self):
            # last message box
            self.msg_title = None
            self.msg_text = None
            self.msg_severity = None # 'warning' or 'error'
            self.msg_choices = None

        def ui_present_crash(self, desktopentry):
            return self.present_crash_response

        def ui_present_package_error(self):
            return self.present_package_error_response

        def ui_present_kernel_error(self):
            return self.present_kernel_error_response

        def ui_present_report_details(self, is_update):
            self.present_details_shown = True
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
            self.msg_choices = options
            return self.question_choice_response

        def ui_question_file(self, text):
            self.msg_text = text
            return self.question_file_response

    class _T(unittest.TestCase):
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
            self.report['ExecutablePath'] = '/bin/bash'
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

            # test suite should not stumble over local packages
            os.environ['APPORT_IGNORE_OBSOLETE_PACKAGES'] = '1'
            os.environ['APPORT_DISABLE_DISTRO_CHECK'] = '1'

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

            self.assertEqual(subprocess.call(['pidof', '/bin/yes']), 1, 'no stray test processes')

            # clean up apport report from _gen_test_crash()
            for f in glob.glob('/var/crash/_usr_bin_yes.*.crash'):
                try:
                    os.unlink(f)
                except OSError:
                    pass

            shutil.rmtree(self.hookdir)
            apport.report._hook_dir = self.orig_hook_dir

        def test_format_filesize(self):
            '''format_filesize().'''

            self.assertEqual(self.ui.format_filesize(0), '0.0 KB')
            self.assertEqual(self.ui.format_filesize(2048), '2.0 KB')
            self.assertEqual(self.ui.format_filesize(2560), '2.6 KB')
            self.assertEqual(self.ui.format_filesize(999999), '1000.0 KB')
            self.assertEqual(self.ui.format_filesize(1000000), '1.0 MB')
            self.assertEqual(self.ui.format_filesize(2.7*1000000), '2.7 MB')
            self.assertEqual(self.ui.format_filesize(1024*1000000), '1.0 GB')
            self.assertEqual(self.ui.format_filesize(2560*1000000), '2.6 GB')

        def test_get_size_loaded(self):
            '''get_complete_size() and get_reduced_size() for loaded Reports.'''

            self.ui.load_report(self.report_file.name)

            fsize = os.path.getsize(self.report_file.name)
            complete_ratio = float(self.ui.get_complete_size()) / fsize
            self.assertTrue(complete_ratio >= 0.99 and complete_ratio <= 1.01)
                
            rs = self.ui.get_reduced_size()
            self.assertTrue(rs > 1000)
            self.assertTrue(rs < 10000)

            # now add some information (e. g. from package hooks)
            self.ui.report['ExtraInfo'] = 'A' * 50000
            s = self.ui.get_complete_size()
            self.assertTrue(s >= fsize + 49900)
            self.assertTrue(s < fsize + 60000)

            rs = self.ui.get_reduced_size()
            self.assertTrue(rs > 51000)
            self.assertTrue(rs < 60000)

        def test_get_size_constructed(self):
            '''get_complete_size() and get_reduced_size() for on-the-fly Reports.'''

            self.ui.report = apport.Report('Bug')
            self.ui.report['Hello'] = 'World'

            s = self.ui.get_complete_size()
            self.assertTrue(s > 5)
            self.assertTrue(s < 100)

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
            del self.report['ExecutablePath']
            self.update_report_file()
            self.ui.load_report(self.report_file.name)

            self.assertTrue(self.ui.report == None)
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
            self.assertTrue(self.ui.report == None)
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
            self.assertTrue(os.path.exists(p))
            self.assertTrue(not os.path.exists(r))
            os.unlink(p)

            # test with RespawnCommand
            self.report['RespawnCommand'] = 'touch ' + r
            self.update_report_file()
            self.ui.load_report(self.report_file.name)

            self.ui.restart()
            time.sleep(1) # FIXME: race condition
            self.assertTrue(not os.path.exists(p))
            self.assertTrue(os.path.exists(r))
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
            self.assertTrue(set(['Date', 'Uname', 'DistroRelease', 'ProblemType']).issubset(
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
            self.assertTrue(set(['SourcePackage', 'Package', 'ProblemType',
                'Uname', 'Dependencies', 'DistroRelease', 'Date',
                'ExecutablePath']).issubset(set(self.ui.report.keys())))
            self.assertTrue(self.ui.ic_progress_pulses > 0,
                'progress dialog for package bug info collection')
            self.assertEqual(self.ui.ic_progress_active, False,
                'progress dialog for package bug info collection finished')

        def test_collect_info_package(self):
            '''collect_info() on report with a package.'''

            # report with only package information
            self.ui.report = apport.Report()
            self.ui.cur_package = 'bash'
            self.ui.collect_info()
            self.assertTrue(set(['SourcePackage', 'Package', 'ProblemType',
                'Uname', 'Dependencies', 'DistroRelease',
                'Date']).issubset(set(self.ui.report.keys())))
            self.assertTrue(self.ui.ic_progress_pulses > 0,
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
            self.report['KnownReport'] = demo_url
            self.update_report_file()
            self.ui.load_report(self.report_file.name)
            self.assertEqual(self.ui.handle_duplicate(), True)
            self.assertEqual(self.ui.msg_severity, 'info')
            self.assertEqual(self.ui.opened_url, demo_url)

            self.ui.opened_url = None
            demo_url = 'http://example.com/1'
            self.report['KnownReport'] = '1'
            self.update_report_file()
            self.ui.load_report(self.report_file.name)
            self.assertEqual(self.ui.handle_duplicate(), True)
            self.assertEqual(self.ui.msg_severity, 'info')
            self.assertEqual(self.ui.opened_url, None)

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

        def test_run_version(self):
            '''run_report_bug() as "ubuntu-bug" with version argument.'''

            sys.argv = ['ubuntu-bug', '-v']
            self.ui = _TestSuiteUserInterface()
            orig_stdout = sys.stdout
            sys.stdout = StringIO()
            self.assertEqual(self.ui.run_argv(), True)
            output = sys.stdout.getvalue()
            sys.stdout = orig_stdout
            self.assertEqual(output, __version__+"\n")

        def test_run_report_bug_package(self):
            '''run_report_bug() for a package.'''

            sys.argv = ['ui-test', '-f', '-p', 'bash']
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), True)

            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertTrue(self.ui.present_details_shown)
            self.assertEqual(self.ui.opened_url, 'http://bash.bugs.example.com/%i' % self.ui.crashdb.latest_id())

            self.assertTrue(self.ui.ic_progress_pulses > 0)
            self.assertEqual(self.ui.report['SourcePackage'], 'bash')
            self.assertTrue('Dependencies' in self.ui.report.keys())
            self.assertTrue('ProcEnviron' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Bug')

            # should not crash on nonexisting package
            sys.argv = ['ui-test', '-f', '-p', 'nonexisting_gibberish']
            self.ui = _TestSuiteUserInterface()
            self.ui.run_argv()

            self.assertEqual(self.ui.msg_severity, 'error')

        def test_run_report_bug_pid_tags(self):
            '''run_report_bug() for a pid with extra tags.'''

            # fork a test process
            pid = os.fork()
            if pid == 0:
                os.dup2(os.open('/dev/null', os.O_WRONLY), sys.stdout.fileno())
                os.execv('/usr/bin/yes', ['yes'])
                assert False, 'Could not execute /usr/bin/yes'

            time.sleep(0.5)

            try:
                # report a bug on yes process
                sys.argv = ['ui-test', '-f', '--tag', 'foo', '-P', str(pid)]
                self.ui = _TestSuiteUserInterface()
                self.assertEqual(self.ui.run_argv(), True)
            finally:
                # kill test process
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

            self.assertTrue('SourcePackage' in self.ui.report.keys())
            self.assertTrue('Dependencies' in self.ui.report.keys())
            self.assertTrue('ProcMaps' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ExecutablePath'], '/usr/bin/yes')
            self.assertFalse('ProcCmdline' in self.ui.report) # privacy!
            self.assertTrue('ProcEnviron' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Bug')
            self.assertTrue('Tags' in self.ui.report.keys())
            self.assertTrue('foo' in self.ui.report['Tags'])

            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, 'http://coreutils.bugs.example.com/%i' % self.ui.crashdb.latest_id())
            self.assertTrue(self.ui.present_details_shown)
            self.assertTrue(self.ui.ic_progress_pulses > 0)

        @classmethod
        def _find_unused_pid(klass):
            '''Find and return an unused PID.'''

            pid = 1
            while True:
                pid += 1
                try:
                    os.kill(pid, 0)
                except OSError as e:
                    if e.errno == errno.ESRCH:
                        break
            return pid

        def test_run_report_bug_wrong_pid(self):
            '''run_report_bug() for a nonexisting pid.'''

            # silently ignore missing PID; this happens when the user closes
            # the application prematurely
            pid = self._find_unused_pid()
            sys.argv = ['ui-test', '-f', '-P', str(pid)]
            self.ui = _TestSuiteUserInterface()
            self.ui.run_argv()

        def test_run_report_bug_noperm_pid(self):
            '''run_report_bug() for a pid which runs as a different user.'''

            restore_root = False
            if os.getuid() == 0:
                # temporarily drop to normal user "mail"
                os.setresuid(8, 8, -1)
                restore_root = True

            try:
                sys.argv = ['ui-test', '-f', '-P', '1']
                self.ui = _TestSuiteUserInterface()
                self.ui.run_argv()

                self.assertEqual(self.ui.msg_severity, 'error')
            finally:
                if restore_root:
                    os.setresuid(0, 0, -1)

        def test_run_report_bug_unpackaged_pid(self):
            '''run_report_bug() for a pid of an unpackaged program.'''

            # create unpackaged test program
            (fd, exename) = tempfile.mkstemp()
            os.write(fd, open('/usr/bin/yes').read())
            os.close(fd)
            os.chmod(exename, 0o755)

            # unpackaged test process
            pid = os.fork()
            if pid == 0:
                os.dup2(os.open('/dev/null', os.O_WRONLY), sys.stdout.fileno())
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

        def test_run_report_bug_kernel_thread(self):
            '''run_report_bug() for a pid of a kernel thread.'''

            import glob
            pid = None
            for path in glob.glob('/proc/[0-9]*/stat'):
                stat = open(path).read().split()
                flags = int(stat[8])
                if flags & PF_KTHREAD:
                    pid = int(stat[0])
                    break

            self.assertFalse(pid is None)
            sys.argv = ['ui-test', '-f', '-P', str(pid)]
            self.ui = _TestSuiteUserInterface()
            self.ui.run_argv()

            self.assertTrue(self.ui.report['Package'].startswith(apport.packaging.get_kernel_package()))

        def test_run_report_bug_file(self):
            '''run_report_bug() with saving report into a file.'''

            d = os.path.join(apport.fileutils.report_dir, 'home')
            os.mkdir(d)
            reportfile = os.path.join(d, 'bashisbad.apport')

            sys.argv = ['ui-test', '-f', '-p', 'bash', '--save', reportfile]
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), True)

            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertFalse(self.ui.present_details_shown)

            self.assertTrue(self.ui.ic_progress_pulses > 0)

            r = apport.Report()
            r.load(open(reportfile))

            self.assertEqual(r['SourcePackage'], 'bash')
            self.assertTrue('Dependencies' in r.keys())
            self.assertTrue('ProcEnviron' in r.keys())
            self.assertEqual(r['ProblemType'], 'Bug')

            # report it
            sys.argv = ['ui-test', '-c', reportfile]
            self.ui = _TestSuiteUserInterface()
            
            self.ui.present_details_response = 'full'
            self.assertEqual(self.ui.run_argv(), True)

            self.assertEqual(self.ui.msg_text, None)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertTrue(self.ui.present_details_shown)

        def _gen_test_crash(self):
            '''Generate a Report with real crash data.'''

            # create a test executable
            test_executable = '/usr/bin/yes'
            assert os.access(test_executable, os.X_OK), test_executable + ' is not executable'
            pid = os.fork()
            if pid == 0:
                os.dup2(os.open('/dev/null', os.O_WRONLY), sys.stdout.fileno())
                sys.stdin.close()
                os.setsid()
                resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
                os.chdir(apport.fileutils.report_dir)
                os.execv(test_executable, [test_executable])
                assert False, 'Could not execute ' + test_executable

            time.sleep(0.5)

            # generate crash report
            r = apport.Report()
            r['ExecutablePath'] = test_executable
            r['Signal'] = '11'
            r.add_proc_info(pid)
            r.add_user_info()

            # generate a core dump
            coredump = os.path.join(apport.fileutils.report_dir, 'core')
            os.kill(pid, signal.SIGSEGV)
            os.waitpid(pid, 0)
            assert os.path.exists(coredump)
            r['CoreDump'] = (coredump,)

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
            self.assertFalse(self.ui.present_details_shown)

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
            self.assertTrue(self.ui.present_details_shown)

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
            self.assertTrue(self.ui.present_details_shown)

            self.assertTrue('SourcePackage' in self.ui.report.keys())
            self.assertTrue('Dependencies' in self.ui.report.keys())
            self.assertTrue('Stacktrace' in self.ui.report.keys())
            self.assertTrue('ProcEnviron' in self.ui.report.keys())
            self.assertFalse('ExecutableTimestamp' in self.ui.report.keys())
            self.assertFalse('StacktraceAddressSignature' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Crash')
            self.assertTrue(len(self.ui.report['CoreDump']) > 10000)
            self.assertTrue(self.ui.report['Title'].startswith('yes crashed with SIGSEGV'))

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
            self.assertTrue(self.ui.present_details_shown)

            self.assertTrue('SourcePackage' in self.ui.report.keys())
            self.assertTrue('Dependencies' in self.ui.report.keys())
            self.assertTrue('Stacktrace' in self.ui.report.keys())
            self.assertFalse('ExecutableTimestamp' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Crash')
            self.assertTrue('CoreDump' not in self.ui.report)

            # so far we did not blacklist, verify that
            self.assertTrue(not self.ui.report.check_ignored())

            # cancel crash notification dialog and blacklist
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_crash_response = {'action': 'cancel', 'blacklist': True }
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertEqual(self.ui.ic_progress_pulses, 0)

            self.assertTrue(self.ui.report.check_ignored())

        def test_run_crash_abort(self):
            '''run_crash() for an abort() without assertion message'''

            r = self._gen_test_crash()
            r['Signal'] = '6'
            report_file = os.path.join(apport.fileutils.report_dir, 'test.crash')
            r.write(open(report_file, 'w'))

            self.ui.present_crash_response = {'action': 'report', 'blacklist': False }
            self.ui.present_details_response = 'full'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None,  self.ui.msg_text)

            self.assertTrue('SourcePackage' in self.ui.report.keys())
            self.assertTrue('Dependencies' in self.ui.report.keys())
            self.assertTrue('Stacktrace' in self.ui.report.keys())
            self.assertTrue('ProcEnviron' in self.ui.report.keys())
            self.assertFalse('ExecutableTimestamp' in self.ui.report.keys())
            self.assertEqual(self.ui.report['Signal'], '6')

            # we disable the ABRT filtering, we want these crashes after all 
            #self.assertTrue('assert' in self.ui.msg_text, '%s: %s' %
            #    (self.ui.msg_title, self.ui.msg_text))
            #self.assertEqual(self.ui.msg_severity, 'info')
            self.assertEqual(self.ui.msg_severity, None)
            self.assertTrue(self.ui.present_details_shown)

        def test_run_crash_argv_file(self):
            '''run_crash() through a file specified on the command line.'''

            # valid
            self.report['Package'] = 'bash'
            self.update_report_file()

            sys.argv = ['ui-test', '-c', self.report_file.name]
            self.ui = _TestSuiteUserInterface()
            
            self.ui.present_details_response = 'full'
            self.assertEqual(self.ui.run_argv(), True)

            self.assertEqual(self.ui.msg_text, None)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertTrue(self.ui.present_details_shown)

            # unreportable
            self.report['Package'] = 'bash'
            self.report['UnreportableReason'] = u'It stinks. \u2665'
            self.update_report_file()

            sys.argv = ['ui-test', '-c', self.report_file.name]
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), True)

            self.assertTrue('It stinks.' in self.ui.msg_text, '%s: %s' %
                (self.ui.msg_title, self.ui.msg_text))
            self.assertEqual(self.ui.msg_severity, 'info')
            self.assertFalse(self.ui.present_details_shown)

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

            self.assertTrue('It stinks.' in self.ui.msg_text, '%s: %s' %
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
            test_executable = '/usr/bin/yes'
            assert os.access(test_executable, os.X_OK), test_executable + ' is not executable'
            pid = os.fork()
            if pid == 0:
                os.setsid()
                os.dup2(os.open('/dev/null', os.O_WRONLY), sys.stdout.fileno())
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
            self.assertTrue('memory' in self.ui.msg_text, '%s: %s' %
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
            self.assertTrue(self.ui.present_details_shown)
           
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

        def test_run_crash_updated_binary(self):
            '''run_crash() on binary that got updated in the meantime'''

            r = self._gen_test_crash()
            r['ExecutableTimestamp'] = str(int(r['ExecutableTimestamp'])-10)
            report_file = os.path.join(apport.fileutils.report_dir, 'test.crash')
            r.write(open(report_file, 'w'))

            self.ui.present_crash_response = {'action': 'report', 'blacklist': False }
            self.ui.present_details_response = 'full'
            self.ui.run_crash(report_file)

            self.assertFalse('ExecutableTimestamp' in self.ui.report)
            self.assertTrue(self.ui.report['ExecutablePath'] in self.ui.msg_text, '%s: %s' %
                (self.ui.msg_title, self.ui.msg_text))
            self.assertTrue('changed' in self.ui.msg_text, '%s: %s' %
                (self.ui.msg_title, self.ui.msg_text))
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
            self.assertFalse(self.ui.present_details_shown)

            # report in crash notification dialog, send report
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_package_error_response = 'report'
            self.ui.present_details_response = 'full'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, 'http://bash.bugs.example.com/%i' % self.ui.crashdb.latest_id())
            self.assertTrue(self.ui.present_details_shown)

            self.assertTrue('SourcePackage' in self.ui.report.keys())
            self.assertTrue('Package' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Package')

            # verify that additional information has been collected
            self.assertTrue('Architecture' in self.ui.report.keys())
            self.assertTrue('DistroRelease' in self.ui.report.keys())
            self.assertTrue('Uname' in self.ui.report.keys())

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
            self.assertFalse(self.ui.present_details_shown)

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
            self.assertTrue(self.ui.present_details_shown)

            self.assertTrue('SourcePackage' in self.ui.report.keys())
            # did we run the hooks properly?
            self.assertTrue('KernelDebug' in self.ui.report.keys())
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
            self.assertEqual(self.ui.msg_severity, None,  self.ui.msg_text)

            self.assertFalse('ProcCwd' in self.ui.report)

            dump = StringIO()
            self.ui.report.write(dump)

            p = pwd.getpwuid(os.getuid())
            bad_strings = [os.uname()[1], p[0], p[4], p[5], os.getcwd()]

            for s in bad_strings:
                self.assertFalse(s in dump.getvalue(), 'dump contains sensitive string: %s' % s)

        def test_run_crash_known(self):
            '''run_crash() for already known problem'''

            r = self._gen_test_crash()
            report_file = os.path.join(apport.fileutils.report_dir, 'test.crash')
            self.ui = _TestSuiteUserInterface()
            self.ui.present_crash_response = {'action': 'report', 'blacklist': False }
            self.ui.present_details_response = 'full'

            # known without URL
            with open(report_file, 'w') as f:
                r.write(f)
            self.ui.crashdb.known = lambda r: '1'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.report['KnownReport'], '1')
            self.assertEqual(self.ui.msg_severity, 'info')
            self.assertEqual(self.ui.opened_url, None)

            # known with URL
            with open(report_file, 'w') as f:
                r.write(f)
            self.ui.crashdb.known = lambda r: 'http://myreport/1'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.report['KnownReport'], 'http://myreport/1')
            self.assertEqual(self.ui.msg_severity, 'info')
            self.assertEqual(self.ui.opened_url, 'http://myreport/1')

        def test_run_update_report_nonexisting_package_from_bug(self):
            '''run_update_report() on a nonexisting package (from bug).'''

            sys.argv = ['ui-test', '-u', '1']
            self.ui = _TestSuiteUserInterface()

            self.assertEqual(self.ui.run_argv(), False)
            self.assertTrue('No additional information collected.' in
                    self.ui.msg_text)
            self.assertFalse(self.ui.present_details_shown)

        def test_run_update_report_nonexisting_package_cli(self):
            '''run_update_report() on a nonexisting package (CLI argument).'''

            sys.argv = ['ui-test', '-u', '1', '-p', 'bar']
            self.ui = _TestSuiteUserInterface()

            self.assertEqual(self.ui.run_argv(), False)
            self.assertTrue('No additional information collected.' in
                    self.ui.msg_text)
            self.assertFalse(self.ui.present_details_shown)

        def test_run_update_report_existing_package_from_bug(self):
            '''run_update_report() on an existing package (from bug).'''

            sys.argv = ['ui-test', '-u', '1']
            self.ui = _TestSuiteUserInterface()

            self.ui.crashdb.download(1)['SourcePackage'] = 'bash'
            self.ui.crashdb.download(1)['Package'] = 'bash'
            self.assertEqual(self.ui.run_argv(), True)
            self.assertEqual(self.ui.msg_severity, None, self.ui.msg_text)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertTrue(self.ui.present_details_shown)

            self.assertTrue(self.ui.ic_progress_pulses > 0)
            self.assertTrue(self.ui.report['Package'].startswith('bash '))
            self.assertTrue('Dependencies' in self.ui.report.keys())
            self.assertTrue('ProcEnviron' in self.ui.report.keys())

        def test_run_update_report_existing_package_cli_tags(self):
            '''run_update_report() on an existing package (CLI argument) with extra tag'''

            sys.argv = ['ui-test', '-u', '1', '-p', 'bash', '--tag', 'foo']
            self.ui = _TestSuiteUserInterface()

            self.assertEqual(self.ui.run_argv(), True)
            self.assertEqual(self.ui.msg_severity, None, self.ui.msg_text)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertTrue(self.ui.present_details_shown)

            self.assertTrue(self.ui.ic_progress_pulses > 0)
            self.assertTrue(self.ui.report['Package'].startswith('bash '))
            self.assertTrue('Dependencies' in self.ui.report.keys())
            self.assertTrue('ProcEnviron' in self.ui.report.keys())
            self.assertTrue('foo' in self.ui.report['Tags'])

        def test_run_update_report_existing_package_cli_cmdname(self):
            '''run_update_report() on an existing package (-collect program).'''

            sys.argv = ['apport-collect', '-p', 'bash', '1']
            self.ui = _TestSuiteUserInterface()

            self.assertEqual(self.ui.run_argv(), True)
            self.assertEqual(self.ui.msg_severity, None, self.ui.msg_text)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertTrue(self.ui.present_details_shown)

            self.assertTrue(self.ui.ic_progress_pulses > 0)
            self.assertTrue(self.ui.report['Package'].startswith('bash '))
            self.assertTrue('Dependencies' in self.ui.report.keys())
            self.assertTrue('ProcEnviron' in self.ui.report.keys())

        def test_run_update_report_noninstalled_but_hook(self):
            '''run_update_report() on an uninstalled package with a source hook.'''

            sys.argv = ['ui-test', '-u', '1']
            self.ui = _TestSuiteUserInterface()

            f = open(os.path.join(self.hookdir, 'source_foo.py'), 'w')
            f.write('def add_info(r, ui):\n  r["MachineType"]="Laptop"\n')
            f.close()

            self.assertEqual(self.ui.run_argv(), True, self.ui.report)
            self.assertEqual(self.ui.msg_severity, None, self.ui.msg_text)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertTrue(self.ui.present_details_shown)

            self.assertTrue(self.ui.ic_progress_pulses > 0)
            self.assertEqual(self.ui.report['Package'], 'foo (not installed)')
            self.assertEqual(self.ui.report['MachineType'], 'Laptop')
            self.assertTrue('ProcEnviron' in self.ui.report.keys())

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
            self.assertTrue('foobar" is not known' in self.ui.msg_text)
            self.assertEqual(self.ui.msg_severity, 'error')

            # does not determine package
            f = open(os.path.join(symptom_script_dir, 'nopkg.py'), 'w')
            f.write('def run(report, ui):\n    pass\n')
            f.close()
            orig_stderr = sys.stderr
            sys.argv = ['ui-test', '-s', 'nopkg' ]
            self.ui = _TestSuiteUserInterface()
            sys.stderr = StringIO()
            self.assertRaises(SystemExit, self.ui.run_argv)
            err = sys.stderr.getvalue()
            sys.stderr = orig_stderr
            self.assertTrue('did not determine the affected package' in err)

            # does not define run()
            f = open(os.path.join(symptom_script_dir, 'norun.py'), 'w')
            f.write('def something(x, y):\n    return 1\n')
            f.close()
            sys.argv = ['ui-test', '-s', 'norun' ]
            self.ui = _TestSuiteUserInterface()
            sys.stderr = StringIO()
            self.assertRaises(SystemExit, self.ui.run_argv)
            err = sys.stderr.getvalue()
            sys.stderr = orig_stderr
            self.assertTrue('norun.py crashed:' in err)

            # crashing script
            f = open(os.path.join(symptom_script_dir, 'crash.py'), 'w')
            f.write('def run(report, ui):\n    return 1/0\n')
            f.close()
            sys.argv = ['ui-test', '-s', 'crash' ]
            self.ui = _TestSuiteUserInterface()
            sys.stderr = StringIO()
            self.assertRaises(SystemExit, self.ui.run_argv)
            err = sys.stderr.getvalue()
            sys.stderr = orig_stderr
            self.assertTrue('crash.py crashed:' in err)
            self.assertTrue('ZeroDivisionError:' in err)

            # working noninteractive script
            f = open(os.path.join(symptom_script_dir, 'itching.py'), 'w')
            f.write('def run(report, ui):\n  report["itch"] = "scratch"\n  return "bash"\n')
            f.close()
            sys.argv = ['ui-test', '-s', 'itching' ]
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), True)
            self.assertEqual(self.ui.msg_text, None)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertTrue(self.ui.present_details_shown)

            self.assertEqual(self.ui.report['itch'], 'scratch')
            self.assertTrue('DistroRelease' in self.ui.report)
            self.assertEqual(self.ui.report['SourcePackage'], 'bash')
            self.assertTrue(self.ui.report['Package'].startswith('bash '))
            self.assertEqual(self.ui.report['ProblemType'], 'Bug')

            # working noninteractive script with extra tag
            sys.argv = ['ui-test', '--tag', 'foo', '-s', 'itching' ]
            self.ui = _TestSuiteUserInterface()
            self.assertEqual(self.ui.run_argv(), True)
            self.assertEqual(self.ui.msg_text, None)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertTrue(self.ui.present_details_shown)

            self.assertEqual(self.ui.report['itch'], 'scratch')
            self.assertTrue('foo' in self.ui.report['Tags'])

            # working interactive script
            f = open(os.path.join(symptom_script_dir, 'itching.py'), 'w')
            f.write('''def run(report, ui):
    report['itch'] = 'slap'
    report['q'] = str(ui.yesno('do you?'))
    return 'bash'
''')
            f.close()
            sys.argv = ['ui-test', '-s', 'itching' ]
            self.ui = _TestSuiteUserInterface()
            self.ui.question_yesno_response = True
            self.assertEqual(self.ui.run_argv(), True)
            self.assertTrue(self.ui.present_details_shown)
            self.assertEqual(self.ui.msg_text, 'do you?')

            self.assertEqual(self.ui.report['itch'], 'slap')
            self.assertTrue('DistroRelease' in self.ui.report)
            self.assertEqual(self.ui.report['SourcePackage'], 'bash')
            self.assertTrue(self.ui.report['Package'].startswith('bash '))
            self.assertEqual(self.ui.report['ProblemType'], 'Bug')
            self.assertEqual(self.ui.report['q'], 'True')

        def test_run_report_bug_list_symptoms(self):
            '''run_report_bug() without specifying arguments and available symptoms.'''

            f = open(os.path.join(symptom_script_dir, 'foo.py'), 'w')
            f.write('''description = 'foo does not work'
def run(report, ui):
    return 'bash'
''')
            f.close()
            f = open(os.path.join(symptom_script_dir, 'bar.py'), 'w')
            f.write('def run(report, ui):\n  return "coreutils"\n')
            f.close()

            sys.argv = ['ui-test', '-f']
            self.ui = _TestSuiteUserInterface()

            self.ui.question_choice_response = None
            self.assertEqual(self.ui.run_argv(), True)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertTrue('kind of problem' in self.ui.msg_text)
            self.assertEqual(set(self.ui.msg_choices), 
                    set(['bar', 'foo does not work', 'Other problem']))

            # cancelled
            self.assertEqual(self.ui.ic_progress_pulses, 0)
            self.assertEqual(self.ui.report, None)
            self.assertFalse(self.ui.present_details_shown)

            # now, choose foo -> bash report
            self.ui.question_choice_response = [self.ui.msg_choices.index('foo does not work')]
            self.assertEqual(self.ui.run_argv(), True)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertTrue(self.ui.ic_progress_pulses > 0)
            self.assertTrue(self.ui.present_details_shown)
            self.assertTrue(self.ui.report['Package'].startswith('bash'))

        def test_parse_argv_single_arg(self):
            '''parse_args() option inference for a single argument'''

            def _chk(program_name, arg, expected_opts):
                sys.argv = [program_name]
                if arg:
                    sys.argv.append(arg)
                orig_stderr = sys.stderr
                sys.stderr = open('/dev/null', 'w')
                try:
                    ui = UserInterface()
                finally:
                    sys.stderr.close()
                    sys.stderr = orig_stderr
                expected_opts['version'] = None
                self.assertEqual(ui.args, [])
                self.assertEqual(ui.options, expected_opts)

            # no arguments -> show pending crashes
            _chk('apport-gtk', None, {'filebug': False, 'package': None,
                'pid': None, 'crash_file': None, 'symptom': None, 
                'update_report': None, 'save': None, 'window': False, 
                'tag': []})
            # updating report not allowed without args
            self.assertRaises(SystemExit, _chk, 'apport-collect', None, {})

            # package 
            _chk('apport-kde', 'coreutils', {'filebug': True, 'package':
                'coreutils', 'pid': None, 'crash_file': None, 'symptom': None, 
                'update_report': None, 'save': None, 'window': False, 
                'tag': []})

            # symptom is preferred over package
            f = open(os.path.join(symptom_script_dir, 'coreutils.py'), 'w')
            f.write('''description = 'foo does not work'
def run(report, ui):
    return 'bash'
''')
            f.close()
            _chk('apport-cli', 'coreutils', {'filebug': True, 'package': None,
                 'pid': None, 'crash_file': None, 'symptom': 'coreutils',
                 'update_report': None, 'save': None, 'window': False, 
                 'tag': []})

            # PID
            _chk('apport-cli', '1234', {'filebug': True, 'package': None,
                 'pid': '1234', 'crash_file': None, 'symptom': None,
                 'update_report': None, 'save': None, 'window': False, 
                 'tag': []})

            # .crash/.apport files; check correct handling of spaces
            for suffix in ('.crash', '.apport'):
                _chk('apport-cli', '/tmp/f oo' + suffix, {'filebug': False,
                     'package': None, 'pid': None, 
                     'crash_file': '/tmp/f oo' + suffix, 'symptom': None,
                     'update_report': None, 'save': None, 'window': False, 
                     'tag': []})

            # executable
            _chk('apport-cli', '/usr/bin/tail', {'filebug': True, 
                 'package': 'coreutils',
                 'pid': None, 'crash_file': None, 'symptom': None, 
                 'update_report': None, 'save': None, 'window': False, 
                 'tag': []})

            # update existing report
            _chk('apport-collect', '1234', {'filebug': False, 'package': None,
                 'crash_file': None, 'symptom': None, 'update_report': 1234,
                 'tag': []})
            _chk('apport-update-bug', '1234', {'filebug': False, 'package': None,
                 'crash_file': None, 'symptom': None, 'update_report': 1234,
                 'tag': []})

        def test_parse_argv_apport_bug(self):
            '''parse_args() option inference when invoked as *-bug'''

            def _chk(args, expected_opts):
                sys.argv = ['apport-bug'] + args
                orig_stderr = sys.stderr
                sys.stderr = open('/dev/null', 'w')
                try:
                    ui = UserInterface()
                finally:
                    sys.stderr.close()
                    sys.stderr = orig_stderr
                expected_opts['version'] = None
                self.assertEqual(ui.args, [])
                self.assertEqual(ui.options, expected_opts)

            #
            # no arguments: default to 'ask for symptom' bug mode
            #
            _chk([], {'filebug': True, 'package': None,
                'pid': None, 'crash_file': None, 'symptom': None, 
                'update_report': None, 'save': None, 'window': False,
                'tag': []})

            #
            # single arguments
            #

            # package
            _chk(['coreutils'], {'filebug': True, 'package':
                'coreutils', 'pid': None, 'crash_file': None, 'symptom': None, 
                'update_report': None, 'save': None, 'window': False, 
                'tag': []})

            # symptom (preferred over package)
            f = open(os.path.join(symptom_script_dir, 'coreutils.py'), 'w')
            f.write('''description = 'foo does not work'
def run(report, ui):
    return 'bash'
''')
            f.close()
            _chk(['coreutils'], {'filebug': True, 'package': None,
                 'pid': None, 'crash_file': None, 'symptom': 'coreutils',
                 'update_report': None, 'save': None, 'window': False, 
                 'tag': []})
            os.unlink(os.path.join(symptom_script_dir, 'coreutils.py'))

            # PID
            _chk(['1234'], {'filebug': True, 'package': None,
                 'pid': '1234', 'crash_file': None, 'symptom': None,
                 'update_report': None, 'save': None, 'window': False, 
                 'tag': []})

            # .crash/.apport files; check correct handling of spaces
            for suffix in ('.crash', '.apport'):
                _chk(['/tmp/f oo' + suffix], {'filebug': False,
                     'package': None, 'pid': None, 
                     'crash_file': '/tmp/f oo' + suffix, 'symptom': None,
                     'update_report': None, 'save': None, 'window': False, 
                     'tag': []})

            # executable name
            _chk(['/usr/bin/tail'], {'filebug': True, 'package': 'coreutils',
                 'pid': None, 'crash_file': None, 'symptom': None, 
                 'update_report': None, 'save': None, 'window': False, 
                 'tag': []})

            #
            # supported options
            #

            # --save
            _chk(['--save', 'foo.apport', 'coreutils'], {'filebug': True,
                'package': 'coreutils', 'pid': None, 'crash_file': None,
                'symptom': None, 'update_report': None, 'save': 'foo.apport',
                'window': False, 'tag': []})

            # --tag
            _chk(['--tag', 'foo', 'coreutils'], {'filebug': True,
                'package': 'coreutils', 'pid': None, 'crash_file': None,
                'symptom': None, 'update_report': None, 'save': None,
                'window': False, 'tag': ['foo']})
            _chk(['--tag', 'foo', '--tag', 'bar', 'coreutils'], {
                'filebug': True, 'package': 'coreutils', 'pid': None,
                'crash_file': None, 'symptom': None, 'update_report': None,
                'save': None, 'window': False, 'tag': ['foo', 'bar']})

        def test_can_examine_locally_crash(self):
            '''can_examine_locally() for a crash report'''

            self.ui.load_report(self.report_file.name)

            orig_path = os.environ['PATH']
            orig_fn = self.ui.ui_run_terminal
            try:
                self.ui.ui_run_terminal = lambda command: True
                os.environ['PATH'] = ''
                self.assertEqual(self.ui.can_examine_locally(), False)

                src_bindir = os.path.join(
                        os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 
                        'bin')
                # this will only work for running the tests in the source tree
                if os.access(os.path.join(src_bindir, 'apport-retrace'), os.X_OK):
                    os.environ['PATH'] = src_bindir
                    self.assertEqual(self.ui.can_examine_locally(), True)
                else:
                    # if we run tests in installed system, we just check that
                    # it doesn't crash
                    self.assertTrue(self.ui.can_examine_locally() in [False, True])

                self.ui.ui_run_terminal = lambda command: False
                self.assertEqual(self.ui.can_examine_locally(), False)

                # does not crash on NotImplementedError
                self.ui.ui_run_terminal = orig_fn
                self.assertEqual(self.ui.can_examine_locally(), False)

            finally:
                os.environ['PATH'] = orig_path
                self.ui.ui_run_terminal = orig_fn

        def test_can_examine_locally_nocrash(self):
            '''can_examine_locally() for a non-crash report'''

            self.ui.load_report(self.report_file.name)
            del self.ui.report['CoreDump']

            orig_path = os.environ['PATH']
            orig_fn = self.ui.ui_run_terminal
            try:
                self.ui.ui_run_terminal = lambda command: True
                src_bindir = os.path.join(
                        os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 
                        'bin')
                self.assertEqual(self.ui.can_examine_locally(), False)
            finally:
                os.environ['PATH'] = orig_path
                self.ui.ui_run_terminal = orig_fn

    unittest.main()

