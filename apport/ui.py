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
import subprocess, threading, webbrowser, xdg.DesktopEntry
from gettext import gettext as _

import apport, apport.fileutils

bugpattern_baseurl = 'http://people.ubuntu.com/~pitti/bugpatterns'

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
    report.add_os_info()

    if reportfile:
        f = open(reportfile, 'w')
        os.chmod (reportfile, 0)
        report.write(f)
        f.close()
        os.chmod (reportfile, 0600)
        apport.fileutils.mark_report_seen(reportfile)

def thread_check_bugpatterns(report, baseurl):
    '''Encapsulate call to search_bug_patterns() and return the result in a
    global variable, so that it is suitable for threading.'''

    global thread_check_bugpatterns_result
    try:
        thread_check_bugpatterns_result = \
            report.search_bug_patterns(baseurl)
    except Exception, e:
        e.backtrace = ''.join(
            traceback.format_exception(sys.exc_type, sys.exc_value, sys.exc_traceback))
        thread_check_bugpatterns_result = e

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

        gettext.textdomain(self.gettext_domain)
        self.parse_argv()

    #
    # main entry points
    #
    
    def run_crashes(self):
        '''Present all currently pending crash reports to the user, ask him
        what to do about them, and offer to file bugs for them.'''
        
        for f in apport.fileutils.get_new_reports():
            self.run_crash(f)

    def run_crash(self, report_file):
        '''Present given crash report to the user, ask him what to do about it,
        and offer to file a bug for it.'''

        if not self.load_report(report_file):
            return

        # ask the user about what to do with the current crash
        desktop_entry = self.get_desktop_entry()
        response = self.ui_present_crash(desktop_entry)
        if response == 'cancel':
            return
        if response == 'restart':
            self.restart()
            return
        assert response == 'report'

        # we want to file a bug now
        self.collect_info()

        if self.handle_duplicate():
            return

        response = self.ui_present_report_details()
        if response == 'cancel':
            return
        if response == 'reduced':
            del self.report['CoreDump']
        else:
            assert response == 'full'

        self.file_report()

    def run_report_bug(self):
        '''Report a bug.

        If a pid is given on the command line, the report will contain runtime
        debug information. If neither a package or a pid is specified, a
        generic distro bug is filed.'''

	self.report = apport.Report('Bug')
	if self.options.pid:
	    self.report.add_proc_info(self.options.pid)
        self.cur_package = self.options.package

        self.collect_info()
        self.file_report()

    def run_argv(self):
        '''Call appopriate run_* method according to command line arguments.'''

        if self.options.filebug:
            self.run_report_bug()
        else:
            self.run_crashes()

    #
    # functions that implement workflow bits
    #

    def parse_argv(self): 
        '''Parse command line options and return (options,
        args) tuple.'''

        optparser = optparse.OptionParser('%prog [options]')
        optparser.add_option('-f', '--file-bug',
            help='Start in bug filing mode. Requires --source and an optional --pid, or just a --pid',
            action='store_true', dest='filebug', default=False)
        optparser.add_option('-p', '--package',
            help='Specify package name in --file-bug mode. This is optional if a --pid is specified.',
            action='store', type='string', dest='package', default=None)
        optparser.add_option('-P', '--pid',
            help='Specify a running program in --file-bug mode. If this is specified, the bug report will contain more information.',
            action='store', type='string', dest='pid', default=None)

        (self.options, self.args) = optparser.parse_args()

    def format_filesize(self, size):
        '''Format the given integer as humanly readable and i18n'ed file size.'''

        if size < 1048576:
            return locale.format('%.1f KB', size/1024.)
        if size < 1024 * 1048576:
            return locale.format('%.1f MB', size / 1048576.)
        return locale.format('%.1f GB', size / float(1024 * 1048576)) 

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
            # since this might take a while, create separate threads and
            # display a progress dialog
            self.ui_start_info_collection_progress()

            if not self.report.has_key('Package'):
                icthread = threading.Thread(target=thread_collect_info,
                    args=(self.report, self.report_file, self.cur_package))
                icthread.start()
                while icthread.isAlive():
                    self.ui_pulse_info_collection_progress()
                    icthread.join(0.1)

            bpthread = threading.Thread(target=thread_check_bugpatterns,
                args=(self.report, bugpattern_baseurl))
            bpthread.start()
            while bpthread.isAlive():
                self.ui_pulse_info_collection_progress()
                bpthread.join(0.1)
            global thread_check_bugpatterns_result
            if isinstance(thread_check_bugpatterns_result, Exception):
                raise Exception, 'Exception in thread_check_bugpatterns():\n' + \
                    thread_check_bugpatterns_result.backtrace

            if thread_check_bugpatterns_result:
                self.report['BugPatternURL'] = thread_check_bugpatterns_result
            self.ui_stop_info_collection_progress()

            # check that we were able to determine package names
            if not self.report.has_key('SourcePackage') or not self.report.has_key('Package'):
                self.ui_error_message(_('Invalid problem report'), 
                    _('Could not determine the package or source package name.'))
                self.ui_shutdown()
                sys.exit(1)

    def open_url(url):
        '''Open the given URL in a new browser window.
        
        Display an error dialog if everything fails.'''

        # figure out appropriate web browser
        try:
            subprocess.call(['kfmclient', 'openURL', url])
        except OSError:
            try:
                if subprocess.call(['firefox', '-remote', 'openURL(%s, new-window)' % url]) != 0:
                    raise OSError, 'firefox -remote failed'
            except OSError:
                try:
                    webbrowser.open(url, new=True, autoraise=True)
                except Exception, e:
                    self.ui_error_message(_('Could not start web browser'), str(e))
                    self.ui_shutdown()
                    sys.exit(1)

    def file_report(self):
        '''Upload the current report to the tracking system and guide the user
        through its user interface.'''

        if self.report.has_key('SourcePackage'):
            self.open_url('https://launchpad.net/distros/ubuntu/+source/%s/+filebug' % self.report['SourcePackage'])
        else:
            self.open_url('https://launchpad.net/distros/ubuntu/+filebug')

    def load_report(self, path):
        '''Load report from given path and do some consistency checks.

        This might issue an error message and return False if the report cannot
        be processed, otherwise self.report is initialized and True is
        returned.'''

        try:
            self.report = apport.Report()
            self.report.load(open(path))
        except MemoryError:
            self.report = None
            self.ui_error_message(_('Memory exhaustion'), 
                _('Your system does not have enough memory to process this crash report.'))
            return False
        except (TypeError, ValueError):
            self.report = None
            self.ui_error_message(_('Invalid problem report'),
                _('This problem report is damaged and cannot be processed.'))
            return False

        if self.report.has_key('Package'):
            self.cur_package = self.report['Package'].split()[0]
        else:
            self.cur_package = apport.fileutils.find_file_package(self.report.get('ExecutablePath', ''))
        if not self.cur_package:
            self.report = None
            self.ui_info_message(_('Invalid problem report'),
                _('This problem report does not apply to a packaged program.'))
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

    def ui_present_crash(self, desktopfile):
        '''Inform that a crash has happened for self.report and
        self.cur_package and ask about an action.

        If the package can be mapped to a desktop file, this is passed as an
        argument; this can be used for enhancing strings, etc. 
        
        Return the action: ignore the crash ('cancel'), restart the crashed
        application ('restart'), or report a bug about the crash ('report').'''

        raise Exception, 'this function must be overridden by subclasses'

    def ui_present_report_details(self):
        '''Show details of the bug report and choose between sending a complete
        or reduced report.

        This function can use the get_complete_size() and get_reduced_size()
        methods to determine the respective size of the data to send, and
        format_filesize() to convert it to a humanly readable form.

        Return the action: send full report ('full'), send reduced report
        ('reduced'), or do not send anything ('cancel').'''

        raise Exception, 'this function must be overridden by subclasses'

    def ui_info_message(self, title, text):
        '''Show an information message box with given title and text.'''

        raise Exception, 'this function must be overridden by subclasses'

    def ui_error_message(self, title, text):
        '''Show an error message box with given title and text.'''

        raise Exception, 'this function must be overridden by subclasses'
        
    def ui_start_info_collection_progress(self):
        '''Open a window with an indefinite progress bar, telling the user to
        wait while debug information is being collected.'''

        raise Exception, 'this function must be overridden by subclasses'

    def ui_pulse_info_collection_progress(self):
        '''Advance the progress bar in the debug data collection progress
        window.
        
        This function is called every 100 ms.'''

        raise Exception, 'this function must be overridden by subclasses'

    def ui_stop_info_collection_progress(self):
        '''Close debug data collection progress window.'''

        raise Exception, 'this function must be overridden by subclasses'

    def ui_shutdown(self):
        '''This is called right before terminating the program and can be used
        for cleaning up.'''
        
        pass

#
# Test suite
#

if  __name__ == '__main__':
    import unittest, tempfile, shutil, signal

    class _TestSuiteUserInterface(UserInterface):
        '''Concrete UserInterface suitable for automatic testing.'''

        def __init__(self):
            UserInterface.__init__(self)

            # state of info collection progress dialog
            self.ic_progress_active = False
            self.ic_progress_pulses = 0 # count the pulses

            # these store the choices the ui_present_* calls do
            self.present_crash_response = None
            self.present_details_response = None

            self.opened_url = None

            self.clear_msg()

        def clear_msg(self):
            # last message box
            self.msg_title = None
            self.msg_text = None
            self.msg_severity = None # 'warning' or 'error'

        def ui_present_crash(self, desktopfile):
            return self.present_crash_response

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

        def open_url(self, url):
            self.opened_url = url

    class _UserInterfaceTest(unittest.TestCase):
        def setUp(self):
            self.orig_report_dir = apport.fileutils.report_dir
            apport.fileutils.report_dir = tempfile.mkdtemp()
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
            self.ui = None
            self.report_file.close()

        def test_format_filesize(self):
            '''Test format_filesize().'''

            self.assertEqual(self.ui.format_filesize(0), '0.0 KB')
            self.assertEqual(self.ui.format_filesize(2048), '2.0 KB')
            self.assertEqual(self.ui.format_filesize(2560), '2.5 KB')
            self.assertEqual(self.ui.format_filesize(1000000), '976.6 KB')
            self.assertEqual(self.ui.format_filesize(1048576), '1.0 MB')
            self.assertEqual(self.ui.format_filesize(2.7*1048576), '2.7 MB')
            self.assertEqual(self.ui.format_filesize(1024*1048576), '1.0 GB')
            self.assertEqual(self.ui.format_filesize(2560*1048576), '2.5 GB')

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

        def test_run_report_bug_distro(self):
            '''Test run_report_bug() for a general distro bug.'''

            self.ui.run_report_bug()
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertNotEqual(self.ui.opened_url, None)

            self.assert_(set(['Date', 'Uname', 'DistroRelease', 'ProblemType']).issubset(
                set(self.ui.report.keys())), 'report has required fields')

        def test_run_report_bug_package(self):
            '''Test run_report_bug() for a package.'''

            sys.argv = ['ui-test', '-f', '-p', 'bash']
            self.ui = _TestSuiteUserInterface()
            self.ui.run_argv()

            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertNotEqual(self.ui.opened_url, None)

            self.assert_(self.ui.ic_progress_pulses > 0)
            self.assertEqual(self.ui.report['SourcePackage'], 'bash')
            self.assert_('Dependencies' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Bug')

        def test_run_report_bug_pid(self):
            '''Test run_report_bug() for a pid.'''

            # fork a test process
            pid = os.fork()
            if pid == 0:
                os.execv('/bin/sleep', ['sleep', '10000'])
                assert False, 'Could not execute /bin/sleep'

            time.sleep(0.5)

            # report a bug on cat process
            sys.argv = ['ui-test', '-f', '-P', str(pid)]
            self.ui = _TestSuiteUserInterface()
            self.ui.run_argv()

            # kill test process
            os.kill(pid, signal.SIGKILL)

            self.assert_('SourcePackage' in self.ui.report.keys())
            self.assert_('Dependencies' in self.ui.report.keys())
            self.assert_('ProcMaps' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ExecutablePath'], '/bin/sleep')
            self.assertEqual(self.ui.report['ProcCmdline'], 'sleep 10000')
            self.assertEqual(self.ui.report['ProblemType'], 'Bug')

            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertNotEqual(self.ui.opened_url, None)
            self.assert_(self.ui.ic_progress_pulses > 0)

        def test_run_crash(self):
            '''Test run_crash().'''

            # create a test executable
            test_executable = '/bin/cat'
            assert os.access(test_executable, os.X_OK), test_executable + ' is not executable'
            pid = os.fork()
            if pid == 0:
                os.setsid()
                os.execv(test_executable, [test_executable])
                assert False, 'Could not execute ' + test_executable
    
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
            r.add_proc_info(pid)
            r.add_user_info()

            # kill test executable
            os.kill(pid, signal.SIGKILL)

            # write crash report
            report_file = os.path.join(apport.fileutils.report_dir, 'test.crash')

            # cancel crash notification dialog
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_crash_response = 'cancel'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertEqual(self.ui.ic_progress_pulses, 0)

            # report in crash notification dialog, cancel details report
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_crash_response = 'report'
            self.ui.present_details_response = 'cancel'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertEqual(self.ui.opened_url, None)
            self.assertNotEqual(self.ui.ic_progress_pulses, 0)

            # report in crash notification dialog, send full report
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_crash_response = 'report'
            self.ui.present_details_response = 'full'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertNotEqual(self.ui.opened_url, None)
            self.assertNotEqual(self.ui.ic_progress_pulses, 0)

            self.assert_('SourcePackage' in self.ui.report.keys())
            self.assert_('Dependencies' in self.ui.report.keys())
            self.assert_('Stacktrace' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Crash')
            self.assert_(len(self.ui.report['CoreDump']) > 10000)

            # report in crash notification dialog, send reduced report
            r.write(open(report_file, 'w'))
            self.ui = _TestSuiteUserInterface()
            self.ui.present_crash_response = 'report'
            self.ui.present_details_response = 'reduced'
            self.ui.run_crash(report_file)
            self.assertEqual(self.ui.msg_severity, None)
            self.assertEqual(self.ui.msg_title, None)
            self.assertNotEqual(self.ui.opened_url, None)
            self.assertNotEqual(self.ui.ic_progress_pulses, 0)

            self.assert_('SourcePackage' in self.ui.report.keys())
            self.assert_('Dependencies' in self.ui.report.keys())
            self.assert_('Stacktrace' in self.ui.report.keys())
            self.assertEqual(self.ui.report['ProblemType'], 'Crash')
            self.assert_(not self.ui.report.has_key('CoreDump'))

    unittest.main()

