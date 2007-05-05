'''Class for an apport report with some useful methods to collect standard
debug information.

Copyright (C) 2006 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import subprocess, tempfile, os.path, urllib, re, pwd, grp, os, sys
import fnmatch

import xml.dom, xml.dom.minidom
from xml.parsers.expat import ExpatError

from problem_report import ProblemReport
import fileutils
from packaging_impl import impl as packaging

_hook_dir = '/usr/share/apport/package-hooks/'

# path of the ignore file
_ignore_file = '~/.apport-ignore.xml'

# programs that we consider interpreters
interpreters = ['sh', 'bash', 'dash', 'csh', 'tcsh', 'python*',
    'ruby*', 'php', 'perl*', 'mono*', 'awk']

#
# helper functions
#

def _transitive_dependencies(package, depends_set):
    '''Recursively add dependencies of package to depends_set.'''

    try:
        cur_ver = packaging.get_version(package)
    except ValueError:
        return
    for d in packaging.get_dependencies(package):
        if not d in depends_set:
            depends_set.add(d)
            _transitive_dependencies(d, depends_set)

def _read_file(f):
    '''Try to read given file and return its contents, or return a textual
    error if it failed.'''

    try:
        return open(f).read().strip()
    except (OSError, IOError), e:
        return 'Error: ' + str(e)

def _read_maps(pid):
    '''
    Since /proc/$pid/maps may become unreadable unless we are
    ptracing the process, detect this, and attempt to attach/detach
    '''

    maps = 'Error: unable to read /proc maps file'
    try:
        maps = file('/proc/%d/maps' % pid).read().strip()
    except (OSError,IOError), e:
        try:
            import ctypes, ctypes.util
            libc = ctypes.CDLL(ctypes.util.find_library("c"))
            # PT_ATTACH
            libc.ptrace(16, pid, 0, 0)
            maps = _read_file('/proc/%d/maps' % pid)
            # PT_DETACH
            libc.ptrace(17, pid, 0, 0)
        except (OSError, IOError, ImportError), e:
            return 'Error: ' + str(e)
    return maps

def _command_output(command, input = None, stderr = subprocess.STDOUT):
    '''Try to execute given command (array) and return its stdout, or return
    a textual error if it failed.'''

    sp = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr, close_fds=True)

    (out, err) = sp.communicate(input)
    if sp.returncode == 0:
        return out
    else:
       raise OSError, 'Error: command %s failed with exit code %i: %s' % (
           str(command), sp.returncode, err)

def _check_bug_pattern(report, pattern):
    '''Check if given report matches the given bug pattern XML DOM node; return the
    bug URL on match, otherwise None.'''

    if not pattern.attributes.has_key('url'):
        return None

    for c in pattern.childNodes:
        # regular expression condition
        if c.nodeType == xml.dom.Node.ELEMENT_NODE and c.nodeName == 're' and \
            c.attributes.has_key('key'):
            key = c.attributes['key'].nodeValue
            if not report.has_key(key):
                return None
            c.normalize()
            if c.hasChildNodes() and \
                c.childNodes[0].nodeType == xml.dom.Node.TEXT_NODE:
                regexp = c.childNodes[0].nodeValue.encode('UTF-8')
                try:
                    if not re.search(regexp, report[key]):
                        return None
                except:
                    return None

    return pattern.attributes['url'].nodeValue.encode('UTF-8')

def _dom_remove_space(node):
    '''Recursively remove whitespace from given XML DOM node.'''

    for c in node.childNodes:
        if c.nodeType == xml.dom.Node.TEXT_NODE and c.nodeValue.strip() == '':
            c.unlink()
            node.removeChild(c)
        else:
            _dom_remove_space(c)

#
# Report class
#

class Report(ProblemReport):
    '''A problem report specific to apport (crash or bug).

    This class wraps a standard ProblemReport and adds methods for collecting
    standard debugging data.'''

    def __init__(self, type='Crash', date=None):
        '''Initialize a fresh problem report.

           date is the desired date/time string; if None (default), the current
           local time is used.
           '''

        ProblemReport.__init__(self, type, date)

    def _pkg_modified_suffix(self, package):
        '''Return a string suitable for appending to Package:/Dependencies:
        fields.

        If package has only unmodified files, return the empty string. If not,
        return ' [modified: ...]' with a list of modified files.'''

        mod = packaging.get_modified_files(package)
        if mod:
            return ' [modified: %s]' % ' '.join(mod)
        else:
            return ''

    def add_package_info(self, package = None):
        '''Add packaging information.

        If package is not given, the report must have ExecutablePath.
        This adds:
        - Package: package name and installed version
        - SourcePackage: source package name
        - PackageArchitecture: processor architecture this package was built
          for
        - Dependencies: package names and versions of all dependencies and
          pre-dependencies; this also checks if the files are unmodified and
          appends a list of all modified files'''

        if not package:
            package = fileutils.find_file_package(self['ExecutablePath'])
            if not package:
                return

        self['Package'] = '%s %s%s' % (package,
            packaging.get_version(package),
            self._pkg_modified_suffix(package))
        self['SourcePackage'] = packaging.get_source(package)
        self['PackageArchitecture'] = packaging.get_architecture(package)

        # get set of all transitive dependencies
        dependencies = set([])
        _transitive_dependencies(package, dependencies)

        # get dependency versions
        self['Dependencies'] = ''
        for dep in dependencies:
            try:
                v = packaging.get_version(dep)
            except ValueError:
                # can happen with uninstalled alternate dependencies
                continue

            if self['Dependencies']:
                self['Dependencies'] += '\n'
            self['Dependencies'] += '%s %s%s' % (dep, v,
                self._pkg_modified_suffix(dep))

    def add_os_info(self):
        '''Add operating system information.

        This adds:
        - DistroRelease: lsb_release -sir output
        - Architecture: system architecture in distro specific notation
        - Uname: uname -a output'''

        p = subprocess.Popen(['lsb_release', '-sir'], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, close_fds=True)
        self['DistroRelease'] = p.communicate()[0].strip().replace('\n', ' ')

        p = subprocess.Popen(['uname', '-a'], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, close_fds=True)
        self['Uname'] = p.communicate()[0].strip()
        self['Architecture'] = packaging.get_system_architecture()

    def add_user_info(self):
        '''Add information about the user.

        This adds:
        - UserGroups: system groups the user is in
        '''

        user = pwd.getpwuid(os.getuid()).pw_name
        groups = [name for name, p, gid, memb in grp.getgrall()
            if user in memb and gid < 1000]
        groups.sort()
        self['UserGroups'] = ' '.join(groups)

    def _check_interpreted(self):
        '''Check ExecutablePath, ProcStatus and ProcCmdline if the process is
        interpreted.'''

        if not self.has_key('ExecutablePath'):
            return

        exebasename = os.path.basename(self['ExecutablePath'])

        # check if we consider ExecutablePath an interpreter; we have to do
        # this, otherwise 'gedit /tmp/foo.txt' would be detected as interpreted
        # script as well
        if not filter(lambda i: fnmatch.fnmatch(exebasename, i), interpreters):
            return

        # first, determine process name
        name = None
        for l in self['ProcStatus'].splitlines():
            try:
                (k, v) = l.split('\t', 1)
            except ValueError:
                continue
            if k == 'Name:':
                name = v
                break
        if not name:
            return

        cmdargs = self['ProcCmdline'].split('\0')
        bindirs = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/']

        # filter out interpreter options
        while len(cmdargs) >= 2 and cmdargs[1].startswith('-'):
            del cmdargs[1]

        # catch scripts explicitly called with interpreter
        if len(cmdargs) >= 2:
            # ensure that cmdargs[1] is an absolute path
            if cmdargs[1].startswith('.') and self.has_key('ProcCwd'):
                cmdargs[1] = os.path.join(self['ProcCwd'], cmdargs[1])
            if os.access(cmdargs[1], os.R_OK):
                self['InterpreterPath'] = self['ExecutablePath']
                self['ExecutablePath'] = os.path.realpath(cmdargs[1])
                return

        # catch directly executed scripts
        if name != exebasename:
            argvexes = filter(lambda p: os.access(p, os.R_OK), [p+cmdargs[0] for p in bindirs])
            if argvexes and os.path.basename(os.path.realpath(argvexes[0])) == name:
                self['InterpreterPath'] = self['ExecutablePath']
                self['ExecutablePath'] = argvexes[0]
                return

    def add_proc_info(self, pid=None, extraenv=[]):
        '''Add /proc/pid information.

        If pid is not given, it defaults to the process' current pid.

        This adds the following fields:
        - ExecutablePath: /proc/pid/exe contents; if the crashed process is
          interpreted, this contains the script path instead
        - InterpreterPath: /proc/pid/exe contents if the crashed process is
          interpreted; otherwise this key does not exist
        - ProcEnviron: A subset of the process' environment (only some standard
          variables that do not disclose potentially sensitive information, plus
          the ones mentioned in extraenv)
        - ProcCmdline: /proc/pid/cmdline contents
        - ProcStatus: /proc/pid/status contents
        - ProcMaps: /proc/pid/maps contents'''

        safe_vars = ['SHELL', 'PATH', 'LANGUAGE', 'LANG', 'LC_CTYPE',
            'LC_COLLATE', 'LC_TIME', 'LC_NUMERIC', 'LC_MONETARY', 'LC_MESSAGES',
            'LC_PAPER', 'LC_NAME', 'LC_ADDRESS', 'LC_TELEPHONE', 'LC_MEASUREMENT',
            'LC_IDENTIFICATION', 'LOCPATH'] + extraenv

        if not pid:
            pid = os.getpid()
        pid = str(pid)

        try:
            self['ProcCwd'] = os.readlink('/proc/' + pid + '/cwd')
        except OSError:
            pass
        self['ProcEnviron'] = ''
        env = _read_file('/proc/'+ pid + '/environ').replace('\n', '\\n')
        if env.startswith('Error:'):
            self['ProcEnviron'] = env
        else:
            for l in env.split('\0'):
                if l.split('=', 1)[0] in safe_vars:
                    if self['ProcEnviron']:
                        self['ProcEnviron'] += '\n'
                    self['ProcEnviron'] += l
        self['ProcStatus'] = _read_file('/proc/' + pid + '/status')
        self['ProcCmdline'] = _read_file('/proc/' + pid + '/cmdline').rstrip('\0')
        self['ProcMaps'] = _read_maps(int(pid))
        self['ExecutablePath'] = os.readlink('/proc/' + pid + '/exe')
        if self['ExecutablePath'].startswith('/rofs/'):
            self['ExecutablePath'] = self['ExecutablePath'][5:]
        assert os.path.exists(self['ExecutablePath'])

        # check if we have an interpreted program
        self._check_interpreted()

        # make ProcCmdline ASCII friendly, do shell escaping
        self['ProcCmdline'] = self['ProcCmdline'].replace('\\', '\\\\').replace(' ', '\\ ').replace('\0', ' ')

    def add_gdb_info(self, debugdir=None):
        '''Add information from gdb.

        This requires that the report has a CoreDump (file ref) and an
        ExecutablePath. This adds the following fields:
        - Registers: Output of gdb's 'info registers' command
        - Disassembly: Output of gdb's 'x/16i $pc' command
        - Stacktrace: Output of gdb's 'bt full' command
        - ThreadStacktrace: Output of gdb's 'thread apply all bt full' command
        - StacktraceTop: simplified stacktrace (topmost 5 functions) for inline
          inclusion into bug reports and easier processing

        The optional debugdir can specify an alternative debug symbol root
        directory.
        '''

        if not self.has_key('CoreDump') or not self.has_key('ExecutablePath'):
            return

        unlink_core = False
        try:
            if hasattr(self['CoreDump'], 'find'):
                (fd, core) = tempfile.mkstemp()
                os.write(fd, self['CoreDump'])
                os.close(fd)
                unlink_core = True
            else:
                core = self['CoreDump'][0]

            gdb_reports = {
                           'Registers': 'info registers',
                           'Disassembly': 'x/16i $pc',
                           'Stacktrace': 'bt full',
                           'ThreadStacktrace': 'thread apply all bt full',
                          }

            command = ['gdb', '--batch']
            if debugdir:
                command += ['--ex', 'set debug-file-directory ' + debugdir]
            command += ['--ex', 'file ' + self.get('InterpreterPath',
                self['ExecutablePath']), '--ex', 'core-file ' + core]
            # limit maximum backtrace depth (to avoid looped stacks)
            command += ['--ex', 'set backtrace limit 2000']
            value_keys = []
            # append the actual commands and something that acts as a separator
            for name, cmd in gdb_reports.iteritems():
                value_keys.append(name)
                command += ['--ex', 'p -99', '--ex', cmd]

            # call gdb
            out = _command_output(command, stderr=open('/dev/null')).replace(
                '(no debugging symbols found)\n','').replace(
                'No symbol table info available.\n','')

            # split the output into the various fields
            part_re = re.compile('^\$\d+\s*=\s*-99$', re.MULTILINE)
            parts = part_re.split(out)
            # drop the gdb startup text prior to first separator
            parts.pop(0)
            for part in parts:
                self[value_keys.pop(0)] = part.replace('\n\n', '\n.\n').strip()
        finally:
            if unlink_core:
                os.unlink(core)

        # StacktraceTop
        if self.has_key('Stacktrace'):
            toptrace = [''] * 5
            bt_fn_re = re.compile('^#(\d+)\s+0x(?:\w+)\s+in\s+(.*)$')
            for line in self['Stacktrace'].splitlines():
                m = bt_fn_re.match(line)
                if m:
                    depth = int(m.group(1))
                    if depth < len(toptrace):
                        toptrace[depth] = m.group(2)
            self['StacktraceTop'] = '\n'.join(toptrace).strip()

    def add_hooks_info(self):
        '''Check for an existing hook script and run it to add additional
        package specific information.

        A hook script needs to be in _hook_dir/<Package>.py and has to
        contain a function 'add_info(report)' that takes and modifies a
        Report.'''

        symb = {}
        assert self.has_key('Package')
        try:
            execfile('%s/%s.py' % (_hook_dir, self['Package'].split()[0]), symb)
            symb['add_info'](self)
        except:
            pass

        if self.has_key('SourcePackage'):
            try:
                execfile('%s/source_%s.py' % (_hook_dir, self['SourcePackage'].split()[0]), symb)
                symb['add_info'](self)
            except:
                pass

    def search_bug_patterns(self, baseurl):
        '''Check bug patterns at baseurl/packagename.xml, return bug URL on match or
        None otherwise.

        The pattern file must be valid XML and has the following syntax:
        root element := <patterns>
        patterns := <pattern url="http://bug.url"> *
        pattern := <re key="report_key">regular expression*</re> +

        For example:
        <?xml version="1.0"?>
        <patterns>
            <pattern url="https://launchpad.net/bugs/1">
                <re key="Foo">ba.*r</re>
            </pattern>
            <pattern url="https://launchpad.net/bugs/2">
                <re key="Foo">write_(hello|goodbye)</re>
                <re key="Package">^\S* 1-2$</re> <!-- test for a particular version -->
            </pattern>
        </patterns>
        '''

        assert self.has_key('Package')
        package = self['Package'].split()[0]
        try:
            patterns = urllib.urlopen('%s/%s.xml' % (baseurl, package)).read()
        except:
            return None

        try:
            dom = xml.dom.minidom.parseString(patterns)
        except ExpatError:
            return None

        for pattern in dom.getElementsByTagName('pattern'):
            m = _check_bug_pattern(self, pattern)
            if m:
                return m

        return None

    def _get_ignore_dom(self):
        '''Read ignore list XML file and return a DOM tree, or an empty DOM
        tree if file does not exist.

        Raises ValueError if the file exists but is invalid XML.'''

        ifpath = os.path.expanduser(_ignore_file)
        if not os.access(ifpath, os.R_OK) or os.path.getsize(ifpath) == 0:
            # create a document from scratch
            dom = xml.dom.getDOMImplementation().createDocument(None, 'apport', None)
        else:
            try:
                dom = xml.dom.minidom.parse(ifpath)
            except ExpatError, e:
                raise ValueError, '%s has invalid format: %s' % (_ignore_file, str(e))

        # remove whitespace so that writing back the XML does not accumulate
        # whitespace
        dom.documentElement.normalize()
        _dom_remove_space(dom.documentElement)

        return dom

    def check_ignored(self):
        '''Check ~/.apport-ignore.xml (in the real UID's home) if the current
        report should not be presented to the user.

        This requires the ExecutablePath attribute. Function can throw a
        ValueError if the file has an invalid format.'''

        assert self.has_key('ExecutablePath')
        dom = self._get_ignore_dom()

        try:
            cur_mtime = float(os.stat(self['ExecutablePath']).st_mtime)
        except OSError:
            # if it does not exist any more, do nothing
            return False

        # search for existing entry and update it
        for ignore in dom.getElementsByTagName('ignore'):
            if ignore.getAttribute('program') == self['ExecutablePath']:
                if float(ignore.getAttribute('mtime')) >= cur_mtime:
                    return True

        return False

    def mark_ignore(self):
        '''Add a ignore list entry for this report to ~/.apport-ignore.xml, so
        that future reports for this ExecutablePath are not presented to the
        user any more.

        Function can throw a ValueError if the file already exists and has an
        invalid format.'''

        assert self.has_key('ExecutablePath')

        dom = self._get_ignore_dom()
        mtime = str(int(os.stat(self['ExecutablePath']).st_mtime))

        # search for existing entry and update it
        for ignore in dom.getElementsByTagName('ignore'):
            if ignore.getAttribute('program') == self['ExecutablePath']:
                ignore.setAttribute('mtime', mtime)
                break
        else:
            # none exists yet, create new ignore node if none exists yet
            e = dom.createElement('ignore')
            e.setAttribute('program', self['ExecutablePath'])
            e.setAttribute('mtime', mtime)
            dom.documentElement.appendChild(e)

        # write back file
        dom.writexml(open(os.path.expanduser(_ignore_file), 'w'),
            addindent='  ', newl='\n')

        dom.unlink()

#
# Unit test
#

import unittest, shutil, signal, time

class _ApportReportTest(unittest.TestCase):
    def test_add_package_info(self):
        '''Test add_package_info().'''

        # determine bash version
        bashversion = packaging.get_version('bash')
        libcversion = packaging.get_version('libc6')

        pr = Report()
        self.assertRaises(ValueError, pr.add_package_info, 'nonexistant_package')

        pr.add_package_info('bash')
        self.assertEqual(pr['Package'], 'bash ' + bashversion.strip())
        self.assertEqual(pr['SourcePackage'], 'bash')
        self.assert_('libc6 ' + libcversion in pr['Dependencies'])

        # test without specifying a package, but with ExecutablePath
        pr = Report()
        self.assertRaises(KeyError, pr.add_package_info)
        pr['ExecutablePath'] = '/bin/bash'
        pr.add_package_info()
        self.assertEqual(pr['Package'], 'bash ' + bashversion.strip())
        self.assertEqual(pr['SourcePackage'], 'bash')
        self.assert_('libc6 ' + libcversion in pr['Dependencies'])
        # check for stray empty lines
        self.assert_('\n\n' not in pr['Dependencies'])
        self.assert_(pr.has_key('PackageArchitecture'))

        pr = Report()
        pr['ExecutablePath'] = '/nonexisting'
        pr.add_package_info()
        self.assert_(not pr.has_key('Package'))

    def test_add_os_info(self):
        '''Test add_os_info().'''

        pr = Report()
        pr.add_os_info()
        self.assert_(pr['Uname'].startswith('Linux'))
        self.assert_(type(pr['DistroRelease']) == type(''))
        self.assert_(pr['Architecture'])

    def test_add_user_info(self):
        '''Test add_user_info().'''

        pr = Report()
        pr.add_user_info()
        self.assert_(pr.has_key('UserGroups'))

        # double-check that user group names are removed
        for g in pr['UserGroups'].split():
            self.assert_(grp.getgrnam(g).gr_gid < 1000)
        self.assert_(grp.getgrgid(os.getgid()).gr_name not in pr['UserGroups'])

    def test_add_proc_info(self):
        '''Test add_proc_info().'''

        # set test environment
        assert os.environ.has_key('LANG'), 'please set $LANG for this test'
        assert os.environ.has_key('USER'), 'please set $USER for this test'
        assert os.environ.has_key('PWD'), '$PWD is not set'

        # check without additional safe environment variables
        pr = Report()
        pr.add_proc_info()
        self.assert_(set(['ProcEnviron', 'ProcMaps', 'ProcCmdline',
            'ProcMaps']).issubset(set(pr.keys())), 'report has required fields')
        self.assert_('LANG='+os.environ['LANG'] in pr['ProcEnviron'])
        self.assert_('USER' not in pr['ProcEnviron'])
        self.assert_('PWD' not in pr['ProcEnviron'])

        # check with one additional safe environment variable
        pr = Report()
        pr.add_proc_info(extraenv=['PWD'])
        self.assert_('USER' not in pr['ProcEnviron'])
        self.assert_('PWD='+os.environ['PWD'] in pr['ProcEnviron'])

        # check process from other user
        assert os.getuid() != 0, 'please do not run this test as root for this check.'
        pr = Report()
        self.assertRaises(OSError, pr.add_proc_info, 1) # EPERM for init process
        self.assert_('init' in pr['ProcStatus'], pr['ProcStatus'])
        self.assert_(pr['ProcEnviron'].startswith('Error:'), pr['ProcEnviron'])
        self.assert_(not pr.has_key('InterpreterPath'))

        # check escaping of ProcCmdline
        p = subprocess.Popen(['cat', '/foo bar', '\\h', '\\ \\', '-'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True)
        assert p.pid
        # wait until /proc/pid/cmdline exists
        while not open('/proc/%i/cmdline' % p.pid).read():
            time.sleep(0.1)
        pr = Report()
        pr.add_proc_info(pid=p.pid)
        p.communicate('\n')
        self.assertEqual(pr['ProcCmdline'], 'cat /foo\ bar \\\\h \\\\\\ \\\\ -')
        self.assertEqual(pr['ExecutablePath'], '/bin/cat')
        self.assert_(not pr.has_key('InterpreterPath'))
        self.assertTrue('/bin/cat' in pr['ProcMaps'])
        self.assertTrue('[stack]' in pr['ProcMaps'])

        # check correct handling of executable symlinks
        assert os.path.islink('/bin/sh'), '/bin/sh needs to be a symlink for this test'
        p = subprocess.Popen(['sh'], stdin=subprocess.PIPE,
            close_fds=True)
        assert p.pid
        # wait until /proc/pid/cmdline exists
        while not open('/proc/%i/cmdline' % p.pid).read():
            time.sleep(0.1)
        pr = Report()
        pr.add_proc_info(pid=p.pid)
        p.communicate('exit\n')
        self.failIf(pr.has_key('InterpreterPath'), pr.get('InterpreterPath'))
        self.assertEqual(pr['ExecutablePath'], os.path.realpath('/bin/sh'))

        # check correct handling of interpreted executables: shell
        p = subprocess.Popen(['/bin/zgrep', 'foo'], stdin=subprocess.PIPE,
            close_fds=True)
        assert p.pid
        # wait until /proc/pid/cmdline exists
        while not open('/proc/%i/cmdline' % p.pid).read():
            time.sleep(0.1)
        pr = Report()
        pr.add_proc_info(pid=p.pid)
        p.communicate('\n')
        self.assertEqual(pr['ExecutablePath'], '/bin/zgrep')
        self.assertEqual(pr['InterpreterPath'], os.path.realpath('/bin/sh'))
        self.assertTrue('[stack]' in pr['ProcMaps'])

        # check correct handling of interpreted executables: python
        (fd, testscript) = tempfile.mkstemp()
        os.write(fd, '''#!/usr/bin/python
import sys
sys.stdin.readline()
''')
        os.close(fd)
        os.chmod(testscript, 0755)
        p = subprocess.Popen([testscript], stdin=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True)
        assert p.pid
        # wait until /proc/pid/cmdline exists
        while not open('/proc/%i/cmdline' % p.pid).read():
            time.sleep(0.1)
        pr = Report()
        pr.add_proc_info(pid=p.pid)
        p.communicate('\n')
        os.unlink(testscript)
        self.assertEqual(pr['ExecutablePath'], testscript)
        self.assert_('python' in pr['InterpreterPath'])
        self.assertTrue('python' in pr['ProcMaps'])
        self.assertTrue('[stack]' in pr['ProcMaps'])

        # test process is gone, should complain about nonexisting PID
        self.assertRaises(OSError, pr.add_proc_info, p.pid)

    def test_check_interpreted(self):
        '''Test _check_interpreted().'''

        # standard ELF binary
        f = tempfile.NamedTemporaryFile()
        pr = Report()
        pr['ExecutablePath'] = '/usr/bin/gedit'
        pr['ProcStatus'] = 'Name:\tgedit'
        pr['ProcCmdline'] = 'gedit\0/' + f.name
        pr._check_interpreted()
        self.assertEqual(pr['ExecutablePath'], '/usr/bin/gedit')
        self.failIf(pr.has_key('InterpreterPath'))
        f.close()

        # bogus argv[0]
        pr = Report()
        pr['ExecutablePath'] = '/bin/dash'
        pr['ProcStatus'] = 'Name:\tznonexisting'
        pr['ProcCmdline'] = 'nonexisting\0/foo'
        pr._check_interpreted()
        self.assertEqual(pr['ExecutablePath'], '/bin/dash')
        self.failIf(pr.has_key('InterpreterPath'))

        # standard sh script
        pr = Report()
        pr['ExecutablePath'] = '/bin/dash'
        pr['ProcStatus'] = 'Name:\tzgrep'
        pr['ProcCmdline'] = '/bin/sh\0/bin/zgrep\0foo'
        pr._check_interpreted()
        self.assertEqual(pr['ExecutablePath'], '/bin/zgrep')
        self.assertEqual(pr['InterpreterPath'], '/bin/dash')

        # standard sh script when being called explicitly with interpreter
        pr = Report()
        pr['ExecutablePath'] = '/bin/dash'
        pr['ProcStatus'] = 'Name:\tdash'
        pr['ProcCmdline'] = '/bin/sh\0/bin/zgrep\0foo'
        pr._check_interpreted()
        self.assertEqual(pr['ExecutablePath'], '/bin/zgrep')
        self.assertEqual(pr['InterpreterPath'], '/bin/dash')

        # special case mono scheme: beagled-helper (use zgrep to make the test
        # suite work if mono or beagle are not installed)
        pr = Report()
        pr['ExecutablePath'] = '/usr/bin/mono'
        pr['ProcStatus'] = 'Name:\tzgrep'
        pr['ProcCmdline'] = 'zgrep\0--debug\0/bin/zgrep'
        pr._check_interpreted()
        self.assertEqual(pr['ExecutablePath'], '/bin/zgrep')
        self.assertEqual(pr['InterpreterPath'], '/usr/bin/mono')

        # special case mono scheme: banshee (use zgrep to make the test
        # suite work if mono or beagle are not installed)
        pr = Report()
        pr['ExecutablePath'] = '/usr/bin/mono'
        pr['ProcStatus'] = 'Name:\tzgrep'
        pr['ProcCmdline'] = 'zgrep\0/bin/zgrep'
        pr._check_interpreted()
        self.assertEqual(pr['ExecutablePath'], '/bin/zgrep')
        self.assertEqual(pr['InterpreterPath'], '/usr/bin/mono')

        # fail on files we shouldn't have access to when name!=argv[0]
        pr = Report()
        pr['ExecutablePath'] = '/usr/bin/python'
        pr['ProcStatus'] = 'Name:\tznonexisting'
        pr['ProcCmdline'] = 'python\0/etc/shadow'
        pr._check_interpreted()
        self.assertEqual(pr['ExecutablePath'], '/usr/bin/python')
        self.failIf(pr.has_key('InterpreterPath'))

        # succeed on files we should have access to when name!=argv[0]
        pr = Report()
        pr['ExecutablePath'] = '/usr/bin/python'
        pr['ProcStatus'] = 'Name:\tznonexisting'
        pr['ProcCmdline'] = 'python\0/etc/passwd'
        pr._check_interpreted()
        self.assertEqual(pr['InterpreterPath'], '/usr/bin/python')
        self.assertEqual(pr['ExecutablePath'], '/etc/passwd')

        # fail on files we shouldn't have access to when name==argv[0]
        pr = Report()
        pr['ExecutablePath'] = '/usr/bin/python'
        pr['ProcStatus'] = 'Name:\tshadow'
        pr['ProcCmdline'] = '../etc/shadow'
        pr._check_interpreted()
        self.assertEqual(pr['ExecutablePath'], '/usr/bin/python')
        self.failIf(pr.has_key('InterpreterPath'))

        # succeed on files we should have access to when name==argv[0]
        pr = Report()
        pr['ExecutablePath'] = '/usr/bin/python'
        pr['ProcStatus'] = 'Name:\tpasswd'
        pr['ProcCmdline'] = '../etc/passwd'
        pr._check_interpreted()
        self.assertEqual(pr['InterpreterPath'], '/usr/bin/python')
        self.assertEqual(pr['ExecutablePath'], '/bin/../etc/passwd')

        # interactive python process
        pr = Report()
        pr['ExecutablePath'] = '/usr/bin/python'
        pr['ProcStatus'] = 'Name:\tpython'
        pr['ProcCmdline'] = 'python'
        pr._check_interpreted()
        self.assertEqual(pr['ExecutablePath'], '/usr/bin/python')
        self.failIf(pr.has_key('InterpreterPath'))

        # python script (abuse /bin/bash since it must exist)
        pr = Report()
        pr['ExecutablePath'] = '/usr/bin/python'
        pr['ProcStatus'] = 'Name:\tbash'
        pr['ProcCmdline'] = 'python\0/bin/bash'
        pr._check_interpreted()
        self.assertEqual(pr['InterpreterPath'], '/usr/bin/python')
        self.assertEqual(pr['ExecutablePath'], '/bin/bash')

        # python script with options (abuse /bin/bash since it must exist)
        pr = Report()
        pr['ExecutablePath'] = '/usr/bin/python'
        pr['ProcStatus'] = 'Name:\tbash'
        pr['ProcCmdline'] = 'python\0-OO\0/bin/bash'
        pr._check_interpreted()
        self.assertEqual(pr['InterpreterPath'], '/usr/bin/python')
        self.assertEqual(pr['ExecutablePath'], '/bin/bash')

    def _generate_sigsegv_report(self, file=None):
        '''Create a test executable which will die with a SIGSEGV, generate a
        core dump for it, create a problem report with those two arguments
        (ExecutablePath and CoreDump) and call add_gdb_info().

        If file is given, the report is written into it. Return the Report.'''

        workdir = None
        orig_cwd = os.getcwd()
        pr = Report()
        try:
            workdir = tempfile.mkdtemp()
            os.chdir(workdir)

            # create a test executable
            open('crash.c', 'w').write('''
int f(x) {
    int* p = 0; *p = x;
    return x+1;
}
int main() { return f(42); }
''')
            assert subprocess.call(['gcc', '-g', 'crash.c', '-o', 'crash']) == 0
            assert os.path.exists('crash')

            # call it through gdb and dump core
            subprocess.call(['gdb', '--batch', '--ex', 'run', '--ex',
                'generate-core-file core', './crash'], stdout=subprocess.PIPE)
            assert os.path.exists('core')
            assert subprocess.call(['readelf', '-n', 'core'],
                stdout=subprocess.PIPE) == 0

            pr['ExecutablePath'] = os.path.join(workdir, 'crash')
            pr['CoreDump'] = (os.path.join(workdir, 'core'),)

            pr.add_gdb_info()
            if file:
                pr.write(file)
                file.flush()
        finally:
            os.chdir(orig_cwd)
            if workdir:
                shutil.rmtree(workdir)

        return pr

    def _validate_gdb_fields(self,pr):
        self.assert_(pr.has_key('Stacktrace'))
        self.assert_(pr.has_key('ThreadStacktrace'))
        self.assert_(pr.has_key('StacktraceTop'))
        self.assert_(pr.has_key('Registers'))
        self.assert_(pr.has_key('Disassembly'))
        self.assert_('(no debugging symbols found)' not in pr['Stacktrace'])
        self.assert_('Core was generated by' not in pr['Stacktrace'], pr['Stacktrace'])
        self.assert_(not re.match(r"(?s)(^|.*\n)#0  [^\n]+\n#0  ",
                                  pr['Stacktrace']))
        self.assert_('#0  0x' in pr['Stacktrace'])
        self.assert_('#1  0x' in pr['Stacktrace'])
        self.assert_('#0  0x' in pr['ThreadStacktrace'])
        self.assert_('#1  0x' in pr['ThreadStacktrace'])
        self.assert_('Thread 1 (process' in pr['ThreadStacktrace'])
        self.assert_(len(pr['StacktraceTop'].splitlines()) <= 5)

    def test_add_gdb_info(self):
        '''Test add_gdb_info() with core dump file reference.'''

        pr = Report()
        # should not throw an exception for missing fields
        pr.add_gdb_info()

        pr = self._generate_sigsegv_report()
        self._validate_gdb_fields(pr)
        self.assertEqual(pr['StacktraceTop'], 'f (x=42) at crash.c:3\nmain () at crash.c:6')

    def test_add_gdb_info_load(self):
        '''Test add_gdb_info() with inline core dump.'''

        rep = tempfile.NamedTemporaryFile()
        self._generate_sigsegv_report(rep)
        rep.seek(0)

        pr = Report()
        pr.load(open(rep.name))
        pr.add_gdb_info()

        self._validate_gdb_fields(pr)

    def test_add_gdb_info_script(self):
        '''Test add_gdb_info() with a script.'''

        (fd, coredump) = tempfile.mkstemp()
        (fd2, script) = tempfile.mkstemp()
        try:
            os.close(fd)
            os.close(fd2)

            # create a test script which produces a core dump for us
            open(script, 'w').write('''#!/bin/sh
gdb --batch --ex 'generate-core-file %s' --pid $$ >/dev/null''' % coredump)
            os.chmod(script, 0755)

            # call script and verify that it gives us a proper ELF core dump
            assert subprocess.call([script]) == 0
            assert subprocess.call(['readelf', '-n', coredump],
                stdout=subprocess.PIPE) == 0

            pr = Report()
            pr['InterpreterPath'] = '/bin/sh'
            pr['ExecutablePath'] = script
            pr['CoreDump'] = (coredump,)
            pr.add_gdb_info()
        finally:
            os.unlink(coredump)
            os.unlink(script)

        self._validate_gdb_fields(pr)
        self.assert_('libc.so' in pr['Stacktrace'])

    def test_search_bug_patterns(self):
        '''Test search_bug_patterns().'''

        pdir = None
        try:
            pdir = tempfile.mkdtemp()

            # create some test patterns
            open(os.path.join(pdir, 'bash.xml'), 'w').write('''<?xml version="1.0"?>
<patterns>
    <pattern url="https://launchpad.net/bugs/1">
        <re key="Foo">ba.*r</re>
    </pattern>
    <pattern url="https://launchpad.net/bugs/2">
        <re key="Foo">write_(hello|goodbye)</re>
        <re key="Package">^\S* 1-2$</re>
    </pattern>
</patterns>''')

            open(os.path.join(pdir, 'coreutils.xml'), 'w').write('''<?xml version="1.0"?>
<patterns>
    <pattern url="https://launchpad.net/bugs/3">
        <re key="Bar">^1$</re>
    </pattern>
    <pattern url="https://launchpad.net/bugs/4">
        <re key="Bar">*</re> <!-- invalid RE -->
    </pattern>
</patterns>''')

            # invalid XML
            open(os.path.join(pdir, 'invalid.xml'), 'w').write('''<?xml version="1.0"?>
</patterns>''')

            # create some reports
            r_bash = Report()
            r_bash['Package'] = 'bash 1-2'
            r_bash['Foo'] = 'bazaar'

            r_coreutils = Report()
            r_coreutils['Package'] = 'coreutils 1'
            r_coreutils['Bar'] = '1'

            r_invalid = Report()
            r_invalid['Package'] = 'invalid 1'

            # positive match cases
            self.assertEqual(r_bash.search_bug_patterns(pdir), 'https://launchpad.net/bugs/1')
            r_bash['Foo'] = 'write_goodbye'
            self.assertEqual(r_bash.search_bug_patterns(pdir), 'https://launchpad.net/bugs/2')
            self.assertEqual(r_coreutils.search_bug_patterns(pdir), 'https://launchpad.net/bugs/3')

            # negative match cases
            r_bash['Package'] = 'bash 1-21'
            self.assertEqual(r_bash.search_bug_patterns(pdir), None,
                'does not match on wrong bash version')
            r_bash['Foo'] = 'zz'
            self.assertEqual(r_bash.search_bug_patterns(pdir), None,
                'does not match on wrong Foo value')
            r_coreutils['Bar'] = '11'
            self.assertEqual(r_coreutils.search_bug_patterns(pdir), None,
                'does not match on wrong Bar value')

            # various errors to check for robustness (no exceptions, just None
            # return value)
            del r_coreutils['Bar']
            self.assertEqual(r_coreutils.search_bug_patterns(pdir), None,
                'does not match on nonexisting key')
            self.assertEqual(r_invalid.search_bug_patterns(pdir), None,
                'gracefully handles invalid XML')
            r_coreutils['Package'] = 'other 2'
            self.assertEqual(r_coreutils.search_bug_patterns(pdir), None,
                'gracefully handles nonexisting package XML file')
            self.assertEqual(r_bash.search_bug_patterns('file:///nonexisting/directory/'), None,
                'gracefully handles nonexisting base path')
            self.assertEqual(r_bash.search_bug_patterns('http://security.ubuntu.com/'), None,
                'gracefully handles base path without bug patterns')
            self.assertEqual(r_bash.search_bug_patterns('http://nonexisting.domain/'), None,
                'gracefully handles nonexisting URL domain')
        finally:
            if pdir:
                shutil.rmtree(pdir)

    def test_add_hooks_info(self):
        '''Test add_hooks_info().'''

        global _hook_dir
        orig_hook_dir = _hook_dir
        _hook_dir = tempfile.mkdtemp()
        try:
            open(os.path.join(_hook_dir, 'foo.py'), 'w').write('''
def add_info(report):
    report['Field1'] = 'Field 1'
    report['Field2'] = 'Field 2\\nBla'
''')
            r = Report()
            self.assertRaises(AssertionError, r.add_hooks_info)

            r = Report()
            r['Package'] = 'bar'
            # should not throw any exceptions
            r.add_hooks_info()
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package']), 'report has required fields')

            r = Report()
            r['Package'] = 'baz 1.2-3'
            # should not throw any exceptions
            r.add_hooks_info()
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package']), 'report has required fields')

            r = Report()
            r['Package'] = 'foo'
            r.add_hooks_info()
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package', 'Field1', 'Field2']), 'report has required fields')
            self.assertEqual(r['Field1'], 'Field 1')
            self.assertEqual(r['Field2'], 'Field 2\nBla')

            r = Report()
            r['Package'] = 'foo 4.5-6'
            r.add_hooks_info()
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package', 'Field1', 'Field2']), 'report has required fields')
            self.assertEqual(r['Field1'], 'Field 1')
            self.assertEqual(r['Field2'], 'Field 2\nBla')

            # source package hook
            open(os.path.join(_hook_dir, 'source_foo.py'), 'w').write('''
def add_info(report):
    report['Field1'] = 'Field 1'
    report['Field2'] = 'Field 2\\nBla'
''')
            r = Report()
            r['SourcePackage'] = 'foo'
            r['Package'] = 'libfoo 3'
            r.add_hooks_info()
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package', 'SourcePackage', 'Field1', 'Field2']), 
                'report has required fields')
            self.assertEqual(r['Field1'], 'Field 1')
            self.assertEqual(r['Field2'], 'Field 2\nBla')

        finally:
            shutil.rmtree(_hook_dir)
            _hook_dir = orig_hook_dir

    def test_ignoring(self):
        '''Test mark_ignore() and check_ignored().'''

        global _ignore_file
        orig_ignore_file = _ignore_file
        workdir = tempfile.mkdtemp()
        _ignore_file = os.path.join(workdir, 'ignore.xml')
        try:
            open(os.path.join(workdir, 'bash'), 'w').write('bash')
            open(os.path.join(workdir, 'crap'), 'w').write('crap')

            bash_rep = Report()
            bash_rep['ExecutablePath'] = os.path.join(workdir, 'bash')
            crap_rep = Report()
            crap_rep['ExecutablePath'] = os.path.join(workdir, 'crap')
            # must be able to deal with executables that do not exist any more
            cp_rep = Report()
            cp_rep['ExecutablePath'] = os.path.join(workdir, 'cp')

            # no ignores initially
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)
            self.assertEqual(cp_rep.check_ignored(), False)

            # ignore crap now
            crap_rep.mark_ignore()
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), True)
            self.assertEqual(cp_rep.check_ignored(), False)

            # ignore bash now
            bash_rep.mark_ignore()
            self.assertEqual(bash_rep.check_ignored(), True)
            self.assertEqual(crap_rep.check_ignored(), True)
            self.assertEqual(cp_rep.check_ignored(), False)

            # poke crap so that it has a newer timestamp
            time.sleep(1)
            open(os.path.join(workdir, 'crap'), 'w').write('crapnew')
            self.assertEqual(bash_rep.check_ignored(), True)
            self.assertEqual(crap_rep.check_ignored(), False)
            self.assertEqual(cp_rep.check_ignored(), False)

            # do not complain about an empty ignore file
            open(_ignore_file, 'w').write('')
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)
            self.assertEqual(cp_rep.check_ignored(), False)
        finally:
            shutil.rmtree(workdir)
            _ignore_file = orig_ignore_file

if __name__ == '__main__':
    unittest.main()
