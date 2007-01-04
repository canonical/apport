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

import subprocess, tempfile, os.path, urllib, re, pwd, grp, os

import xml.dom, xml.dom.minidom
from xml.parsers.expat import ExpatError

import warnings
warnings.filterwarnings("ignore", "apt API not stable yet", FutureWarning)
import apt

from problem_report import ProblemReport
import fileutils

#
# helper functions
#

def _transitive_dependencies(package, depends_set, cache):
    '''Recursively add dependencies of package to depends_set, using the given
    apt cache.'''

    try:
        cur_ver = cache[package]._pkg.CurrentVer
    except (AttributeError, KeyError):
        return
    if not cur_ver:
        return
    for p in cur_ver.DependsList.get('Depends', []) + cur_ver.DependsList.get('PreDepends', []):
        name = p[0].TargetPkg.Name
        if not name in depends_set:
            depends_set.add(name)
            _transitive_dependencies(name, depends_set, cache)

def _read_file(f):
    '''Try to read given file and return its contents, or return a textual
    error if it failed.'''

    try:
        return open(f).read().strip()
    except (OSError, IOError), e:
        return 'Error: ' + str(e)

def _command_output(command, input = None, stderr = subprocess.STDOUT):
    '''Try to execute given command (array) and return its stdout, or return
    a textual error if it failed.'''

    try:
       sp = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr, close_fds=True)
    except OSError, e:
       error_log('_command_output Popen(%s): %s' % (str(command), str(e)))
       return 'Error: ' + str(e)

    out = sp.communicate(input)[0]
    if sp.returncode == 0:
       return out
    else:
       error_log('_command_output %s failed with exit code %i: %s' % (
           str(command), sp.returncode, out))
       return 'Error: command %s failed with exit code %i: %s' % (
           str(command), sp.returncode, out)

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

        sumfile = '/var/lib/dpkg/info/%s.md5sums' % package
        if not os.path.exists(sumfile):
            return ''
        mod = fileutils.check_files_md5(sumfile)
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
        - Dependencies: package names and versions of all dependencies and
          pre-dependencies; this also checks if the files are unmodified and
          appends a list of all modified files'''

        if not package:
            package = fileutils.find_file_package(self['ExecutablePath'])
            if not package:
                return

        cache = apt.Cache()

        self['Package'] = '%s %s%s' % (package, cache[package].installedVersion, self._pkg_modified_suffix(package))
        self['SourcePackage'] = cache[package].sourcePackageName

        # get set of all transitive dependencies
        dependencies = set([])
        _transitive_dependencies(package, dependencies, cache)

        # get dependency versions
        self['Dependencies'] = ''
        for dep in dependencies:
            try:
                cur_ver = cache[dep]._pkg.CurrentVer
            except (KeyError, AttributeError):
                continue
            if not cur_ver:
                # can happen with uninstalled alternate dependencies
                continue
            if self['Dependencies']:
                self['Dependencies'] += '\n'
            self['Dependencies'] += '%s %s%s' % (dep, cur_ver.VerStr, self._pkg_modified_suffix(dep))

    def add_os_info(self):
        '''Add operating system information.

        This adds:
        - DistroRelease: lsb_release -sir output
        - Uname: uname -a output'''

        p = subprocess.Popen(['lsb_release', '-sir'], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, close_fds=True)
        self['DistroRelease'] = p.communicate()[0].strip().replace('\n', ' ')

        p = subprocess.Popen(['uname', '-a'], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, close_fds=True)
        self['Uname'] = p.communicate()[0].strip()

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
        if name == os.path.basename(self['ExecutablePath']):
            return

        cmdargs = self['ProcCmdline'].split('\0', 2)
        bindirs = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/']

        argvexes = filter(lambda p: os.access(p, os.R_OK), [p+cmdargs[0] for p in bindirs])
        if argvexes and os.path.basename(cmdargs[0]) == name:
            self['InterpreterPath'] = self['ExecutablePath']
            self['ExecutablePath'] = argvexes[0]
            return

        if len(cmdargs) >= 2:
            # ensure that cmdargs[1] is an absolute path 
            if cmdargs[1].startswith('.') and self.has_key('ProcCwd'):
                cmdargs[1] = os.path.join(self['ProcCwd'], cmdargs[1])
            if os.path.basename(cmdargs[0]) != name and os.access(cmdargs[1], os.R_OK):
                self['InterpreterPath'] = self['ExecutablePath']
                self['ExecutablePath'] = os.path.realpath(cmdargs[1])

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
            self['ExecutablePath'] = os.readlink('/proc/' + pid + '/exe')
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
        self['ProcMaps'] = _read_file('/proc/' + pid + '/maps')

        # check if we have an interpreted program
        self._check_interpreted()

        # make ProcCmdline ASCII friendly, do shell escaping
        self['ProcCmdline'] = self['ProcCmdline'].replace('\\', '\\\\').replace(' ', '\\ ').replace('\0', ' ')

    def add_gdb_info(self, debugdir=None):
        '''Add information from gdb.

        This requires that the report has a CoreDump (file ref) and an
        ExecutablePath. This adds the following fields:
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
                           'Disassembly': 'disassemble $pc $pc+32',
                           'Stacktrace': 'bt full',
                           'ThreadStacktrace': 'thread apply all bt full',
                          }

            command = ['gdb', '--batch']
            if debugdir:
                command += ['--ex', 'set debug-file-directory ' + debugdir]
            command += ['--ex', 'file ' + self.get('InterpreterPath',
                self['ExecutablePath']), '--ex', 'core-file ' + core]
	    value_keys = []
            for name, cmd in gdb_reports.iteritems():
		value_keys.append(name)
		# append the actual command and something that acts as a separator
		command += ['--ex', cmd, '--ex', 'p -99']
	    # remove the very last separator
	    command.pop()
	    command.pop()

	    # call gdb
	    out = _command_output(command, stderr=open('/dev/null')).replace(
		'(no debugging symbols found)\n','').replace(
		'No symbol table info available.\n','')

	    # split the output into the various fields
	    part_re = re.compile('^\$\d+\s*=\s*-99$', re.MULTILINE)
	    for part in part_re.split(out):
		self[value_keys.pop(0)] = part.replace('\n\n', '\n.\n').strip()
        finally:
            if unlink_core:
                os.unlink(core)

        # StacktraceTop
        toptrace = [''] * 5
        bt_fn_re = re.compile('^#(\d+)\s+0x(?:\w+)\s+in\s+(.*)$')
        for line in self['Stacktrace'].splitlines():
            m = bt_fn_re.match(line)
            if m:
                depth = int(m.group(1))
                if depth < len(toptrace):
                    toptrace[depth] = m.group(2)
        self['StacktraceTop'] = '\n'.join(toptrace)

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
        except IOError:
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


#
# Unit test
#

import unittest, shutil, signal

class _ApportReportTest(unittest.TestCase):
    def test_add_package_info(self):
        '''Test add_package_info() behaviour.'''

        # determine bash version
        p = subprocess.Popen('dpkg -s bash | grep ^Version: | cut -f2 -d\ ',
            shell=True, stdout=subprocess.PIPE)
        bashversion = p.communicate()[0]
        assert p.returncode == 0
        assert bashversion

        # determine libc version
        p = subprocess.Popen('dpkg -s libc6 | grep ^Version: | cut -f2 -d\ ',
            shell=True, stdout=subprocess.PIPE)
        libcversion = p.communicate()[0]
        assert p.returncode == 0
        assert libcversion

        pr = Report()
        self.assertRaises(KeyError, pr.add_package_info, 'nonexistant_package')

        pr.add_package_info('bash')
        self.assertEqual(pr['Package'], 'bash ' + bashversion.strip())
        self.assertEqual(pr['SourcePackage'], 'bash')
        self.assert_(pr['Dependencies'].find('libc6 ' + libcversion) >= 0)

        # test without specifying a package, but with ExecutablePath
        pr = Report()
        self.assertRaises(KeyError, pr.add_package_info)
        pr['ExecutablePath'] = '/bin/bash'
        pr.add_package_info()
        self.assertEqual(pr['Package'], 'bash ' + bashversion.strip())
        self.assertEqual(pr['SourcePackage'], 'bash')
        self.assert_(pr['Dependencies'].find('libc6 ' + libcversion) >= 0)

        pr = Report()
        pr['ExecutablePath'] = '/nonexisting'
        pr.add_package_info()
        self.assert_(not pr.has_key('Package'))

    def test_add_os_info(self):
        '''Test add_os_info() behaviour.'''

        pr = Report()
        pr.add_os_info()
        self.assert_(pr['Uname'].startswith('Linux'))
        self.assert_(type(pr['DistroRelease']) == type(''))

    def test_add_user_info(self):
        '''Test add_user_info behaviour.'''

        pr = Report()
        pr.add_user_info()
        self.assert_(pr.has_key('UserGroups'))

        # double-check that user group names are removed
        for g in pr['UserGroups'].split():
            self.assert_(grp.getgrnam(g).gr_gid < 1000)
        self.assert_(grp.getgrgid(os.getgid()).gr_name not in pr['UserGroups'])

    def test_add_proc_info(self):
        '''Test add_proc_info() behaviour.'''

        # set test environment
        assert os.environ.has_key('LANG'), 'please set $LANG for this test'
        assert os.environ.has_key('USER'), 'please set $USER for this test'
        assert os.environ.has_key('PWD'), '$PWD is not set'

        # check without additional safe environment variables
        pr = Report()
        pr.add_proc_info()
        self.assert_(set(['ProcEnviron', 'ProcMaps', 'ProcCmdline',
            'ProcMaps']).issubset(set(pr.keys())), 'report has required fields')
        self.assert_(pr['ProcEnviron'].find('LANG='+os.environ['LANG']) >= 0)
        self.assert_(pr['ProcEnviron'].find('USER') < 0)
        self.assert_(pr['ProcEnviron'].find('PWD') < 0)

        # check with one additional safe environment variable
        pr = Report()
        pr.add_proc_info(extraenv=['PWD'])
        self.assert_(pr['ProcEnviron'].find('USER') < 0)
        self.assert_(pr['ProcEnviron'].find('PWD='+os.environ['PWD']) >= 0)

        # check process from other user
        assert os.getuid() != 0, 'please do not run this test as root for this check.'
        pr = Report()
        pr.add_proc_info(pid=1)
        self.assert_(pr['ProcStatus'].find('init') >= 0, pr['ProcStatus'])
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

        # check correct handling of interpreted executables: python 
        assert not os.path.exists('./testsuite-unpack'), 'Directory ./testsuite-unpack must not exist'
        p = subprocess.Popen(['./bin/apport-unpack', '-', 'testsuite-unpack'], stdin=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True)
        assert p.pid
        # wait until /proc/pid/cmdline exists
        while not open('/proc/%i/cmdline' % p.pid).read():
            time.sleep(0.1)
        pr = Report()
        pr.add_proc_info(pid=p.pid)
        p.communicate('\n')
        os.rmdir('testsuite-unpack')
        self.assertEqual(pr['ExecutablePath'], os.path.realpath('./bin/apport-unpack'))
        self.assert_(pr['InterpreterPath'].find('python') >= 0)

    def test_check_interpreted(self):
        '''Test _check_interpreted() behaviour.'''
        
        # standard ELF binary
        pr = Report()
        pr['ExecutablePath'] = '/usr/bin/gedit'
        pr['ProcStatus'] = 'Name:\tgedit'
        pr['ProcCmdline'] = 'gedit\0/tmp/foo.txt'
        pr._check_interpreted()
        self.assertEqual(pr['ExecutablePath'], '/usr/bin/gedit')
        self.failIf(pr.has_key('InterpreterPath'))

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

        # standard sh script (this is also the common mono scheme)
        pr = Report()
        pr['ExecutablePath'] = '/bin/dash'
        pr['ProcStatus'] = 'Name:\tzgrep'
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

    def test_add_gdb_info(self):
        '''Test add_gdb_info() behaviour with core dump file reference.'''

        pr = Report()
        # should not throw an exception for missing fields
        pr.add_gdb_info()

        # create a test executable
        test_executable = '/bin/cat'
        assert os.access(test_executable, os.X_OK), test_executable + ' is not executable'
        pid = os.fork()
        if pid == 0:
            os.setsid()
            os.execv(test_executable, [test_executable])
            assert False, 'Could not execute ' + test_executable

        # generate a core dump
        (fd, coredump) = tempfile.mkstemp()
        try:
            os.close(fd)
            assert subprocess.call(['gdb', '--batch', '--ex', 'generate-core-file '
                + coredump, test_executable, str(pid)], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE) == 0

            # verify that it's a proper ELF file
            assert subprocess.call(['readelf', '-n', coredump],
                stdout=subprocess.PIPE) == 0

            # kill test executable
            os.kill(pid, signal.SIGKILL)

            pr['ExecutablePath'] = test_executable
            pr['CoreDump'] = (coredump,)

            pr.add_gdb_info()
        finally:
            os.unlink(coredump)

        self.assert_(pr.has_key('Stacktrace'))
        self.assert_(pr.has_key('ThreadStacktrace'))
        self.assert_(pr.has_key('StacktraceTop'))
        self.assert_(pr.has_key('Registers'))
        self.assert_(pr['Stacktrace'].find('#0  0x') > 0)
        self.assert_(pr['Stacktrace'].find('(no debugging symbols found)') < 0)
        self.assert_(pr['Stacktrace'].find('No symbol table info available') < 0)
        self.assert_(pr['ThreadStacktrace'].find('#0  0x') > 0)
        self.assert_(pr['ThreadStacktrace'].find('Thread 1 (process %i)' % pid) > 0)
        self.assertEqual(len(pr['StacktraceTop'].splitlines()), 5)
        self.assert_(pr['StacktraceTop'].startswith('read ('))
        self.assert_(pr['Disassembly'].find('Dump of assembler code from 0x') >= 0)

    def test_add_gdb_info_load(self):
        '''Test add_gdb_info() behaviour with inline core dump.'''

        pr = Report()
        # should not throw an exception for missing fields
        pr.add_gdb_info()

        # create a test executable
        test_executable = '/bin/cat'
        assert os.access(test_executable, os.X_OK), test_executable + ' is not executable'
        pid = os.fork()
        if pid == 0:
            os.setsid()
            os.execv(test_executable, [test_executable])
            assert False, 'Could not execute ' + test_executable

        # generate a core dump
        (fd, coredump) = tempfile.mkstemp()
        try:
            os.close(fd)
            assert subprocess.call(['gdb', '--batch', '--ex', 'generate-core-file '
                + coredump, test_executable, str(pid)], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE) == 0

            # verify that it's a proper ELF file
            assert subprocess.call(['readelf', '-n', coredump],
                stdout=subprocess.PIPE) == 0

            # kill test executable
            os.kill(pid, signal.SIGKILL)

            pr['ExecutablePath'] = test_executable
            pr['CoreDump'] = (coredump,)
            rep = tempfile.NamedTemporaryFile()
            pr.write(rep)
            rep.flush()
        finally:
            os.unlink(coredump)

        pr = Report()
        pr.load(open(rep.name))
        pr.add_gdb_info()

        self.assert_(pr.has_key('Stacktrace'))
        self.assert_(pr.has_key('ThreadStacktrace'))
        self.assert_(pr.has_key('Registers'))
        self.assert_(pr['Stacktrace'].find('#0  0x') > 0)
        self.assert_(pr['Stacktrace'].find('(no debugging symbols found)') < 0)
        self.assert_(pr['ThreadStacktrace'].find('#0  0x') > 0)
        self.assert_(pr['ThreadStacktrace'].find('Thread 1 (process %i)' % pid) > 0)
        self.assert_(pr['Disassembly'].find('Dump of assembler code from 0x') >= 0)

    def test_add_gdb_info_script(self):
        '''Test add_gdb_info() behaviour with a script.'''

        pr = Report()
        # should not throw an exception for missing fields
        pr.add_gdb_info()

        # create a test executable
        test_executable = '/bin/zgrep'
        assert os.access(test_executable, os.X_OK), test_executable + ' is not executable'
        pid = os.fork()
        if pid == 0:
            os.setsid()
            os.execv(test_executable, [test_executable, 'x'])
            assert False, 'Could not execute ' + test_executable

        # generate a core dump
        (fd, coredump) = tempfile.mkstemp()
        try:
            os.close(fd)
            assert subprocess.call(['gdb', '--batch', '--ex', 'generate-core-file '
                + coredump, test_executable, str(pid)], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE) == 0

            # verify that it's a proper ELF file
            assert subprocess.call(['readelf', '-n', coredump],
                stdout=subprocess.PIPE) == 0

            # kill test executable
            os.kill(pid, signal.SIGKILL)

            pr['InterpreterPath'] = '/bin/sh'
            pr['ExecutablePath'] = test_executable
            pr['CoreDump'] = (coredump,)

            pr.add_gdb_info()
        finally:
            os.unlink(coredump)

        self.assert_(pr.has_key('Stacktrace'))
        self.assert_(pr.has_key('ThreadStacktrace'))
        self.assert_(pr.has_key('StacktraceTop'))
        self.assert_(pr.has_key('Registers'))
        self.assert_('from /lib/libc.so' in pr['Stacktrace'])

    def test_search_bug_patterns(self):
        '''Test search_bug_patterns() behaviour.'''

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

if __name__ == '__main__':
    unittest.main()
