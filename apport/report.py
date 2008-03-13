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
import fnmatch, glob, atexit

import xml.dom, xml.dom.minidom
from xml.parsers.expat import ExpatError

from problem_report import ProblemReport
import fileutils
from packaging_impl import impl as packaging

_hook_dir = '/usr/share/apport/package-hooks/'
_common_hook_dir = '/usr/share/apport/general-hooks/'

# path of the ignore file
_ignore_file = '~/.apport-ignore.xml'

# system-wide blacklist
_blacklist_dir = '/etc/apport/blacklist.d'

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

def get_module_license(module):
    '''Return the license for a given kernel module.'''

    try:
        modinfo = subprocess.Popen(['/sbin/modinfo', module], stdout=subprocess.PIPE)
        out = modinfo.communicate()[0]
        if modinfo.returncode != 0:
            return None
    except OSError:
        return None
    for l in out.splitlines():
        fields = l.split(':', 1)
        if len(fields) < 2:
            continue
        if fields[0] == 'license':
            return fields[1].strip()

    return None

def nonfree_modules(module_list = '/proc/modules'):
    '''Check loaded modules and return a list of those which are not free.'''
    try:
        mods = [l.split()[0] for l in open(module_list)]
    except IOError:
        return []

    nonfree = []
    for m in mods:
        l = get_module_license(m)
        if l and not ('GPL' in l or 'BSD' in l or 'MPL' in l or 'MIT' in l):
            nonfree.append(m)

    return nonfree

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
        - Uname: uname -srm output
        - NonfreeKernelModules: loaded kernel modules which are not free (if
            there are none, this field will not be present)'''

        p = subprocess.Popen(['lsb_release', '-sir'], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, close_fds=True)
        self['DistroRelease'] = p.communicate()[0].strip().replace('\n', ' ')

        u = os.uname()
        self['Uname'] = '%s %s %s' % (u[0], u[2], u[4])
        self['Architecture'] = packaging.get_system_architecture()
        nm = nonfree_modules()
        if nm:
            self['NonfreeKernelModules'] = ' '.join(nonfree_modules())

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

        This requires that the report has a CoreDump and an
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
            elif hasattr(self['CoreDump'], 'gzipvalue'):
                (fd, core) = tempfile.mkstemp()
                os.close(fd)
                self['CoreDump'].write(open(core, 'w'))
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

            assert os.path.exists(self.get('InterpreterPath', self['ExecutablePath']))

            # call gdb
            try:
                out = _command_output(command, stderr=open('/dev/null')).replace(
                    '(no debugging symbols found)\n','').replace(
                    'No symbol table info available.\n','')
            except OSError:
                return

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

        if self.has_key('Stacktrace'):
            self._gen_stacktrace_top()

    def _gen_stacktrace_top(self):
        '''Build field StacktraceTop as the top five functions of Stacktrace. 

        Signal handler invocations and related functions are skipped since they
        are generally not useful for triaging and duplicate detection.'''
        
        unwind_functions = set(['g_logv', 'g_log', 'IA__g_log', 'IA__g_logv',
            'g_assert_warning', 'IA__g_assert_warning'])
        toptrace = [''] * 5
        depth = 0
        unwound = False
        unwinding = False
        bt_fn_re = re.compile('^#(\d+)\s+(?:0x(?:\w+)\s+in\s+(.*)|(<signal handler called>)\s*)$')

        for line in self['Stacktrace'].splitlines():
            m = bt_fn_re.match(line)
            if not m:
                continue

            if not unwound or unwinding:
                if m.group(2):
                    fn = m.group(2).split()[0].split('(')[0]
                else:
                    fn = None
                if m.group(3) or fn in unwind_functions:
                    unwinding = True
                    depth = 0
                    toptrace = [''] * 5
                    unwound = True
                    continue
                else:
                    unwinding = False

            if depth < len(toptrace):
                toptrace[depth] = m.group(2) or m.group(3)
                depth += 1
        self['StacktraceTop'] = '\n'.join(toptrace).strip()

    def add_hooks_info(self):
        '''Check for an existing hook script and run it to add additional
        package specific information.

        A hook script needs to be in _hook_dir/<Package>.py or in
        _common_hook_dir/*.py and has to contain a function 'add_info(report)'
        that takes and modifies a Report.'''

        symb = {}
        assert self.has_key('Package')

        # common hooks
        for hook in glob.glob(_common_hook_dir + '/*.py'):
            try:
                execfile(hook, symb)
                symb['add_info'](self)
            except:
                pass

        # binary package hook
        try:
            execfile('%s/%s.py' % (_hook_dir, self['Package'].split()[0]), symb)
            symb['add_info'](self)
        except:
            pass

        # source package hook
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
            <pattern url="http://bugtracker.net/bugs/1">
                <re key="Foo">ba.*r</re>
            </pattern>
            <pattern url="http://bugtracker.net/bugs/2">
                <re key="Foo">write_(hello|goodbye)</re>
                <re key="Package">^\S* 1-2$</re> <!-- test for a particular version -->
            </pattern>
        </patterns>
        '''

        # some distros might not want to support these
        if not baseurl:
            return

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
        '''Check ~/.apport-ignore.xml (in the real UID's home) and
        /etc/apport/blacklist.d/ if the current report should not be presented
        to the user.

        This requires the ExecutablePath attribute. Function can throw a
        ValueError if the file has an invalid format.'''

        assert self.has_key('ExecutablePath')

        # check blacklist
        try:
            for f in os.listdir(_blacklist_dir):
                try:
                    fd = open(os.path.join(_blacklist_dir, f))
                except IOError:
                    continue
                for line in fd:
                    if line.strip() == self['ExecutablePath']:
                        return True
        except OSError:
            pass

        dom = self._get_ignore_dom()

        try:
            cur_mtime = int(os.stat(self['ExecutablePath']).st_mtime)
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

    def has_useful_stacktrace(self):
        '''Check whether this report has a stacktrace that can be considered
        'useful'.

        The current heuristic is to consider it useless if it either is shorter
        than three lines and has any unknown function, or for longer traces, a
        minority of known functions.'''
        
        if not self.get('StacktraceTop'):
            return False
        
        unknown_fn = [f.startswith('??') for f in self['StacktraceTop'].splitlines()]

        if len(unknown_fn) < 3:
            return unknown_fn.count(True) == 0

        return unknown_fn.count(True) <= len(unknown_fn)/2.

    def standard_title(self):
        '''Create an appropriate title for a crash database entry.

        This contains the topmost function name from the stack trace and the
        signal (for signal crashes) or the Python exception (for unhandled
        Python exceptions).

        Return None if the report is not a crash or a default title could not
        be generated.'''

        # signal crash
        if self.has_key('Signal') and \
            self.has_key('ExecutablePath') and \
            self.has_key('StacktraceTop'):

            signal_names = {
                '4': 'SIGILL',
                '6': 'SIGABRT',
                '8': 'SIGFPE',
                '11': 'SIGSEGV',
                '13': 'SIGPIPE'
            }

            fn = ''
            for l in self['StacktraceTop'].splitlines():
                fname = l.split('(')[0].strip()
                if fname != '??':
                    fn = ' in %s()' % fname
                    break

            arch_mismatch = ''
            if self.has_key('Architecture') and \
                self.has_key('PackageArchitecture') and \
                self['Architecture'] != self['PackageArchitecture'] and \
                self['PackageArchitecture'] != 'all':
                arch_mismatch = ' [non-native %s package]' % self['PackageArchitecture']

            return '%s crashed with %s%s%s' % (
                os.path.basename(self['ExecutablePath']),
                signal_names.get(self.get('Signal'),
                    'signal ' + self.get('Signal')),
                fn, arch_mismatch
            )

        # Python exception
        if self.has_key('Traceback') and \
            self.has_key('ExecutablePath'):

            trace = self['Traceback'].splitlines()

            if len(trace) < 1:
                return None
            if len(trace) < 3:
                return '%s crashed with %s' % (
                    os.path.basename(self['ExecutablePath']),
                    trace[0])

            trace_re = re.compile('^\s*File.* in (.+)$')
            i = len(trace)-1
            function = 'unknown'
            while i >= 0:
                m = trace_re.match(trace[i])
                if m:
                    function = m.group(1)
                    break
                i -= 1

            return '%s crashed with %s in %s()' % (
                os.path.basename(self['ExecutablePath']),
                trace[-1].split(':')[0],
                function
            )

        # package problem
        if self.get('ProblemType') == 'Package' and \
            self.has_key('Package'):

            title = 'package %s failed to install/upgrade' % \
                self['Package']
            if self.get('ErrorMessage'):
                title += ': ' + self['ErrorMessage'].splitlines()[-1]

            return title

        return None

    def obsolete_packages(self):
        '''Check Package: and Dependencies: for obsolete packages and return a
        list of them.'''

        obsolete = []
        for l in (self['Package'] + '\n' + self.get('Dependencies', '')).splitlines():
            if not l:
                continue
            pkg, ver = l.split()[:2]
            avail = packaging.get_available_version(pkg)
            if ver != None and ver != 'None' and avail != None and \
                packaging.compare_versions(ver, avail) < 0:
                obsolete.append(pkg)
        return obsolete

    def crash_signature(self):
        '''Calculate a signature string for a crash suitable for identifying
        duplicates.

        For signal crashes this the concatenation of ExecutablePath, Signal
        number, and StacktraceTop function names, separated by a colon. If
        StacktraceTop has unknown functions or the report lacks any of those
        fields, return None.
        
        For Python crashes, this concatenates the ExecutablePath, exception
        name, and Traceback function names, again separated by a colon.'''

        if not self.has_key('ExecutablePath'):
            return None

        # signal crashes
        if self.has_key('StacktraceTop') and self.has_key('Signal'):
            sig = '%s:%s' % (self['ExecutablePath'], self['Signal'])
            bt_fn_re = re.compile('^(?:([\w:~]+).*|(<signal handler called>)\s*)$')

            for line in self['StacktraceTop'].splitlines():
                m = bt_fn_re.match(line)
                if m:
                    sig += ':' + (m.group(1) or m.group(2))
                else:
                    # this will also catch ??
                    return None
            return sig

        # Python crashes
        if self.has_key('Traceback'):
            trace = self['Traceback'].splitlines()

            sig = ''
            if len(trace) == 1:
                # sometimes, Python exceptions do not have file references
                m = re.match('(\w+): ', trace[0])
                if m:
                    return self['ExecutablePath'] + ':' + m.group(1)
                else:
                    return None
            elif len(trace) < 3:
                return None

            for l in trace:
                if l.startswith('  File'):
                    sig += ':' + l.split()[-1]

            return self['ExecutablePath'] + ':' + trace[-1].split(':')[0] + sig

        return None

    def anonymize(self):
        '''Remove user identifying strings from the report.

        This particularly removes the user name, host name, and IPs
        from attributes which contain data read from the environment, and
        removes the ProcCwd attribute completely.
        '''

        p = pwd.getpwuid(os.getuid())
        replacements = {
            p[0]: 'username',
            p[4]: 'User Name',
            p[5]: '/home/username',
            os.uname()[1]: 'hostname',
        }

        for s in p[4].split(','):
            s = s.strip()
            if len(s) > 2:
                replacements[s] = 'GECOS'

        try:
            del self['ProcCwd']
        except KeyError:
            pass

        for k in self:
            if k == 'CoreDump':
                continue
            for old, new in replacements.iteritems():
                self[k] = self[k].replace(old, new)

#
# Unit test
#

import unittest, shutil, signal, time
from cStringIO import StringIO

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
        self.assertEqual(pr['InterpreterPath'],
            os.path.realpath(open('/bin/zgrep').readline().strip()[2:]))
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
            atexit.register(shutil.rmtree, workdir)
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
    <pattern url="http://bugtracker.net/bugs/1">
        <re key="Foo">ba.*r</re>
    </pattern>
    <pattern url="http://bugtracker.net/bugs/2">
        <re key="Foo">write_(hello|goodbye)</re>
        <re key="Package">^\S* 1-2$</re>
    </pattern>
</patterns>''')

            open(os.path.join(pdir, 'coreutils.xml'), 'w').write('''<?xml version="1.0"?>
<patterns>
    <pattern url="http://bugtracker.net/bugs/3">
        <re key="Bar">^1$</re>
    </pattern>
    <pattern url="http://bugtracker.net/bugs/4">
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
            self.assertEqual(r_bash.search_bug_patterns(pdir), 'http://bugtracker.net/bugs/1')
            r_bash['Foo'] = 'write_goodbye'
            self.assertEqual(r_bash.search_bug_patterns(pdir), 'http://bugtracker.net/bugs/2')
            self.assertEqual(r_coreutils.search_bug_patterns(pdir), 'http://bugtracker.net/bugs/3')

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
            # existing host, but no bug patterns
            self.assertEqual(r_bash.search_bug_patterns('http://security.ubuntu.com/'), None,
                'gracefully handles base path without bug patterns')
            # nonexisting host
            self.assertEqual(r_bash.search_bug_patterns('http://nonexisting.domain/'), None,
                'gracefully handles nonexisting URL domain')
        finally:
            if pdir:
                shutil.rmtree(pdir)

    def test_add_hooks_info(self):
        '''Test add_hooks_info().'''

        global _hook_dir
        global _common_hook_dir
        orig_hook_dir = _hook_dir
        _hook_dir = tempfile.mkdtemp()
        orig_common_hook_dir = _common_hook_dir
        _common_hook_dir = tempfile.mkdtemp()
        try:
            open(os.path.join(_hook_dir, 'foo.py'), 'w').write('''
def add_info(report):
    report['Field1'] = 'Field 1'
    report['Field2'] = 'Field 2\\nBla'
''')

            open(os.path.join(_common_hook_dir, 'foo1.py'), 'w').write('''
def add_info(report):
    report['CommonField1'] = 'CommonField 1'
''')
            open(os.path.join(_common_hook_dir, 'foo2.py'), 'w').write('''
def add_info(report):
    report['CommonField2'] = 'CommonField 2'
''')

            # should only catch .py files
            open(os.path.join(_common_hook_dir, 'notme'), 'w').write('''
def add_info(report):
    report['BadField'] = 'XXX'
''')
            r = Report()
            self.assertRaises(AssertionError, r.add_hooks_info)

            r = Report()
            r['Package'] = 'bar'
            # should not throw any exceptions
            r.add_hooks_info()
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package', 'CommonField1', 'CommonField2']), 
                'report has required fields')

            r = Report()
            r['Package'] = 'baz 1.2-3'
            # should not throw any exceptions
            r.add_hooks_info()
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package', 'CommonField1', 'CommonField2']), 
                'report has required fields')

            r = Report()
            r['Package'] = 'foo'
            r.add_hooks_info()
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package', 'Field1', 'Field2', 'CommonField1',
                'CommonField2']), 'report has required fields')
            self.assertEqual(r['Field1'], 'Field 1')
            self.assertEqual(r['Field2'], 'Field 2\nBla')
            self.assertEqual(r['CommonField1'], 'CommonField 1')
            self.assertEqual(r['CommonField2'], 'CommonField 2')

            r = Report()
            r['Package'] = 'foo 4.5-6'
            r.add_hooks_info()
            self.assertEqual(set(r.keys()), set(['ProblemType', 'Date',
                'Package', 'Field1', 'Field2', 'CommonField1',
                'CommonField2']), 'report has required fields')
            self.assertEqual(r['Field1'], 'Field 1')
            self.assertEqual(r['Field2'], 'Field 2\nBla')
            self.assertEqual(r['CommonField1'], 'CommonField 1')
            self.assertEqual(r['CommonField2'], 'CommonField 2')

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
                'Package', 'SourcePackage', 'Field1', 'Field2', 'CommonField1',
                'CommonField2']), 'report has required fields')
            self.assertEqual(r['Field1'], 'Field 1')
            self.assertEqual(r['Field2'], 'Field 2\nBla')
            self.assertEqual(r['CommonField1'], 'CommonField 1')
            self.assertEqual(r['CommonField2'], 'CommonField 2')

        finally:
            shutil.rmtree(_hook_dir)
            shutil.rmtree(_common_hook_dir)
            _hook_dir = orig_hook_dir
            _common_hook_dir = orig_common_hook_dir

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

    def test_blacklisting(self):
        '''Test check_ignored() for system-wise blacklist.'''

        global _blacklist_dir
        global _ignore_file
        orig_blacklist_dir = _blacklist_dir
        _blacklist_dir = tempfile.mkdtemp()
        orig_ignore_file = _ignore_file
        _ignore_file = '/nonexistant'
        try:
            bash_rep = Report()
            bash_rep['ExecutablePath'] = '/bin/bash'
            crap_rep = Report()
            crap_rep['ExecutablePath'] = '/bin/crap'

            # no ignores initially
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)

            # should not stumble over comments
            open(os.path.join(_blacklist_dir, 'README'), 'w').write(
                '# Ignore file\n#/bin/bash\n')

            # no ignores on nonmatching paths
            open(os.path.join(_blacklist_dir, 'bl1'), 'w').write(
                '/bin/bas\n/bin/bashh\nbash\nbin/bash\n')
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), False)

            # ignore crap now
            open(os.path.join(_blacklist_dir, 'bl_2'), 'w').write(
                '/bin/crap\n')
            self.assertEqual(bash_rep.check_ignored(), False)
            self.assertEqual(crap_rep.check_ignored(), True)

            # ignore bash now
            open(os.path.join(_blacklist_dir, 'bl1'), 'a').write(
                '/bin/bash\n')
            self.assertEqual(bash_rep.check_ignored(), True)
            self.assertEqual(crap_rep.check_ignored(), True)
        finally:
            shutil.rmtree(_blacklist_dir)
            _blacklist_dir = orig_blacklist_dir
            _ignore_file = orig_ignore_file

    def test_has_useful_stacktrace(self):
        '''Test has_useful_stacktrace().'''

        r = Report()
        self.failIf(r.has_useful_stacktrace())

        r['StacktraceTop'] = ''
        self.failIf(r.has_useful_stacktrace())

        r['StacktraceTop'] = '?? ()'
        self.failIf(r.has_useful_stacktrace())

        r['StacktraceTop'] = '?? ()\n?? ()'
        self.failIf(r.has_useful_stacktrace())

        r['StacktraceTop'] = 'read () from /lib/libc.6.so\n?? ()'
        self.failIf(r.has_useful_stacktrace())

        r['StacktraceTop'] = 'read () from /lib/libc.6.so\n?? ()\n?? ()\n?? ()'
        self.failIf(r.has_useful_stacktrace())

        r['StacktraceTop'] = 'read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so'
        self.assert_(r.has_useful_stacktrace())

        r['StacktraceTop'] = 'read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so\n?? ()'
        self.assert_(r.has_useful_stacktrace())

        r['StacktraceTop'] = 'read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so\n?? ()\n?? ()'
        self.assert_(r.has_useful_stacktrace())

        r['StacktraceTop'] = 'read () from /lib/libc.6.so\n?? ()\nfoo (i=1) from /usr/lib/libfoo.so\n?? ()\n?? ()'
        self.failIf(r.has_useful_stacktrace())

    def test_standard_title(self):
        '''Test standard_title().'''

        report = Report()
        self.assertEqual(report.standard_title(), None)

        # named signal crash
        report['Signal'] = '11'
        report['ExecutablePath'] = '/bin/bash'
        report['StacktraceTop'] = '''foo()
bar(x=3)
baz()
'''
        self.assertEqual(report.standard_title(),
            'bash crashed with SIGSEGV in foo()')

        # unnamed signal crash
        report['Signal'] = '42'
        self.assertEqual(report.standard_title(),
            'bash crashed with signal 42 in foo()')

        # do not crash on empty StacktraceTop
        report['StacktraceTop'] = ''
        self.assertEqual(report.standard_title(),
            'bash crashed with signal 42')

        # do not create bug title with unknown function name
        report['StacktraceTop'] = '??()\nfoo()'
        self.assertEqual(report.standard_title(),
            'bash crashed with signal 42 in foo()')

        # if we do not know any function name, don't mention ??
        report['StacktraceTop'] = '??()\n??()'
        self.assertEqual(report.standard_title(),
            'bash crashed with signal 42')

        # Python crash
        report = Report()
        report['ExecutablePath'] = '/usr/share/apport/apport-gtk'
        report['Traceback'] = '''Traceback (most recent call last):
File "/usr/share/apport/apport-gtk", line 202, in <module>
app.run_argv()
File "/var/lib/python-support/python2.5/apport/ui.py", line 161, in run_argv
self.run_crashes()
File "/var/lib/python-support/python2.5/apport/ui.py", line 104, in run_crashes
self.run_crash(f)
File "/var/lib/python-support/python2.5/apport/ui.py", line 115, in run_crash
response = self.ui_present_crash(desktop_entry)
File "/usr/share/apport/apport-gtk", line 67, in ui_present_crash
subprocess.call(['pgrep', '-x',
NameError: global name 'subprocess' is not defined'''
        self.assertEqual(report.standard_title(),
            'apport-gtk crashed with NameError in ui_present_crash()')

        # slightly weird Python crash
        report = Report()
        report['ExecutablePath'] = '/usr/share/apport/apport-gtk'
        report['Traceback'] = '''TypeError: Cannot create a consistent method resolution
order (MRO) for bases GObject, CanvasGroupableIface, CanvasGroupable'''
        self.assertEqual(report.standard_title(),
            'apport-gtk crashed with TypeError: Cannot create a consistent method resolution')

        # Python crash with custom message
        report = Report()
        report['ExecutablePath'] = '/usr/share/apport/apport-gtk'
        report['Traceback'] = '''Traceback (most recent call last):
  File "/x/foo.py", line 242, in setup_chooser
    raise "Moo"
Moo'''

        self.assertEqual(report.standard_title(), 'apport-gtk crashed with Moo in setup_chooser()')

        # Python crash with custom message with newlines (LP #190947)
        report = Report()
        report['ExecutablePath'] = '/usr/share/apport/apport-gtk'
        report['Traceback'] = '''Traceback (most recent call last):
  File "/x/foo.py", line 242, in setup_chooser
    raise "\nKey: "+key+" isn't set.\nRestarting AWN usually solves this issue\n"
 
Key: /apps/avant-window-navigator/app/active_png isn't set.
Restarting AWN usually solves this issue'''

        t = report.standard_title()
        self.assert_(t.startswith('apport-gtk crashed with'))
        self.assert_(t.endswith('setup_chooser()'))

        # package install problem
        report = Report('Package')
        report['Package'] = 'bash'

        # no ErrorMessage
        self.assertEqual(report.standard_title(),
            'package bash failed to install/upgrade')

        # empty ErrorMessage
        report['ErrorMessage'] = ''
        self.assertEqual(report.standard_title(),
            'package bash failed to install/upgrade')

        # nonempty ErrorMessage
        report['ErrorMessage'] = 'botched\nnot found\n'
        self.assertEqual(report.standard_title(),
            'package bash failed to install/upgrade: not found')

        # matching package/system architectures
        report['Signal'] = '11'
        report['ExecutablePath'] = '/bin/bash'
        report['StacktraceTop'] = '''foo()
bar(x=3)
baz()
'''
        report['PackageArchitecture'] = 'amd64'
        report['Architecture'] = 'amd64'
        self.assertEqual(report.standard_title(),
            'bash crashed with SIGSEGV in foo()')

        # non-native package (on multiarch)
        report['PackageArchitecture'] = 'i386'
        self.assertEqual(report.standard_title(),
            'bash crashed with SIGSEGV in foo() [non-native i386 package]')

        # Arch: all package (matches every system architecture)
        report['PackageArchitecture'] = 'all'
        self.assertEqual(report.standard_title(),
            'bash crashed with SIGSEGV in foo()')

    def test_obsolete_packages(self):
        '''Test obsolete_packages().'''

        report = Report()
        self.assertRaises(KeyError, report.obsolete_packages)

        # should work without Dependencies
        report['Package'] = 'bash 0'
        self.assertEqual(report.obsolete_packages(), ['bash'])
        report['Package'] = 'bash 0 [modified: /bin/bash]'
        self.assertEqual(report.obsolete_packages(), ['bash'])
        report['Package'] = 'bash ' + packaging.get_available_version('bash')
        self.assertEqual(report.obsolete_packages(), [])

        report['Dependencies'] = 'coreutils 0\ncron 0\n'
        self.assertEqual(report.obsolete_packages(), ['coreutils', 'cron'])

        report['Dependencies'] = 'coreutils %s [modified: /bin/mount]\ncron 0\n' % \
            packaging.get_available_version('coreutils')
        self.assertEqual(report.obsolete_packages(), ['cron'])

        report['Dependencies'] = 'coreutils %s\ncron %s\n' % (
            packaging.get_available_version('coreutils'),
            packaging.get_available_version('cron'))
        self.assertEqual(report.obsolete_packages(), [])

    def test_gen_stacktrace_top(self):
        '''Test _gen_stacktrace_top().'''
        
        # nothing to chop off
        r = Report()
        r['Stacktrace'] = '''#0  0x10000488 in h (p=0x0) at crash.c:25
#1  0x100004c8 in g (x=1, y=42) at crash.c:26
#2  0x10000514 in f (x=1) at crash.c:27
#3  0x10000530 in e (x=1) at crash.c:28
#4  0x10000530 in d (x=1) at crash.c:29
#5  0x10000530 in c (x=1) at crash.c:30
#6  0x10000550 in main () at crash.c:31
'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '''h (p=0x0) at crash.c:25
g (x=1, y=42) at crash.c:26
f (x=1) at crash.c:27
e (x=1) at crash.c:28
d (x=1) at crash.c:29''')

        # single signal handler invocation
        r = Report()
        r['Stacktrace'] = '''#0  0x10000488 in raise () from /lib/libpthread.so.0
#1  0x100004c8 in ??
#2  <signal handler called>
#3  0x10000530 in e (x=1) at crash.c:28
#4  0x10000530 in d (x=1) at crash.c:29
#5  0x10000530 in c (x=1) at crash.c:30
#6  0x10000550 in main () at crash.c:31
'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '''e (x=1) at crash.c:28
d (x=1) at crash.c:29
c (x=1) at crash.c:30
main () at crash.c:31''')

        # stacked signal handler; should only cut the first one
        r = Report()
        r['Stacktrace'] = '''#0  0x10000488 in raise () from /lib/libpthread.so.0
#1  0x100004c8 in ??
#2  <signal handler called>
#3  0x10000530 in e (x=1) at crash.c:28
#4  0x10000530 in d (x=1) at crash.c:29
#5  0x10000123 in raise () from /lib/libpthread.so.0
#6  <signal handler called>
#7  0x10000530 in c (x=1) at crash.c:30
#8  0x10000550 in main () at crash.c:31
'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '''e (x=1) at crash.c:28
d (x=1) at crash.c:29
raise () from /lib/libpthread.so.0
<signal handler called>
c (x=1) at crash.c:30''')

        # Gnome assertion; should unwind the logs and assert call
        r = Report()
        r['Stacktrace'] = '''#0  0xb7d39cab in IA__g_logv (log_domain=<value optimized out>, log_level=G_LOG_LEVEL_ERROR, 
    format=0xb7d825f0 "file %s: line %d (%s): assertion failed: (%s)", args1=0xbfee8e3c "xxx") at /build/buildd/glib2.0-2.13.5/glib/gmessages.c:493
#1  0xb7d39f29 in IA__g_log (log_domain=0xb7edbfd0 "libgnomevfs", log_level=G_LOG_LEVEL_ERROR, 
    format=0xb7d825f0 "file %s: line %d (%s): assertion failed: (%s)") at /build/buildd/glib2.0-2.13.5/glib/gmessages.c:517
#2  0xb7d39fa6 in IA__g_assert_warning (log_domain=0xb7edbfd0 "libgnomevfs", file=0xb7ee1a26 "gnome-vfs-volume.c", line=254, 
    pretty_function=0xb7ee1920 "gnome_vfs_volume_unset_drive_private", expression=0xb7ee1a39 "volume->priv->drive == drive")
    at /build/buildd/glib2.0-2.13.5/glib/gmessages.c:552
No locals.
#3  0xb7ec6c11 in gnome_vfs_volume_unset_drive_private (volume=0x8081a30, drive=0x8078f00) at gnome-vfs-volume.c:254
        __PRETTY_FUNCTION__ = "gnome_vfs_volume_unset_drive_private"
#4  0x08054db8 in _gnome_vfs_volume_monitor_disconnected (volume_monitor=0x8070400, drive=0x8078f00) at gnome-vfs-volume-monitor.c:963
        vol_list = (GList *) 0x8096d30
        current_vol = (GList *) 0x8097470
#5  0x0805951e in _hal_device_removed (hal_ctx=0x8074da8, udi=0x8093be4 "/org/freedesktop/Hal/devices/volume_uuid_92FC9DFBFC9DDA35")
    at gnome-vfs-hal-mounts.c:1316
        backing_udi = <value optimized out>
#6  0xb7ef1ead in filter_func (connection=0x8075288, message=0x80768d8, user_data=0x8074da8) at libhal.c:820
        udi = <value optimized out>
        object_path = 0x8076d40 "/org/freedesktop/Hal/Manager"
        error = {name = 0x0, message = 0x0, dummy1 = 1, dummy2 = 0, dummy3 = 0, dummy4 = 1, dummy5 = 0, padding1 = 0xb7e50c00}
#7  0xb7e071d2 in dbus_connection_dispatch (connection=0x8075288) at dbus-connection.c:4267
#8  0xb7e33dfd in ?? () from /usr/lib/libdbus-glib-1.so.2'''
        r._gen_stacktrace_top()
        self.assertEqual(r['StacktraceTop'], '''gnome_vfs_volume_unset_drive_private (volume=0x8081a30, drive=0x8078f00) at gnome-vfs-volume.c:254
_gnome_vfs_volume_monitor_disconnected (volume_monitor=0x8070400, drive=0x8078f00) at gnome-vfs-volume-monitor.c:963
_hal_device_removed (hal_ctx=0x8074da8, udi=0x8093be4 "/org/freedesktop/Hal/devices/volume_uuid_92FC9DFBFC9DDA35")
filter_func (connection=0x8075288, message=0x80768d8, user_data=0x8074da8) at libhal.c:820
dbus_connection_dispatch (connection=0x8075288) at dbus-connection.c:4267''')

    def test_crash_signature(self):
        '''Test crash_signature().'''

        r = Report()
        self.assertEqual(r.crash_signature(), None)

        # signal crashes
        r['Signal'] = '42'
        r['ExecutablePath'] = '/bin/crash'

        r['StacktraceTop'] = '''foo_bar (x=1) at crash.c:28
d01 (x=1) at crash.c:29
raise () from /lib/libpthread.so.0
<signal handler called>
__frob::~frob (x=1) at crash.c:30'''

        self.assertEqual(r.crash_signature(), '/bin/crash:42:foo_bar:d01:raise:<signal handler called>:__frob::~frob')

        r['StacktraceTop'] = '''foo_bar (x=1) at crash.c:28
??
raise () from /lib/libpthread.so.0
<signal handler called>
__frob (x=1) at crash.c:30'''
        self.assertEqual(r.crash_signature(), None)

        # Python crashes
        del r['Signal']
        r['Traceback'] = '''Traceback (most recent call last):
  File "test.py", line 7, in <module>
    print _f(5)
  File "test.py", line 5, in _f
    return g_foo00(x+1)
  File "test.py", line 2, in g_foo00
    return x/0
ZeroDivisionError: integer division or modulo by zero'''
        self.assertEqual(r.crash_signature(), '/bin/crash:ZeroDivisionError:<module>:_f:g_foo00')

        # sometimes Python traces do not have file references
        r['Traceback'] = 'TypeError: function takes exactly 0 arguments (1 given)'
        self.assertEqual(r.crash_signature(), '/bin/crash:TypeError')

        r['Traceback'] = 'FooBar'
        self.assertEqual(r.crash_signature(), None)

    def test_binary_data(self):
        '''Test that methods get along with binary data.'''

        pr = Report()
        pr['Signal'] = '11'
        pr['ExecutablePath'] = '/bin/foo'
        pr['Stacktrace'] = '''#0  0x10000488 in h (p="\0\0\0\1\2") at crash.c:25
#1  0x10000550 in main () at crash.c:31
'''
        pr['ThreadStacktrace'] = pr['Stacktrace']
        pr['ProcCmdline'] = 'python\0-OO\011\0/bin/bash'
        pr._gen_stacktrace_top()

        io = StringIO()
        pr.write(io)
        io.seek(0)
        pr = Report()
        pr.load(io, binary='compressed')

        assert hasattr(pr['StacktraceTop'], 'get_value')

        self.assertEqual(pr.has_useful_stacktrace(), True)
        self.assertEqual(pr.crash_signature(), '/bin/foo:11:h:main')
        self.assertEqual(pr.standard_title(), 'foo crashed with SIGSEGV in h()')

    def test_module_license_evaluation(self):
        '''Test that module licenses can be validated correctly.'''

        def _build_ko(license):
            asm = tempfile.NamedTemporaryFile(prefix='%s-' % (license),
                                              suffix='.S')
            asm.write('.section .modinfo\n.string "license=%s"\n' % (license))
            asm.flush()
            ko = tempfile.NamedTemporaryFile(prefix='%s-' % (license),
                                             suffix='.ko')
            subprocess.call(['/usr/bin/as',asm.name,'-o',ko.name])
            return ko
        
        good_ko = _build_ko('GPL')
        bad_ko  = _build_ko('BAD')

        # test:
        #  - loaded real module
        #  - unfindable module
        #  - fake GPL module
        #  - fake BAD module

        # direct license check
        self.assert_('GPL' in get_module_license('usbcore'))
        self.assert_(get_module_license('does-not-exist') == None)
        self.assert_('GPL' in get_module_license(good_ko.name))
        self.assert_('BAD' in get_module_license(bad_ko.name))

        # check via nonfree_modules logic
        f = tempfile.NamedTemporaryFile()
        f.write('usbcore\ndoes-not-exist\n%s\n%s\n' %
                (good_ko.name,bad_ko.name))
        f.flush()
        nonfree = nonfree_modules(f.name)
        self.failIf('usbcore' in nonfree)
        self.failIf('does-not-exist' in nonfree)
        self.failIf(good_ko.name in nonfree)
        self.assert_(bad_ko.name in nonfree)

if __name__ == '__main__':
    unittest.main()
