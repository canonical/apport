'''Various utility functions to handle apport problem reports.

Copyright (C) 2006 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import subprocess, os, os.path, glob, time, urllib, re, signal
import xml.dom, xml.dom.minidom
from xml.parsers.expat import ExpatError

import warnings
warnings.filterwarnings("ignore", "apt API not stable yet", FutureWarning)
import apt

from problem_report import ProblemReport

report_dir = os.environ.get('APPORT_REPORT_DIR', '/var/crash')

def find_package_desktopfile(package):
    '''If given package is installed and has a single .desktop file, return the
    path to it, otherwise return None.'''

    dpkg = subprocess.Popen(['dpkg', '-L', package], stdout=subprocess.PIPE,
	stderr=subprocess.PIPE)
    out = dpkg.communicate(input)[0]
    if dpkg.returncode != 0:
	return None

    desktopfile = None

    for line in out.splitlines():
	if line.endswith('.desktop'):
	    if desktopfile:
		return None # more than one
	    else:
		desktopfile = line

    return desktopfile

def find_file_package(file):
    '''Return the package that ships the given file (or None if no package
    ships it).'''

    # first apply some heuristics to avoid the expensive dpkg database grepping
    pkg_whitelist = ['/bin/', '/boot', '/etc/', '/initrd', '/lib', '/sbin/',
    '/usr/', '/var'] # packages only ship files in these directories
    whitelist_match = False
    for i in pkg_whitelist:
	if file.startswith(i):
	    whitelist_match = True
	    break
    if file.startswith('/usr/local/') or not whitelist_match:
	return None

    fname = os.path.splitext(os.path.basename(file))[0]

    all_lists = []
    likely_lists = []
    for f in glob.glob('/var/lib/dpkg/info/*.list'):
	p = os.path.splitext(os.path.basename(f))[0]
	if fname.find(p) >= 0 or p.find(fname) >= 0:
	    likely_lists.append(f)
	else:
	    all_lists.append(f)

    # first check the likely packages
    p = subprocess.Popen(['fgrep', '-lxm', '1', file] +
	likely_lists, stdin=subprocess.PIPE,
	stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    out = p.communicate()[0]
    if p.returncode != 0:
	p = subprocess.Popen(['fgrep', '-lxm', '1', file] +
	    all_lists, stdin=subprocess.PIPE,
	    stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	out = p.communicate()[0]
	if p.returncode != 0:
	    return None

    return os.path.splitext(os.path.basename(out))[0]

def seen_report(report):
    '''Check whether the given report file has already been processed
    earlier.'''

    st = os.stat(report)
    return (st.st_atime > st.st_mtime) or (st.st_size == 0)

def mark_report_seen(report):
    '''Mark given report file as seen.'''

    st = os.stat(report)
    os.utime(report, (st.st_mtime, st.st_mtime-1))
    return

def get_all_reports():
    '''Return a list with all report files which are accessible to the calling
    user.'''

    return [r for r in glob.glob(os.path.join(report_dir, '*.crash')) 
	    if os.path.getsize(r) > 0 and os.access(r, os.R_OK)]

def get_new_reports():
    '''Return a list with all report files which have not yet been processed
    and are accessible to the calling user.'''

    return [r for r in get_all_reports() if not seen_report(r)]

def delete_report(report):
    '''Delete the given report file.

    If unlinking the file fails due to a permission error (if report_dir is not
    writable to normal users), the file will be truncated to 0 bytes instead.'''

    try:
	os.unlink(report)
    except OSError:
	open(report, 'w').truncate(0)

def get_recent_crashes(report):
    '''Return the number of recent crashes for the given report file.
    
    Return the number of recent crashes (currently, crashes which happened more
    than 24 hours ago are discarded).'''

    pr = ProblemReport()
    pr.load(report, False)
    try:
	count = int(pr['CrashCounter'])
	report_time = time.mktime(time.strptime(pr['Date']))
	cur_time = time.mktime(time.localtime())
	# discard reports which are older than 24 hours
	if cur_time - report_time > 24*3600:
	    return 0
	return count
    except (ValueError, KeyError):
	return 0

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

def report_add_package_info(report, package = None):
    '''Add packaging information to the given report.

    If package is not given, the report must have ExecutableName.
    This adds:
    - Package: package name and installed version
    - SourcePackage: source package name
    - Dependencies: package names and versions of all dependencies and
      pre-dependencies'''

    if not package:
	package = find_file_package(report['ExecutablePath'])
	if not package:
	    return

    cache = apt.Cache()

    report['Package'] = '%s %s' % (package, cache[package].installedVersion)
    report['SourcePackage'] = cache[package].sourcePackageName

    # get set of all transitive dependencies
    dependencies = set([])
    _transitive_dependencies(package, dependencies, cache)

    # get dependency versions
    report['Dependencies'] = ''
    for dep in dependencies:
	try:
	    cur_ver = cache[dep]._pkg.CurrentVer
	except (KeyError, AttributeError):
	    continue
	if report['Dependencies']:
	    report['Dependencies'] += '\n'
	report['Dependencies'] += '%s %s' % (dep, cur_ver.VerStr)

def report_add_os_info(report):
    '''Add operating system information to the given report.

    This adds:
    - DistroRelease: lsb_release -sir output
    - Uname: uname -a output'''

    p = subprocess.Popen(['lsb_release', '-sir'], stdout=subprocess.PIPE,
	stderr=subprocess.STDOUT, close_fds=True)
    report['DistroRelease'] = p.communicate()[0].strip().replace('\n', ' ')

    p = subprocess.Popen(['uname', '-a'], stdout=subprocess.PIPE,
	stderr=subprocess.STDOUT, close_fds=True)
    report['Uname'] = p.communicate()[0].strip()

def _read_file(f):
    '''Try to read given file and return its contents, or return a textual
    error if it failed.'''

    try:
	return open(f).read().strip()
    except (OSError, IOError), e:
	return 'Error: ' + str(e)

def report_add_proc_info(report, pid=None, extraenv=[]):
    '''Add /proc/pid information to the given report.

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
	report['ExecutablePath'] = os.readlink('/proc/' + pid + '/exe')
    except OSError:
	pass
    report['ProcEnviron'] = ''
    env = _read_file('/proc/'+ pid + '/environ').replace('\n', '\\n')
    if env.startswith('Error:'):
	report['ProcEnviron'] = env
    else:
	for l in env.split('\0'):
	    if l.split('=', 1)[0] in safe_vars:
		if report['ProcEnviron']:
		    report['ProcEnviron'] += '\n'
		report['ProcEnviron'] += l
    report['ProcStatus'] = _read_file('/proc/' + pid + '/status')
    report['ProcCmdline'] = _read_file('/proc/' + pid + '/cmdline').rstrip('\0').replace('\\', '\\\\').replace(' ', '\\ ').replace('\0', ' ')
    report['ProcMaps'] = _read_file('/proc/' + pid + '/maps')

    # check if we have an interpreted program
    # first, determine process name
    name = None
    for l in report['ProcStatus'].splitlines():
	try:
	    (k, v) = l.split('\t', 1)
	except ValueError:
	    continue
	if k == 'Name:':
	    name = v
	    break
    if not name:
	return

    cmdargs = _read_file('/proc/' + pid + '/cmdline').split('\0', 2)
    if len(cmdargs) >= 2:
	# ensure that cmdargs[1] is an absolute path 
	if cmdargs[1].startswith('.'):
	    cmdargs[1] = os.path.join(os.readlink('/proc/' + pid + '/cwd'), cmdargs[1])
	if os.path.basename(cmdargs[0]) != name and os.access(cmdargs[1], os.R_OK):
	    report['InterpreterPath'] = report['ExecutablePath']
	    report['ExecutablePath'] = os.path.realpath(cmdargs[1])

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

def report_add_gdb_info(report, debugdir=None):
    '''Add information from gdb to the given report.

    This requires that the report has a CoreDump (file ref) and an
    ExecutablePath. This adds the following fields:
    - Stacktrace: Output of gdb's 'bt full' command
    - ThreadStacktrace: Output of gdb's 'thread apply all bt full' command

    The optional debugdir can specify an alternative debug symbol root
    directory.
    '''

    if not report.has_key('CoreDump') or not report.has_key('ExecutablePath'):
	return

    unlink_core = False
    try:
	if hasattr(report['CoreDump'], 'find'):
	    (fd, core) = tempfile.mkstemp()
	    os.write(fd, report['CoreDump'])
	    os.close(fd)
	    unlink_core = True
	else:
	    core = report['CoreDump'][0]

	gdb_reports = {
		       'Registers': 'info registers',
	               'Disassembly': 'disassemble $pc $pc+32',
	               'Stacktrace': 'bt full',
	               'ThreadStacktrace': 'thread apply all bt full',
		      }

	command = ['gdb', '--batch']
	if debugdir:
	    command += ['--ex', 'set debug-file-directory ' + debugdir]
	command += ['--ex', 'file ' + report['ExecutablePath'], '--ex',
	'core-file ' + core]
	for field, gdbcommand in gdb_reports.iteritems():
	    report[field] = _command_output(command + ['--ex', gdbcommand],
		stderr=open('/dev/null')).replace('\n\n', '\n.\n').strip()
    finally:
	if unlink_core:
	    os.unlink(core)

def make_report_path(report, uid=None):
    '''Construct a canonical pathname for the given report.
    
    If uid is not given, it defaults to the uid of the current process.'''

    if report.has_key('ExecutablePath'):
	subject = report['ExecutablePath'].replace('/', '_')
    elif report.has_key('Package'):
	subject = report['Package'].split(None, 1)[0]
    else:
	raise ValueError, 'report has neither ExecutablePath nor Package attribute'

    if not uid:
	uid = os.getuid()

    return os.path.join(report_dir, '%s.%i.crash' % (subject, uid))

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

def report_search_bug_patterns(report, baseurl):
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

    assert report.has_key('Package')
    package = report['Package'].split()[0]
    try:
	patterns = urllib.urlopen('%s/%s.xml' % (baseurl, package)).read()
    except IOError:
	return None

    try:
	dom = xml.dom.minidom.parseString(patterns)
    except ExpatError:
	return None

    for pattern in dom.getElementsByTagName('pattern'):
	m = _check_bug_pattern(report, pattern)
	if m:
	    return m

    return None

#
# Unit test
#

import unittest, tempfile, os, shutil, sys, time, StringIO

class _ApportUtilsTest(unittest.TestCase):
    def setUp(self):
	global report_dir
	self.orig_report_dir = report_dir
	report_dir = tempfile.mkdtemp()

    def tearDown(self):
	global report_dir
	shutil.rmtree(report_dir)
	report_dir = self.orig_report_dir
	self.orig_report_dir = None

    def _create_reports(self, create_inaccessible = False):
	'''Create some test reports.'''

	r1 = os.path.join(report_dir, 'rep1.crash')
	r2 = os.path.join(report_dir, 'rep2.crash')

	open(r1, 'w').write('report 1')
	open(r2, 'w').write('report 2')
	os.chmod(r1, 0600)
	os.chmod(r2, 0600)
	if create_inaccessible:
	    ri = os.path.join(report_dir, 'inaccessible.crash')
	    open(ri, 'w').write('inaccessible')
	    os.chmod(ri, 0)
	    return [r1, r2, ri]
	else:
	    return [r1, r2]

    def test_get_all_reports(self):
	'''Test get_all_reports() behaviour.'''

	self.assertEqual(get_all_reports(), [])
	tr = [r for r in self._create_reports(True) if r.find('inaccessible') == -1]
	self.assertEqual(set(get_all_reports()), set(tr))

	# now mark them as seen and check again
	for r in tr:
	    mark_report_seen(r)

	self.assertEqual(set(get_all_reports()), set(tr))

    def test_seen(self):
	'''Test get_new_reports() and seen_report() behaviour.'''

	self.assertEqual(get_new_reports(), [])
	tr = [r for r in self._create_reports(True) if r.find('inaccessible') == -1]
	self.assertEqual(set(get_new_reports()), set(tr))

	# now mark them as seen and check again
	nr = set(tr)
	for r in tr:
	    self.assertEqual(seen_report(r), False)
	    nr.remove(r)
	    mark_report_seen(r)
	    self.assertEqual(seen_report(r), True)
	    self.assertEqual(set(get_new_reports()), nr)

    def test_delete_report(self):
	'''Test delete_report() behaviour.'''

	tr = self._create_reports()

	while tr:
	    self.assertEqual(set(get_all_reports()), set(tr))
	    delete_report(tr.pop())

    def test_find_package_desktopfile(self):
	'''Test find_package_desktopfile() behaviour.'''

	# find a package without any .desktop file
	sp = subprocess.Popen("grep -c '\.desktop$' /var/lib/dpkg/info/*.list | grep -m 1 ':0$'",
	    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	nodesktop = os.path.splitext(os.path.basename(sp.communicate()[0]))[0]
	sp = subprocess.Popen("grep -c '\.desktop$' /var/lib/dpkg/info/*.list | grep -m 1 ':1$'",
	    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	onedesktop = os.path.splitext(os.path.basename(sp.communicate()[0]))[0]
	sp = subprocess.Popen("grep -c '\.desktop$' /var/lib/dpkg/info/*.list | grep -m 1 -v ':\(0\|1\)$'",
	    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	multidesktop = os.path.splitext(os.path.basename(sp.communicate()[0]))[0]

	self.assertEqual(find_package_desktopfile(nodesktop), None, 'no-desktop package %s' % nodesktop)
	self.assertEqual(find_package_desktopfile(multidesktop), None, 'multi-desktop package %s' % multidesktop)
	d = find_package_desktopfile(onedesktop)
	self.assertNotEqual(d, None, 'one-desktop package %s' % onedesktop)
	self.assert_(os.path.exists(d))
	self.assert_(d.endswith('.desktop'))

    def test_get_recent_crashes(self):
	'''Test get_recent_crashes() behaviour.'''

	# incomplete fields
	r = StringIO.StringIO('''ProblemType: Crash''')
	self.assertEqual(get_recent_crashes(r), 0)

	r = StringIO.StringIO('''ProblemType: Crash
Date: Wed Aug 01 00:00:01 1990''')
	self.assertEqual(get_recent_crashes(r), 0)

	# ancient report
	r = StringIO.StringIO('''ProblemType: Crash
Date: Wed Aug 01 00:00:01 1990
CrashCounter: 3''')
	self.assertEqual(get_recent_crashes(r), 0)

	# old report (one day + one hour ago)
	r = StringIO.StringIO('''ProblemType: Crash
Date: %s
CrashCounter: 3''' % time.ctime(time.mktime(time.localtime())-25*3600))
	self.assertEqual(get_recent_crashes(r), 0)

	# current report (one hour ago)
	r = StringIO.StringIO('''ProblemType: Crash
Date: %s
CrashCounter: 3''' % time.ctime(time.mktime(time.localtime())-3600))
	self.assertEqual(get_recent_crashes(r), 3)

    def test_find_file_package(self):
	'''Test find_file_package() behaviour.'''

	self.assertEqual(find_file_package('/bin/bash'), 'bash')
	self.assertEqual(find_file_package('/bin/cat'), 'coreutils')
	self.assertEqual(find_file_package('/nonexisting'), None)

    def test_report_add_package_info(self):
	'''Test report_add_package_info() behaviour.'''

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

	pr = ProblemReport()

	self.assertRaises(KeyError, report_add_package_info, pr, 'nonexistant_package')

	report_add_package_info(pr, 'bash')
	self.assertEqual(pr['Package'], 'bash ' + bashversion.strip())
	self.assertEqual(pr['SourcePackage'], 'bash')
	self.assert_(pr['Dependencies'].find('libc6 ' + libcversion) >= 0)

	# test without specifying a package, but with ExecutablePath
	pr = ProblemReport()
	self.assertRaises(KeyError, report_add_package_info, pr)
	pr['ExecutablePath'] = '/bin/bash'
	report_add_package_info(pr)
	self.assertEqual(pr['Package'], 'bash ' + bashversion.strip())
	self.assertEqual(pr['SourcePackage'], 'bash')
	self.assert_(pr['Dependencies'].find('libc6 ' + libcversion) >= 0)

	pr = ProblemReport()
	pr['ExecutablePath'] = '/nonexisting'
	report_add_package_info(pr)
	self.assert_(not pr.has_key('Package'))

    def test_report_add_os_info(self):
	'''Test report_add_os_info() behaviour.'''

	pr = ProblemReport()
	report_add_os_info(pr)
	self.assert_(pr['Uname'].startswith('Linux'))
	self.assert_(type(pr['DistroRelease']) == type(''))

    def test_report_add_proc_info(self):
	'''Test report_add_proc_info() behaviour.'''

	# set test environment
	assert os.environ.has_key('LANG'), 'please set $LANG for this test'
	assert os.environ.has_key('USER'), 'please set $USER for this test'
	assert os.environ.has_key('PWD'), '$PWD is not set'

	# check without additional safe environment variables
	pr = ProblemReport()
	report_add_proc_info(pr)
	self.assert_(set(['ProcEnviron', 'ProcMaps', 'ProcCmdline',
	    'ProcMaps']).issubset(set(pr.keys())), 'report has required fields')
	self.assert_(pr['ProcEnviron'].find('LANG='+os.environ['LANG']) >= 0)
	self.assert_(pr['ProcEnviron'].find('USER') < 0)
	self.assert_(pr['ProcEnviron'].find('PWD') < 0)

	# check with one additional safe environment variable
	pr = ProblemReport()
	report_add_proc_info(pr, extraenv=['PWD'])
	self.assert_(pr['ProcEnviron'].find('USER') < 0)
	self.assert_(pr['ProcEnviron'].find('PWD='+os.environ['PWD']) >= 0)

	# check process from other user
	assert os.getuid() != 0, 'please do not run this test as root for this check.'
	pr = ProblemReport()
	report_add_proc_info(pr, pid=1)
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
	pr = ProblemReport()
	report_add_proc_info(pr, pid=p.pid)
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
	pr = ProblemReport()
	report_add_proc_info(pr, pid=p.pid)
	p.communicate('\n')
	self.assertEqual(pr['ExecutablePath'], '/bin/zgrep')
	self.assertEqual(pr['InterpreterPath'], os.path.realpath('/bin/sh'))

	# check correct handling of interpreted executables: python 
	assert not os.path.exists('./testsuite-unpack'), 'Directory ./testsuite-unpack must not exist'
	p = subprocess.Popen(['./apport-unpack', '-', 'testsuite-unpack'], stdin=subprocess.PIPE,
	    stderr=subprocess.PIPE, close_fds=True)
	assert p.pid
	# wait until /proc/pid/cmdline exists
	while not open('/proc/%i/cmdline' % p.pid).read():
	    time.sleep(0.1)
	pr = ProblemReport()
	report_add_proc_info(pr, pid=p.pid)
	p.communicate('\n')
	os.rmdir('testsuite-unpack')
	self.assertEqual(pr['ExecutablePath'], os.path.realpath('./apport-unpack'))
	self.assert_(pr['InterpreterPath'].find('python') >= 0)

    def test_report_add_gdb_info(self):
	'''Test report_add_gdb_info() behaviour with core dump file reference.'''

	pr = ProblemReport()
	# should not throw an exception for missing fields
	report_add_gdb_info(pr)

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
		+ coredump, test_executable, str(pid)], stdout=subprocess.PIPE) == 0

	    # verify that it's a proper ELF file
	    assert subprocess.call(['readelf', '-n', coredump],
		stdout=subprocess.PIPE) == 0

	    # kill test executable
	    os.kill(pid, signal.SIGKILL)

	    pr['ExecutablePath'] = test_executable
	    pr['CoreDump'] = (coredump,)

	    report_add_gdb_info(pr)
	finally:
	    os.unlink(coredump)

	self.assert_(pr.has_key('Stacktrace'))
	self.assert_(pr.has_key('ThreadStacktrace'))
	self.assert_(pr['Stacktrace'].find('#0  0x') > 0)
	self.assert_(pr['ThreadStacktrace'].find('#0  0x') > 0)
	self.assert_(pr['ThreadStacktrace'].find('Thread 1 (process %i)' % pid) > 0)

    def test_report_add_gdb_info_load(self):
	'''Test report_add_gdb_info() behaviour with inline core dump.'''

	pr = ProblemReport()
	# should not throw an exception for missing fields
	report_add_gdb_info(pr)

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
		+ coredump, test_executable, str(pid)], stdout=subprocess.PIPE) == 0

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

	pr = ProblemReport()
	pr.load(open(rep.name))
	report_add_gdb_info(pr)

	self.assert_(pr.has_key('Stacktrace'))
	self.assert_(pr.has_key('ThreadStacktrace'))
	self.assert_(pr['CoreDump'].find('') == 0)
	self.assert_(pr['Stacktrace'].find('#0  0x') > 0)
	self.assert_(pr['ThreadStacktrace'].find('#0  0x') > 0)
	self.assert_(pr['ThreadStacktrace'].find('Thread 1 (process %i)' % pid) > 0)

    def test_make_report_path(self):
	'''Test make_report_path() behaviour.'''

	pr = ProblemReport()
	self.assertRaises(ValueError, make_report_path, pr)

	pr['Package'] = 'bash 1'
	self.assert_(make_report_path(pr).startswith('%s/bash' % report_dir))
	pr['ExecutablePath'] = '/bin/bash';
	self.assert_(make_report_path(pr).startswith('%s/_bin_bash' % report_dir))

    def test_report_search_bug_patterns(self):
	'''Test report_search_bug_patterns() behaviour.'''

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
	    r_bash = ProblemReport()
	    r_bash['Package'] = 'bash 1-2'
	    r_bash['Foo'] = 'bazaar'

	    r_coreutils = ProblemReport()
	    r_coreutils['Package'] = 'coreutils 1'
	    r_coreutils['Bar'] = '1'

	    r_invalid = ProblemReport()
	    r_invalid['Package'] = 'invalid 1'

	    # positive match cases
	    self.assertEqual(report_search_bug_patterns(r_bash, pdir), 'https://launchpad.net/bugs/1')
	    r_bash['Foo'] = 'write_goodbye'
	    self.assertEqual(report_search_bug_patterns(r_bash, pdir), 'https://launchpad.net/bugs/2')
	    self.assertEqual(report_search_bug_patterns(r_coreutils, pdir), 'https://launchpad.net/bugs/3')

	    # negative match cases
	    r_bash['Package'] = 'bash 1-21'
	    self.assertEqual(report_search_bug_patterns(r_bash, pdir), None, 
		'does not match on wrong bash version')
	    r_bash['Foo'] = 'zz'
	    self.assertEqual(report_search_bug_patterns(r_bash, pdir), None, 
		'does not match on wrong Foo value')
	    r_coreutils['Bar'] = '11'
	    self.assertEqual(report_search_bug_patterns(r_coreutils, pdir), None, 
		'does not match on wrong Bar value')

	    # various errors to check for robustness (no exceptions, just None
	    # return value)
	    del r_coreutils['Bar']
	    self.assertEqual(report_search_bug_patterns(r_coreutils, pdir), None, 
		'does not match on nonexisting key')
	    self.assertEqual(report_search_bug_patterns(r_invalid, pdir), None, 
		'gracefully handles invalid XML')
	    r_coreutils['Package'] = 'other 2'
	    self.assertEqual(report_search_bug_patterns(r_coreutils, pdir), None, 
		'gracefully handles nonexisting package XML file')
	    self.assertEqual(report_search_bug_patterns(r_bash, 'file:///nonexisting/directory/'), None, 
		'gracefully handles nonexisting base path')
	    self.assertEqual(report_search_bug_patterns(r_bash, 'http://archive.ubuntu.com/'), None, 
		'gracefully handles base path without bug patterns')
	    self.assertEqual(report_search_bug_patterns(r_bash, 'http://nonexisting.domain/'), None, 
		'gracefully handles nonexisting URL domain')
	finally:
	    if pdir:
		shutil.rmtree(pdir)

if __name__ == '__main__':
    unittest.main()
