'''Various utility functions to handle apport problem reports.

Copyright (C) 2006 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import subprocess, os, os.path, glob, time
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

def seen_report(report):
    '''Check whether the given report file has already been processed
    earlier.'''

    st = os.stat(report)
    return (st.st_atime > st.st_mtime) or (st.st_size == 0)

def mark_report_seen(report):
    '''Mark given report file as seen.'''

    # change the file's access time until it stat's different than the mtime.
    # This might take a while if we only have 1-second resolution. Time out
    # after 1.2 seconds.

    timeout = 12
    while timeout > 0:
	f = open(report)
	f.read(1)
	f.close()
	st = os.stat(report)
	if st.st_atime > st.st_mtime:
	    break
	time.sleep(0.1)
	timeout -= 1

    if timeout == 0:
	raise OSError, 'could not modify atime of report file ' + report

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

#
# Unit test
#

import unittest, tempfile, os, shutil, sys, time, StringIO

class ApportUtilsTest(unittest.TestCase):
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

if __name__ == '__main__':
    unittest.main()
