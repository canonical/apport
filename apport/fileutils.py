'''Functions to manage apport problem report files.

Copyright (C) 2006 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import os, glob, subprocess, os.path
from problem_report import ProblemReport

report_dir = os.environ.get('APPORT_REPORT_DIR', '/var/crash')

def find_package_desktopfile(package):
    '''If given package is installed and has a single .desktop file, return the
    path to it, otherwise return None.'''

    if package is None:
        return None

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

def likely_packaged(file):
    '''Check whether the given file is likely to belong to a package.

    This is semi-decidable: A return value of False is definitive, a True value
    is only a guess which needs to be checked with find_file_package().
    However, this function is very fast and does not access the dpkg
    database.'''

    pkg_whitelist = ['/bin/', '/boot', '/etc/', '/initrd', '/lib', '/sbin/',
    '/usr/', '/var'] # packages only ship files in these directories

    whitelist_match = False
    for i in pkg_whitelist:
        if file.startswith(i):
            whitelist_match = True
            break
    return whitelist_match and not file.startswith('/usr/local/')

def find_file_package(file):
    '''Return the package that ships the given file (or None if no package
    ships it).'''

    if not likely_packaged(file):
	return None

    # check if the file is a diversion
    dpkg = subprocess.Popen(['/usr/sbin/dpkg-divert', '--list', file],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = dpkg.communicate()[0]
    if dpkg.returncode == 0 and out:
        return out.split()[-1]

    fname = os.path.splitext(os.path.basename(file))[0].lower()

    all_lists = []
    likely_lists = []
    for f in glob.glob('/var/lib/dpkg/info/*.list'):
        p = os.path.splitext(os.path.basename(f))[0].lower()
        if fname.find(p) >= 0 or p.find(fname) >= 0:
            likely_lists.append(f)
        else:
            all_lists.append(f)

    # first check the likely packages
    p = subprocess.Popen(['fgrep', '-lxm', '1', '--', file] +
        likely_lists, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    out = p.communicate()[0]
    if p.returncode != 0:
        p = subprocess.Popen(['fgrep', '-lxm', '1', '--', file] +
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
    try:
        os.utime(report, (st.st_mtime, st.st_mtime-1))
    except OSError:
        # file is probably not our's, so do it the slow and boring way
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

def check_files_md5(sumfile):
    '''Given a list of MD5 sums in md5sum(1) format (relative to /), check
    integrity of all files and return a list of files that don't match.'''

    assert os.path.exists(sumfile)
    m = subprocess.Popen(['/usr/bin/md5sum', '-c', sumfile],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        cwd='/', env={})
    out = m.communicate()[0]

    # if md5sum succeeded, don't bother parsing the output
    if m.returncode == 0:
        return []

    mismatches = []
    for l in out.splitlines():
        if l.endswith('FAILED'):
            mismatches.append(l.rsplit(':', 1)[0])

    return mismatches

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

    def test_likely_packaged(self):
        '''Test likely_packaged() behaviour.'''

        self.assertEqual(likely_packaged('/bin/bash'), True)
        self.assertEqual(likely_packaged('/usr/bin/foo'), True)
        self.assertEqual(likely_packaged('/usr/local/bin/foo'), False)
        self.assertEqual(likely_packaged('/home/test/bin/foo'), False)
        self.assertEqual(likely_packaged('/tmp/foo'), False)
	# err on the side of caution for /var
        self.assertEqual(likely_packaged('/var/lib/foo'), True)

    def test_find_file_package(self):
        '''Test find_file_package() behaviour.'''

        self.assertEqual(find_file_package('/bin/bash'), 'bash')
        self.assertEqual(find_file_package('/bin/cat'), 'coreutils')
        self.assertEqual(find_file_package('/nonexisting'), None)

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

    def test_get_all_reports(self):
        '''Test get_all_reports() behaviour.'''

        self.assertEqual(get_all_reports(), [])
        tr = [r for r in self._create_reports(True) if r.find('inaccessible') == -1]
        self.assertEqual(set(get_all_reports()), set(tr))

        # now mark them as seen and check again
        for r in tr:
            mark_report_seen(r)

        self.assertEqual(set(get_all_reports()), set(tr))

    def test_delete_report(self):
        '''Test delete_report() behaviour.'''

        tr = self._create_reports()

        while tr:
            self.assertEqual(set(get_all_reports()), set(tr))
            delete_report(tr.pop())

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

    def test_find_file_package_diversion(self):
        '''Test find_file_package() behaviour for a diverted file.'''

        # pick first diversion we have
        p = subprocess.Popen('LC_ALL=C dpkg-divert --list | head -n 1',
            shell=True, stdout=subprocess.PIPE)
        out = p.communicate()[0]
        assert p.returncode == 0
        assert out
        fields = out.split()
        file = fields[2]
        pkg = fields[-1]

        self.assertEqual(find_file_package(file), pkg)

    def test_make_report_path(self):
        '''Test make_report_path() behaviour.'''

        pr = ProblemReport()
        self.assertRaises(ValueError, make_report_path, pr)

        pr['Package'] = 'bash 1'
        self.assert_(make_report_path(pr).startswith('%s/bash' % report_dir))
        pr['ExecutablePath'] = '/bin/bash';
        self.assert_(make_report_path(pr).startswith('%s/_bin_bash' % report_dir))

    def test_check_files_md5(self):
        '''Test check_files_md5() behaviour.'''

        f1 = os.path.join(report_dir, 'test 1.txt')
        f2 = os.path.join(report_dir, 'test:2.txt')
        sumfile = os.path.join(report_dir, 'sums.txt')
        open(f1, 'w').write('Some stuff')
        open(f2, 'w').write('More stuff')
        # use one relative and one absolute path in checksums file
        open(sumfile, 'w').write('''2e41290da2fa3f68bd3313174467e3b5  %s
f6423dfbc4faf022e58b4d3f5ff71a70  %s
''' % (f1[1:], f2))
        self.assertEqual(check_files_md5(sumfile), [], 'correct md5sums')

        open(f1, 'w').write('Some stuff!')
        self.assertEqual(check_files_md5(sumfile), [f1[1:]], 'file 1 wrong')
        open(f2, 'w').write('More stuff!')
        self.assertEqual(check_files_md5(sumfile), [f1[1:], f2], 'files 1 and 2 wrong')
        open(f1, 'w').write('Some stuff')
        self.assertEqual(check_files_md5(sumfile), [f2], 'file 2 wrong')

if __name__ == '__main__':
    unittest.main()
