'''Class for representing and working with chroots.'''

# (c) 2007 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import subprocess, tempfile, os.path, shutil

class Chroot:
    '''Work with a chroot (either in directory or in tarball form).'''

    def __init__(self, root):
	'''Bind to a chroot, which can either be a directory, a tarball, or
	None to work in the main system.

	If a tarball is given, then it gets unpacked into a temporary directory
	which is cleaned up at program termination.'''

	self.exec_prefix = ['fakechroot', '-s', 'fakeroot']
	self.remove = False

	if root is None:
	    self.root = None
	elif os.path.isdir(root):
	    self.root = root
	else:
	    assert os.path.isfile(root)
	    self.root = tempfile.mkdtemp()
	    self.remove = True
	    assert subprocess.call(self.exec_prefix + ['tar', '-C', self.root,
		'-xzf', root]) == 0

    def __del__(self):
	if self.remove:
	    shutil.rmtree(self.root)
    
    def _exec_capture(self, argv, stdin=None):
	'''Internal helper function to wrap subprocess.Popen() and return a
	triple (stdout, stderr, returncode).'''

	if stdin:
	    p = subprocess.Popen(argv, stdin=subprocess.PIPE,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	    (out, err) = p.communicate(stdin)
	else:
	    p = subprocess.Popen(argv, stdin=subprocess.PIPE,
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	    (out, err) = p.communicate()
	return (out, err, p.returncode)
	    
    def run(self, argv):
	'''Execute the given commandline vector in the chroot and return the
	exit code.'''

	if self.root:
	    return subprocess.call(self.exec_prefix + ['chroot', self.root] + argv)
	else:
	    return subprocess.call(argv)

    def run_capture(self, argv, stdin=None):
	'''Execute the given command line vector in the chroot and return a
	triple (stdout, stderr, exit code).'''

	if self.root:
            return self._exec_capture(self.exec_prefix + ['chroot', self.root] +
	       argv, stdin)
	else:
	   return self._exec_capture(argv, stdin)
	
#
# Unit test
#

if __name__ == '__main__':
    import unittest, os

    class ChrootTest(unittest.TestCase):
	def test_null(self):
	    '''Test null chroot (working in the main system)'''

	    c = Chroot(None)
	    self.assertEqual(c.run(['/bin/sh', '-c', 'exit 42']), 42)

	    (out, err, ret) = c.run_capture(['/bin/ls', '/bin/ls'])
	    self.assertEqual(ret, 0)
	    self.assertEqual(out, '/bin/ls\n')
	    self.assertEqual(err, '')

	    (out, err, ret) = c.run_capture(['/bin/ls', '/nonexisting/gibberish'])
	    self.assertNotEqual(ret, 0)
	    self.assertEqual(out, '')
	    self.assertNotEqual(err, '')

	def _mkchroot(self):
	    '''Return a test chroot dir with /bin/hello and /bin/42.'''

	    d = tempfile.mkdtemp()
	    bindir = os.path.join(d, 'bin')
	    os.mkdir(bindir)
	    open(os.path.join(d, 'hello.c'), 'w').write('''
#include <stdio.h>
int main() { puts("hello"); return 0; }
''')
	    open(os.path.join(d, '42.c'), 'w').write('''
int main() { return 42; }
''')
	    assert subprocess.call(['cc', '-static', os.path.join(d,
		'hello.c'), '-o', os.path.join(bindir, 'hello')]) == 0
	    assert subprocess.call(['cc', '-static', os.path.join(d,
		'42.c'), '-o', os.path.join(bindir, '42')]) == 0

	    return d

	def test_dir(self):
	    '''Test directory chroot.'''

	    d = self._mkchroot() 
	    try:
		c = Chroot(d)

		self.assertEqual(c.run(['/bin/42']), 42)

		(out, err, ret) = c.run_capture(['/bin/hello'])
		self.assertEqual(ret, 0)
		self.assertEqual(out, 'hello\n')
		self.assertEqual(err, '')

		del c
		self.assert_(os.path.exists(os.path.join(d, 'bin', '42')),
		    'directory chroot should not delete the chroot')

	    finally:
		shutil.rmtree(d)

	def test_tarball(self):
	    '''Test tarball chroot.'''

	    d = self._mkchroot() 
	    try:
		(fd, tar) = tempfile.mkstemp()
		os.close(fd)
		orig_cwd = os.getcwd()
		os.chdir(d)
		assert subprocess.call(['tar', 'czPf', tar, '.']) == 0
		assert os.path.exists(tar)
		os.chdir(orig_cwd)
	    finally:
		shutil.rmtree(d)

	    try:
		c = Chroot(tar)
		self.assertEqual(c.run(['/bin/42']), 42)

		(out, err, ret) = c.run_capture(['/bin/hello'])
		self.assertEqual(ret, 0)
		self.assertEqual(out, 'hello\n')
		self.assertEqual(err, '')

		d = c.root
		del c
		self.assert_(not os.path.exists(d), 
		    'tarball chroot should delete the temporary chroot')
	    finally:
		os.unlink(tar)

    unittest.main()
