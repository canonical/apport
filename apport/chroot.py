'''Class for representing and working with chroots.'''

# (c) 2007 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import subprocess, tempfile, os, os.path, shutil

def setup_fakeroot_env():
    '''Set up a fakeroot/fakechroot environment.

    This needs the libraries /usr/lib/libfakeroot/libfakeroot-sysv.so and
    /usr/lib/fakechroot/libfakechroot.so; these paths can be overridden
    with the environment variables APPORT_LIBFAKEROOT and
    APPORT_LIBFAKECHROOT.'''

    libfakeroot = os.environ.get('APPORT_LIBFAKEROOT',
        '/usr/lib/libfakeroot/libfakeroot-sysv.so')
    assert os.path.exists(libfakeroot), \
        '%s not found; please set APPORT_LIBFAKEROOT correctly' % libfakeroot

    libfakechroot = os.environ.get('APPORT_LIBFAKECHROOT',
        '/usr/lib/fakechroot/libfakechroot.so')
    assert os.path.exists(libfakechroot), \
        '%s not found; please set APPORT_LIBFAKECHROOT correctly' % libfakechroot

    os.environ['LD_PRELOAD'] = '%s %s %s' % (libfakechroot, libfakeroot,
        os.environ.get('LD_PRELOAD', ''))
    os.environ['LD_LIBRARY_PATH'] = '/usr/local/lib:/usr/lib:/lib:' + \
        os.environ.get('LD_LIBRARY_PATH', '')
    os.environ['FAKECHROOT'] = 'true'

def pathsplit(p, rest=[]):
    (h,t) = os.path.split(p)
    if len(h) < 1: return [t]+rest
    if len(t) < 1: return [h]+rest
    return pathsplit(h,[t]+rest)

def commonpath(l1, l2, common=[]):
    if len(l1) < 1: return (common, l1, l2)
    if len(l2) < 1: return (common, l1, l2)
    if l1[0] != l2[0]: return (common, l1, l2)
    return commonpath(l1[1:], l2[1:], common+[l1[0]])

def relpath(p1, p2):
    (common,l1,l2) = commonpath(pathsplit(p1), pathsplit(p2))
    p = []
    if len(l1) > 0:
        p = [ '../' * len(l1) ]
    p = p + l2
    return os.path.join( *p )

class Chroot:
    '''Work with a chroot (either in directory or in tarball form).
    
    If called as non-root user, this calls setup_fakeroot_env() to use the
    fakeroot/fakechroot libraries.'''

    def __init__(self, root):
        '''Bind to a chroot, which can either be a directory, a tarball, or
        None to work in the main system.

        If a tarball is given, then it gets unpacked into a temporary directory
        which is cleaned up at program termination.'''

        self.remove = False

        if os.geteuid() != 0:
            setup_fakeroot_env()

        self.root_tarball = None
        if root is None:
            self.root = None
        elif os.path.isdir(root):
            self.root = root
        else:
            assert os.path.isfile(root)
            self.root_tarball = root
            self.root = tempfile.mkdtemp()
            self.remove = True
            assert subprocess.call(['tar', '-C', self.root,
                '-xzf', root]) == 0

    def __del__(self):
        if hasattr(self, 'remove') and self.remove:
            shutil.rmtree(self.root)

    def tar(self, tarball=None):
        '''Create a tarball from the chroot.

        If tarball does not specify a .tar.gz path, then the Chroot must have
        been created from a tarball, and that tarball is updated.'''

        if not tarball:
            assert self.root_tarball
            tarball = self.root_tarball

        f = open(tarball, 'w')

        orig_cwd = os.getcwd()
        try:
            os.chdir(self.root)
            tar = subprocess.Popen(['tar', 'cp', '.'], stdout=subprocess.PIPE)
            gz = subprocess.Popen(['gzip', '-9'], stdin=tar.stdout, stdout=f)
            assert tar.wait() == 0
            assert gz.wait() == 0
            f.close()
        finally:
            os.chdir(orig_cwd)
    
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
            return subprocess.call(['chroot', self.root] + argv)
        else:
            return subprocess.call(argv)

    def run_capture(self, argv, stdin=None):
        '''Execute the given command line vector in the chroot and return a
        triple (stdout, stderr, exit code).'''

        if self.root:
            return self._exec_capture(['chroot', self.root] +
               argv, stdin)
        else:
           return self._exec_capture(argv, stdin)
        
    def fix_symlinks(self):
        '''Remove root prefix from symbolic links in chroot directory,
        otherwise chroot tarballs don't work at all, and we cannot move/rename
        chroot directories.'''

        for r, dirs, files in os.walk(self.root):
            for f in files:
                path = os.path.join(r, f)
                if os.path.islink(path):
                    target = os.readlink(path)
                    if target.startswith(self.root):
                        os.unlink(path)
                        os.symlink(relpath(os.path.dirname(path), target), path)

#
# Unit test
#

if __name__ == '__main__':
    import unittest, os, tarfile

    class ChrootTest(unittest.TestCase):
        def test_null(self):
            '''Test null chroot (working in the main system)'''

            c = Chroot(None)
            self.assertEqual(c.root_tarball, None)
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
            tarpath = None
            try:
                c = Chroot(d)
                self.assertEqual(c.root_tarball, None)

                # test running
                self.assertEqual(c.run(['/bin/42']), 42)
                (out, err, ret) = c.run_capture(['/bin/hello'])
                self.assertEqual(ret, 0)
                self.assertEqual(out, 'hello\n')
                self.assertEqual(err, '')

                # test tar'ing
                open(os.path.join(c.root, 'newfile'), 'w')
                self.assertRaises(AssertionError, c.tar)
                (fd, tarpath) = tempfile.mkstemp()
                os.close(fd)
                c.tar(tarpath)
                t = tarfile.open(tarpath)
                self.assert_(set(['./bin/42', './bin/hello',
                    './newfile']).issubset(set(t.getnames())))

                # test cleanup
                del c
                self.assert_(os.path.exists(os.path.join(d, 'bin', '42')),
                    'directory chroot should not delete the chroot')

            finally:
                shutil.rmtree(d)
                if tarpath:
                    os.unlink(tarpath)

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
                self.assertEqual(c.root_tarball, tar)

                # test running
                self.assertEqual(c.run(['/bin/42']), 42)
                (out, err, ret) = c.run_capture(['/bin/hello'])
                self.assertEqual(ret, 0)
                self.assertEqual(out, 'hello\n')
                self.assertEqual(err, '')

                # test tar'ing
                open(os.path.join(c.root, 'newfile'), 'w')
                c.tar()
                t = tarfile.open(tar)
                self.assert_(set(['./bin/42', './bin/hello',
                    './newfile']).issubset(set(t.getnames())))

                # test cleanup
                d = c.root
                del c
                self.assert_(not os.path.exists(d), 
                    'tarball chroot should delete the temporary chroot')
            finally:
                os.unlink(tar)

        def test_fix_symlinks(self):
            '''Test symlink fixing in chroots.'''

            d = self._mkchroot() 
            try:
                os.symlink(os.path.join(d, 'bin', '42'), os.path.join(d, 'bin', '42prefix'))
                os.symlink(os.path.join('/bin/42'), os.path.join(d, 'bin', '42noprefix'))
                os.symlink(os.path.join('bin/42'), os.path.join(d, '42rel'))

                c = Chroot(d)
                c.fix_symlinks()

                self.assertEqual(c.run(['/42rel']), 42)
                self.assertEqual(c.run(['/bin/42prefix']), 42)
                self.assertEqual(os.readlink(os.path.join(d, 'bin', '42noprefix')), '/bin/42')

            finally:
                shutil.rmtree(d)

    unittest.main()
