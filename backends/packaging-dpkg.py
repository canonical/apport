'''An apport.PackageInfo class implementation for dpkg, as found on Debian and
derivatives such as Ubuntu.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import subprocess, os, glob

class DpkgPackageInfo:
    '''Concrete apport.PackageInfo class implementation for dpkg, as
    found on Debian and derivatives such as Ubuntu.'''

    def get_version(self, package):
        '''Return the installed version of a package.'''

        return self._get_field(self._call_dpkg(['-s', package]), 'Version')

    def get_dependencies(self, package):
        '''Return a list of packages a package depends on.'''

        # get Depends: and PreDepends:
        result = []
        r = self._get_field(self._call_dpkg(['-s', package]), 'Depends') or ''
        result = [p.split()[0] for p in r.split(',')]
        r = self._get_field(self._call_dpkg(['-s', package]), 'Pre-Depends') or ''
        result += [p.split()[0] for p in r.split(',')]

        return result

    def get_source(self, package):
        '''Return the source package name for a package.'''

        status = self._call_dpkg(['-s', package])
        if status:
            return self._get_field(status, 'Source') or package
        else:
            return None

    def get_files(self, package):
        '''Return list of files shipped by a package.'''

        list = self._call_dpkg(['-L', package])
        if list is None:
            return None
        return [f for f in list.splitlines() if not f.startswith('diverted')]

    def get_modified_files(self, package):
        '''Return list of all modified files of a package.'''

        sumfile = '/var/lib/dpkg/info/%s.md5sums' % package
        # some packages do not ship md5sums, shrug on them
        if not os.path.exists(sumfile):
            return []
        return self._check_files_md5(sumfile)

    def get_file_package(self, file):
        '''Return the package a file belongs to, or None if the file is not
        shipped by any package.'''

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

    #
    # Internal helper methods
    #

    def _call_dpkg(self, args):
        '''Call dpkg with given arguments and return output, or return None on
        error.'''

        dpkg = subprocess.Popen(['dpkg'] + args, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        out = dpkg.communicate(input)[0]
        if dpkg.returncode == 0:
            return out
        else:
            raise ValueError, 'package does not exist'

    def _get_field(self, data, field):
        '''Extract a particular field from given debcontrol data and return
        it.'''

        if data is None:
            return None

        value = None
        for l in data.splitlines():
            if l.startswith(field + ':'):
                value = l[len(field)+2:]
                continue
            if value:
                if l.startswith(' '):
                    value += l
                else:
                    break

        return value

    def _check_files_md5(self, sumfile):
        '''Internal function for calling md5sum.

        This is separate from get_modified_files so that it is automatically
        testable.'''

        m = subprocess.Popen(['/usr/bin/md5sum', '-c', sumfile], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, cwd='/', env={})
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

if __name__ == '__main__':
    import unittest, tempfile, shutil

    class _DpkgPackageInfoTest(unittest.TestCase):
        def setUp(self):
            self.i = DpkgPackageInfo()

        def test_get_field(self):
            '''Test _get_field().'''

            data = '''Package: foo
Version: 1.2-3
Depends: libc6 (>= 2.4), libfoo,
 libbar (<< 3),
 libbaz
Conflicts: fu
Description: Test
 more
'''
            self.assertEqual(self.i._get_field(data, 'Nonexisting'), None)
            self.assertEqual(self.i._get_field(data, 'Version'), '1.2-3')
            self.assertEqual(self.i._get_field(data, 'Conflicts'), 'fu')
            self.assertEqual(self.i._get_field(data, 'Description'), 
                'Test more')
            self.assertEqual(self.i._get_field(data, 'Depends'), 
                'libc6 (>= 2.4), libfoo, libbar (<< 3), libbaz')

        def test_check_files_md5(self):
            '''Test _check_files_md5() behaviour.'''

            td = tempfile.mkdtemp()
            try:
                f1 = os.path.join(td, 'test 1.txt')
                f2 = os.path.join(td, 'test:2.txt')
                sumfile = os.path.join(td, 'sums.txt')
                open(f1, 'w').write('Some stuff')
                open(f2, 'w').write('More stuff')
                # use one relative and one absolute path in checksums file
                open(sumfile, 'w').write('''2e41290da2fa3f68bd3313174467e3b5  %s
        f6423dfbc4faf022e58b4d3f5ff71a70  %s
        ''' % (f1[1:], f2))
                self.assertEqual(self.i._check_files_md5(sumfile), [], 'correct md5sums')

                open(f1, 'w').write('Some stuff!')
                self.assertEqual(self.i._check_files_md5(sumfile), [f1[1:]], 'file 1 wrong')
                open(f2, 'w').write('More stuff!')
                self.assertEqual(self.i._check_files_md5(sumfile), [f1[1:], f2], 'files 1 and 2 wrong')
                open(f1, 'w').write('Some stuff')
                self.assertEqual(self.i._check_files_md5(sumfile), [f2], 'file 2 wrong')
            finally:
                shutil.rmtree(td)

        def test_get_version(self):
            '''Test get_version().'''

            self.assert_(self.i.get_version('libc6').startswith('2'))
            self.assertRaises(ValueError, self.i.get_version, 'nonexisting')

        def test_get_dependencies(self):
            '''Test get_dependencies().'''

            d  = self.i.get_dependencies('bash')
            self.assert_(len(d) > 2)
            self.assert_('libc6' in d)

        def test_get_source(self):
            '''Test get_source().'''

            self.assertRaises(ValueError, self.i.get_source, 'nonexisting')
            self.assertEqual(self.i.get_source('bash'), 'bash')
            self.assertEqual(self.i.get_source('libc6'), 'glibc')

        def test_get_files(self):
            '''Test get_files().'''

            self.assertRaises(ValueError, self.i.get_files, 'nonexisting')
            self.assert_('/bin/bash' in self.i.get_files('bash'))

        def test_get_file_package(self):
            '''Test get_file_package() on normal files.'''

            self.assertEqual(self.i.get_file_package('/bin/bash'), 'bash')
            self.assertEqual(self.i.get_file_package('/bin/cat'), 'coreutils')
            self.assertEqual(self.i.get_file_package('/nonexisting'), None)

        def test_get_file_package_diversion(self):
            '''Test get_file_package() behaviour for a diverted file.'''

            # pick first diversion we have
            p = subprocess.Popen('LC_ALL=C dpkg-divert --list | head -n 1',
                shell=True, stdout=subprocess.PIPE)
            out = p.communicate()[0]
            assert p.returncode == 0
            assert out
            fields = out.split()
            file = fields[2]
            pkg = fields[-1]

            self.assertEqual(self.i.get_file_package(file), pkg)

    # only execute if dpkg is available
    try:
        if subprocess.call(['dpkg', '--help'], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE) == 0:
            unittest.main()
    except OSError:
        pass
