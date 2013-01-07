# Copyright (C) 2012 Canonical Ltd.
# Author: Kyle Nitzsche <kyle.nitzsche@canonica.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import unittest
import subprocess
import tempfile
import shutil
import os
import os.path
import sys
import problem_report


class T(unittest.TestCase):
    @classmethod
    def setUpClass(klass):
        klass.workdir = tempfile.mkdtemp()
        klass.pwd = os.getcwd()

    @classmethod
    def tearDownClass(klass):
        shutil.rmtree(klass.workdir)

    def test_valgrind_min_installed(self):
        '''verify the valgrind is installed and recent enough'''

        cmd = ['valgrind', '-q', '--extra-debuginfo-path=./', 'ls']
        (ret, out, err) = self._call(cmd)
        self.assertEqual(ret, 0)

    def _call(self, argv):
        p = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, err) = p.communicate()
        ret = p.returncode
        return ret, bytes.decode(out), bytes.decode(err)

    def test_help_display(self):
        '''verify help displays'''

        cmd = ['apport-valgrind', '-h']
        (ret, out, err) = self._call(cmd)
        self.assertEqual(ret, 0)

    def test_invalid_args(self):
        '''verify return is not 0 when invalid args are passed'''

        cmd = ['apport-valgrind', '-k', 'pwd']
        (ret, out, err) = self._call(cmd)
        self.assertNotEqual(ret, 0)

    def test_vlog_created(self):
        '''verify apport-valgrind creates valgrind.log with expected content'''

        cmd = ['apport-valgrind', '--no-sandbox', 'ls']
        os.chdir(self.workdir)
        subprocess.call(cmd)
        self.assertTrue(
            os.path.exists('valgrind.log'),
            msg='Expected valgrind.log file not found.')
        os.chdir(self.pwd)

    def test_intentional_mem_leak_detection(self):
        '''verify apport-valgrind log reports intentional memory leak'''

        os.chdir(self.workdir)

        # compile memleak.c to create memleak.o that intentionally creates a
        # memory leak
        code = '''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void makeleak(void);

int main(void)
{
    makeleak();
}

void makeleak(void){
    char *leak = malloc(128);
    strcpy(leak, "Initialiazing leak value");
    printf("%s", leak);
    /*free(leak);*/
}'''

        with open('memleak.c', 'w') as fd:
                fd.write(code)
        cmd = ['gcc', '-g', 'memleak.c', '-o', 'memleak.o']
        self.assertEqual(
            subprocess.call(cmd), 0, msg='compiling memleak.c failed.')

        self.assertTrue(
            os.path.exists('memleak.o'),
            msg='memleak.o does not exist but should')

        # run apport-valgrind on the new memleak.o
        cmd = ['apport-valgrind', '--no-sandbox', os.path.join(self.workdir,
               './memleak.o')]
        subprocess.call(cmd)
        logpath = os.path.join(self.workdir, './valgrind.log')

        # verify the generated valgrind.log contains the known leak
        cmd = ['grep', 'definitely lost:', logpath]
        res = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
        res = bytes.decode(res)
        res = res.rstrip('\n')

        found = res.find('128 bytes')
        self.assertTrue(found != -1,
                        msg='The intentional memory leak should be reported '
                        'in the valgrind log file but is not.')
        os.chdir(self.pwd)


unittest.main()
