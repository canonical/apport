# Copyright (C) 2012 Canonical Ltd.
# Author: Kyle Nitzsche <kyle.nitzsche@canonica.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import os
import shutil
import subprocess
import tempfile
import unittest

from tests.paths import local_test_environment


@unittest.skipIf(shutil.which("valgrind") is None, "valgrind not installed")
class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = os.environ | local_test_environment()

    def setUp(self):
        self.workdir = tempfile.mkdtemp()
        self.pwd = os.getcwd()

    def tearDown(self):
        shutil.rmtree(self.workdir)
        os.chdir(self.pwd)

    def test_valgrind_min_installed(self):
        """valgrind is installed and recent enough"""

        cmd = ["valgrind", "-q", "--extra-debuginfo-path=./", "ls"]
        (ret, out, err) = self._call(cmd)
        self.assertEqual(err, "")
        self.assertEqual(ret, 0)
        self.assertIn("tests", out)

    def _call(self, argv):
        process = subprocess.run(
            argv,
            check=False,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return (process.returncode, process.stdout, process.stderr)

    def test_help_display(self):
        """help display"""

        cmd = ["apport-valgrind", "-h"]
        (ret, out, err) = self._call(cmd)
        self.assertEqual(err, "")
        self.assertEqual(ret, 0)
        self.assertIn("--help", out)

    def test_invalid_args(self):
        """return code is not 0 when invalid args are passed"""

        cmd = ["apport-valgrind", "-k", "pwd"]
        (ret, out, err) = self._call(cmd)
        self.assertEqual(out, "")
        self.assertNotEqual(ret, 0)
        self.assertIn("unrecognized arguments: -k", err)

    def test_vlog_created(self):
        """apport-valgrind creates valgrind.log with expected content"""

        cmd = ["apport-valgrind", "--no-sandbox", "true"]
        os.chdir(self.workdir)
        self.assertEqual(self._call(cmd), (0, "", ""))
        self.assertTrue(
            os.path.exists("valgrind.log"),
            msg="Expected valgrind.log file not found.",
        )

    def test_intentional_mem_leak_detection(self):
        """apport-valgrind log reports intentional memory leak"""

        os.chdir(self.workdir)

        # compile memleak.c to create memleak.o that intentionally creates a
        # memory leak
        code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void makeleak(void);

int main(void)
{
    makeleak();
    return 0;
}

void makeleak(void){
    char *leak = malloc(128);
    strcpy(leak, "Initializing leak value");
    /*free(leak);*/
}"""

        with open("memleak.c", "w", encoding="utf-8") as fd:
            fd.write(code)
        cmd = ["gcc", "-Wall", "-Werror", "-g", "memleak.c", "-o", "memleak"]
        self.assertEqual(
            subprocess.call(cmd), 0, "compiling memleak.c failed."
        )

        self.assertTrue(os.path.exists("memleak"))

        # run apport-valgrind on the new memleak.o
        cmd = [
            "apport-valgrind",
            "--no-sandbox",
            os.path.join(self.workdir, "./memleak"),
        ]
        self.assertEqual(self._call(cmd), (0, "", ""))
        logpath = os.path.join(self.workdir, "./valgrind.log")

        # verify the generated valgrind.log contains the known leak
        cmd = ["grep", "definitely lost:", logpath]
        ret, res, err = self._call(cmd)
        self.assertEqual(err, "")
        self.assertEqual(ret, 0)
        res = res.rstrip("\n")

        found = res.find("128 bytes")
        self.assertGreater(
            found,
            0,
            "The intentional memory leak should be reported "
            "in the valgrind log file but is not.",
        )

    def test_unpackaged_exe(self):
        """apport-valgrind creates valgrind log on unpackaged executable"""

        exepath = os.path.join(self.workdir, "pwd")
        shutil.copy("/bin/pwd", exepath)
        logpath = os.path.join(self.workdir, "unpackaged-exe.log")

        cmd = ["apport-valgrind", "--no-sandbox", "-l", logpath, exepath]
        self.assertEqual(self._call(cmd), (0, os.getcwd() + "\n", ""))
        self.assertTrue(
            os.path.exists(logpath),
            "A log file %s should exist but does not" % logpath,
        )

        with open(logpath, encoding="utf-8") as f:
            log = f.read()
            self.assertIn(exepath, log)
