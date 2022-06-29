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

with open("/proc/meminfo") as f:
    for line in f.readlines():
        if line.startswith("MemTotal"):
            MEM_TOTAL_MiB = int(line.split()[1]) // 1024
            break


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

    @unittest.skipIf(
        MEM_TOTAL_MiB < 2000, f"{MEM_TOTAL_MiB} MiB is not enough memory"
    )
    def test_sandbox_cache_options(self):
        """apport-valgrind creates a user specified sandbox and cache"""

        sandbox = os.path.join(self.workdir, "test-sandbox")
        cache = os.path.join(self.workdir, "test-cache")

        cmd = [
            "apport-valgrind",
            "--sandbox-dir",
            sandbox,
            "--cache",
            cache,
            "/bin/true",
        ]
        subprocess.check_call(cmd, env=self.env)

        self.assertTrue(
            os.path.exists(sandbox),
            "A sandbox directory %s was specified but was not created"
            % sandbox,
        )

        self.assertTrue(
            os.path.exists(cache),
            "A cache directory %s was specified but was not created" % cache,
        )
