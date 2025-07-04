# Copyright (C) 2012 Canonical Ltd.
# Author: Kyle Nitzsche <kyle.nitzsche@canonica.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""System tests for bin/apport-valgrind."""

import os
import shutil
import subprocess
import tempfile
import unittest

from tests.helper import get_gnu_coreutils_cmd, skip_if_command_is_missing
from tests.paths import local_test_environment

with open("/proc/meminfo", encoding="utf-8") as f:
    for line in f.readlines():
        if line.startswith("MemTotal"):
            MEM_TOTAL_MiB = int(line.split()[1]) // 1024
            break


@skip_if_command_is_missing("valgrind")
class TestApportValgrind(unittest.TestCase):
    """System tests for bin/apport-valgrind."""

    env: dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.env = os.environ | local_test_environment()

    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp()
        self.pwd = os.getcwd()

    def tearDown(self) -> None:
        shutil.rmtree(self.workdir)
        os.chdir(self.pwd)

    @unittest.skipIf(MEM_TOTAL_MiB < 2000, f"{MEM_TOTAL_MiB} MiB is not enough memory")
    def test_sandbox_cache_options(self) -> None:
        """apport-valgrind creates a user specified sandbox and cache"""
        sandbox = os.path.join(self.workdir, "test-sandbox")
        cache = os.path.join(self.workdir, "test-cache")

        cmd = [
            "apport-valgrind",
            "--sandbox-dir",
            sandbox,
            "--cache",
            cache,
            get_gnu_coreutils_cmd("true"),
        ]
        subprocess.check_call(cmd, env=self.env)

        self.assertTrue(
            os.path.exists(sandbox),
            f"A sandbox directory {sandbox} was specified but was not created",
        )

        self.assertTrue(
            os.path.exists(cache),
            f"A cache directory {cache} was specified but was not created",
        )
