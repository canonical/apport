# Copyright (C) 2022 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Command line Apport user interface tests."""

import os
import unittest

import apport.report
from tests.helper import import_module_from_file, skip_if_command_is_missing
from tests.paths import is_local_source_directory, local_test_environment

if is_local_source_directory():
    apport_cli_path = "bin/apport-cli"
else:
    apport_cli_path = "/usr/bin/apport-cli"
apport_cli = import_module_from_file(apport_cli_path)


class TestApportCli(unittest.TestCase):
    """Test apport-cli."""

    @classmethod
    def setUpClass(cls):
        cls.orig_environ = os.environ.copy()
        os.environ |= local_test_environment()

    @classmethod
    def tearDownClass(cls):
        os.environ.clear()
        os.environ.update(cls.orig_environ)

    def setUp(self):
        self.app = apport_cli.CLIUserInterface([apport_cli_path])
        self.app.report = apport.report.Report()
        self.app.report.add_os_info()
        self.app.report["ExecutablePath"] = "/bin/bash"
        self.app.report["Signal"] = "11"
        self.app.report["CoreDump"] = b"\x01\x02"

    @skip_if_command_is_missing("/usr/bin/sensible-pager")
    def test_ui_update_view(self):
        read_fd, write_fd = os.pipe()
        with os.fdopen(write_fd, "w", buffering=1) as stdout:
            self.app.ui_update_view(stdout=stdout)
        with os.fdopen(read_fd, "r") as pipe:
            report = pipe.read()
        self.assertIn(
            "== ExecutablePath =================================\n"
            "/bin/bash\n\n"
            "== ProblemType =================================\n"
            "Crash\n\n"
            "== Signal =================================\n"
            "11\n\n",
            report,
        )
