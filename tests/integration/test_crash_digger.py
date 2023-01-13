"""Test crash-digger"""

# Copyright (C) 2007 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
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
import textwrap
import unittest

import apport.fileutils
from tests.paths import local_test_environment


class T(unittest.TestCase):
    def setUp(self):
        """Set up config dir, crashdb.conf, and apport-retrace for testing"""
        self.env = os.environ | local_test_environment()

        self.workdir = tempfile.mkdtemp()

        crashdb_conf = os.path.join(self.workdir, "crashdb.conf")
        with open(crashdb_conf, "w", encoding="utf-8") as f:
            f.write(
                textwrap.dedent(
                    """\
                    default = "memory"
                    databases = {
                        "memory": {
                            "impl": "memory",
                            "distro": "Testux",
                            "sample_data": "1",
                            "dupdb_url": "%s",
                        },
                        "empty": {"impl": "memory", "distro": "Foonux"},
                    }
                    """
                    % os.path.join(self.workdir, "dupdb")
                )
            )

        self.config_dir = os.path.join(self.workdir, "config")
        os.mkdir(self.config_dir)
        os.mkdir(os.path.join(self.config_dir, "Testux 1.0"))
        os.mkdir(os.path.join(self.config_dir, "Testux 2.2"))

        self.apport_retrace_log = os.path.join(
            self.workdir, "apport-retrace.log"
        )

        self.apport_retrace = os.path.join(self.workdir, "apport-retrace")
        with open(self.apport_retrace, "w", encoding="utf-8") as f:
            f.write(f'#!/bin/sh\necho "$@" >> "{self.apport_retrace_log}"')
        os.chmod(self.apport_retrace, 0o755)

        self.lock_file = os.path.join(self.workdir, "lock")

        self.env["APPORT_CRASHDB_CONF"] = crashdb_conf

        self.orig_report_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = os.path.join(self.workdir, "crashes")
        os.mkdir(apport.fileutils.report_dir)
        self.env["APPORT_REPORT_DIR"] = apport.fileutils.report_dir

    def tearDown(self):
        shutil.rmtree(self.workdir)
        apport.fileutils.report_dir = self.orig_report_dir

    def call(self, args):
        """Call crash-digger with given arguments.

        Return a pair (stdout, stderr).
        """
        crash_digger = subprocess.run(
            ["crash-digger", "--apport-retrace", self.apport_retrace] + args,
            check=False,
            encoding="UTF-8",
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return (crash_digger.stdout, crash_digger.stderr)

    def test_crashes(self):
        """Crash retracing."""
        (out, err) = self.call(
            [
                "-c",
                self.config_dir,
                "-a",
                "/dev/zero",
                "-d",
                os.path.join(self.workdir, "dup.db"),
                "-vl",
                self.lock_file,
            ]
        )
        self.assertEqual(err, "", "no error messages:\n" + err)
        self.assertIn("Available releases: ['Testux 1.0', 'Testux 2.2']", out)
        self.assertIn("retracing #0", out)
        self.assertIn("retracing #1", out)
        self.assertIn("retracing #2", out)
        self.assertIn(
            "crash is release FooLinux Pi/2"
            " which does not have a config available",
            out,
        )
        self.assertNotIn("failed with status", out)
        self.assertNotIn("#3", out, "dupcheck crashes are not retraced")
        self.assertNotIn("#4", out, "dupcheck crashes are not retraced")

        with open(self.apport_retrace_log, encoding="utf-8") as f:
            retrace_log = f.read()
        self.assertEqual(len(retrace_log.splitlines()), 2)
        self.assertNotIn("dup.db -v 0\n", retrace_log)
        self.assertIn("dup.db -v 1\n", retrace_log)
        self.assertIn("dup.db -v 2\n", retrace_log)
        self.assertFalse(os.path.exists(self.lock_file))

        self.assertFalse(
            os.path.isdir(os.path.join(self.workdir, "dupdb", "sig"))
        )

    def test_crashes_error(self):
        """Crash retracing if apport-retrace fails on bug #1."""
        # make apport-retrace fail on bug 1
        os.rename(self.apport_retrace, self.apport_retrace + ".bak")
        with open(self.apport_retrace, "w", encoding="utf-8") as f:
            f.write(
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    echo "$@" >> {self.apport_retrace_log}
                    while [ -n "$2" ]; do shift; done
                    if [ "$1" = 1 ]; then
                        echo "cannot frobnicate bug" >&2
                        exit 1
                    fi
                    """
                )
            )
        os.chmod(self.apport_retrace, 0o755)

        (out, err) = self.call(
            [
                "-c",
                self.config_dir,
                "-a",
                "/dev/zero",
                "-d",
                os.path.join(self.workdir, "dup.db"),
                "-vl",
                self.lock_file,
            ]
        )
        self.assertEqual(err, "")
        self.assertIn("Available releases: ['Testux 1.0', 'Testux 2.2']", out)
        self.assertIn("retracing #0", out)
        self.assertIn("retracing #1", out)
        self.assertIn("retracing #2", out)
        self.assertIn(
            "crash is release FooLinux Pi/2"
            " which does not have a config available",
            out,
        )
        self.assertNotIn("#0 failed with status", out)
        self.assertIn("#1 failed with status: 1", out)
        self.assertNotIn("#3", out, "dupcheck crashes are not retraced")
        self.assertNotIn("#4", out, "dupcheck crashes are not retraced")

        with open(self.apport_retrace_log, encoding="utf-8") as f:
            retrace_log = f.read()
        self.assertEqual(len(retrace_log.splitlines()), 2)
        self.assertNotIn("dup.db -v 0\n", retrace_log)
        self.assertIn("dup.db -v 1\n", retrace_log)
        self.assertIn("dup.db -v 2\n", retrace_log)
        self.assertFalse(os.path.exists(self.lock_file))

        os.rename(self.apport_retrace + ".bak", self.apport_retrace)

    def test_crashes_transient_error(self):
        """Crash retracing if apport-retrace reports a transient error."""
        # make apport-retrace fail on bug 1
        os.rename(self.apport_retrace, self.apport_retrace + ".bak")
        with open(self.apport_retrace, "w", encoding="utf-8") as f:
            f.write(
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    echo "$@" >> {self.apport_retrace_log}
                    while [ -n "$2" ]; do shift; done
                    if [ "$1" = 1 ]; then
                        echo "cannot frobnicate crash db" >&2
                        exit 99
                    fi
                    """
                )
            )
        os.chmod(self.apport_retrace, 0o755)

        out = self.call(
            [
                "-c",
                self.config_dir,
                "-a",
                "/dev/zero",
                "-d",
                os.path.join(self.workdir, "dup.db"),
                "-vl",
                self.lock_file,
            ]
        )[0]
        self.assertIn("Available releases: ['Testux 1.0', 'Testux 2.2']", out)
        self.assertIn("retracing #0", out)
        self.assertIn("retracing #1", out)
        self.assertNotIn(
            "retracing #2", out, "should not continue after errors"
        )
        self.assertIn("transient error reported; halting", out)

        with open(self.apport_retrace_log, encoding="utf-8") as f:
            retrace_log = f.read()
        self.assertIn("dup.db -v 1\n", retrace_log)
        # stops after failing #1
        self.assertNotIn("dup.db -v 2\n", retrace_log)

        self.assertFalse(os.path.exists(self.lock_file))

    def test_dupcheck(self):
        """Duplicate checking."""
        (out, err) = self.call(
            [
                "-a",
                "/dev/zero",
                "-d",
                os.path.join(self.workdir, "dup.db"),
                "-vDl",
                self.lock_file,
            ]
        )
        self.assertEqual(err, "", "no error messages:\n" + err)
        self.assertNotIn("#1", out, "signal crashes are not retraced")
        self.assertNotIn("#2", out, "signal crashes are not retraced")
        self.assertIn("checking #3 for duplicate", out)
        self.assertIn("checking #4 for duplicate", out)
        self.assertIn("Report is a duplicate of #3 (not fixed yet)", out)
        self.assertFalse(os.path.exists(self.apport_retrace_log))
        self.assertFalse(os.path.exists(self.lock_file))

    def test_stderr_redirection(self):
        """apport-retrace's stderr is redirected to stdout."""
        with open(self.apport_retrace, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\necho ApportRetraceError >&2\n")
        (out, err) = self.call(
            [
                "-c",
                self.config_dir,
                "-a",
                "/dev/zero",
                "-d",
                os.path.join(self.workdir, "dup.db"),
                "-vl",
                self.lock_file,
            ]
        )
        self.assertEqual(err, "", "no error messages:\n" + err)
        self.assertIn("ApportRetraceError", out)

    def test_publish_db(self):
        """Duplicate database publishing."""
        (out, err) = self.call(
            [
                "-c",
                self.config_dir,
                "-a",
                "/dev/zero",
                "-d",
                os.path.join(self.workdir, "dup.db"),
                "-vl",
                self.lock_file,
                "--publish-db",
                os.path.join(self.workdir, "dupdb"),
            ]
        )
        self.assertEqual(err, "", "no error messages:\n" + err)
        self.assertIn("retracing #0", out)

        self.assertTrue(
            os.path.isdir(os.path.join(self.workdir, "dupdb", "sig"))
        )

    def test_alternate_crashdb(self):
        """Alternate crash database name."""
        # existing DB "empty" has no crashes
        (out, err) = self.call(
            [
                "-c",
                self.config_dir,
                "-a",
                "/dev/zero",
                "-vl",
                self.lock_file,
                "--crash-db",
                "empty",
            ]
        )
        self.assertEqual(err, "", "no error messages:\n" + err)
        self.assertNotIn("retracing #", out)
        self.assertNotIn("crash is", out)
        self.assertNotIn("failed with status", out)

        # nonexisting DB
        (out, err) = self.call(
            [
                "-c",
                self.config_dir,
                "-a",
                "/dev/zero",
                "-vl",
                self.lock_file,
                "--crash-db",
                "nonexisting",
            ]
        )
        self.assertEqual(out, "", "no output messages:\n" + out)
        self.assertNotIn("Traceback", err)
        self.assertIn("nonexisting", err)
