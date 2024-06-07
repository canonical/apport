# Copyright (C) 2023 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for apport.sandboxutils."""

import os
import tempfile
import unittest
import unittest.mock
from unittest.mock import MagicMock

from apport.packaging import PackageInfo
from apport.report import Report
from apport.sandboxutils import _move_or_add_base_files_first, make_sandbox


class TestSandboxutils(unittest.TestCase):
    """Unit tests for apport.sandboxutils."""

    @staticmethod
    def _get_sample_report() -> Report:
        report = Report()
        report["Architecture"] = "amd64"
        report["DistroRelease"] = "Ubuntu 22.04"
        report["ExecutablePath"] = "/bin/bash"
        report["Signal"] = "11"
        return report

    @unittest.mock.patch("apport.sandboxutils.packaging", spec=PackageInfo)
    def test_make_sandbox(self, packaging_mock: MagicMock) -> None:
        """make_sandbox() for a sample report."""
        packaging_mock.install_packages.return_value = "obsolete\n"
        report = self._get_sample_report()
        sandbox, cache, outdated_msg = make_sandbox(report, "system")
        self.assertTrue(os.path.exists(sandbox), f"'{sandbox}' does not exist")
        self.assertTrue(os.path.exists(cache), f"'{cache}' does not exist")
        self.assertEqual(outdated_msg, "obsolete\nobsolete\n")
        self.assertEqual(packaging_mock.install_packages.call_count, 2)

    @unittest.mock.patch("apport.sandboxutils.packaging", spec=PackageInfo)
    def test_make_sandbox_install_packages_failure(
        self, packaging_mock: MagicMock
    ) -> None:
        """make_sandbox() where packaging.install_packages fails."""
        packaging_mock.install_packages.side_effect = SystemError("100% fail")
        with self.assertRaises(SystemExit):
            make_sandbox(self._get_sample_report(), "system")
        packaging_mock.install_packages.assert_called_once()

    @unittest.mock.patch("apport.sandboxutils.packaging", spec=PackageInfo)
    def test_make_sandbox_with_sandbox_dir(self, packaging_mock: MagicMock) -> None:
        """make_sandbox() with sandbox_dir set."""
        packaging_mock.install_packages.return_value = "obsolete\n"
        with tempfile.TemporaryDirectory(dir="/var/tmp") as tmpdir:
            config_dir = os.path.join(tmpdir, "config")
            cache_dir = os.path.join(tmpdir, "cache")
            sandbox_dir = os.path.join(tmpdir, "sandbox")
            sandbox, cache, outdated_msg = make_sandbox(
                self._get_sample_report(),
                config_dir,
                cache_dir=cache_dir,
                sandbox_dir=sandbox_dir,
            )
            self.assertEqual(sandbox, sandbox_dir)
            self.assertEqual(cache, cache_dir)
        self.assertEqual(outdated_msg, "obsolete\nobsolete\n")
        self.assertEqual(packaging_mock.install_packages.call_count, 2)

    def test_move_or_add_base_files_first_existing(self) -> None:
        """_move_or_add_base_files_first() with base-files in list."""
        pkgs: list[tuple[str, None | str]] = [
            ("chaos-marmosets", "0.1.2-2"),
            ("base-files", "13ubuntu9"),
            ("libc6", "2.39-0ubuntu8.2"),
        ]
        _move_or_add_base_files_first(pkgs)
        self.assertEqual(
            pkgs,
            [
                ("base-files", "13ubuntu9"),
                ("chaos-marmosets", "0.1.2-2"),
                ("libc6", "2.39-0ubuntu8.2"),
            ],
        )

    def test_move_or_add_base_files_first_missing(self) -> None:
        """_move_or_add_base_files_first() without base-files in list."""
        pkgs: list[tuple[str, None | str]] = [
            ("chaos-marmosets", "0.1.2-2"),
            ("libc6", "2.39-0ubuntu8.2"),
        ]
        _move_or_add_base_files_first(pkgs)
        self.assertEqual(
            pkgs,
            [
                ("base-files", None),
                ("chaos-marmosets", "0.1.2-2"),
                ("libc6", "2.39-0ubuntu8.2"),
            ],
        )
