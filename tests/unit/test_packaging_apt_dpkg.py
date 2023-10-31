# Copyright (C) 2022 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for apport.packaging_impl.apt_dpkg."""

import tempfile
import unittest
import unittest.mock
from unittest.mock import MagicMock

import apt

from apport.packaging_impl.apt_dpkg import (
    WITH_DEB822_SUPPORT,
    _parse_deb822_sources,
    _read_mirror_file,
    impl,
)


@unittest.mock.patch(
    "apport.packaging_impl.apt_dpkg.__AptDpkgPackageInfo.get_os_version",
    MagicMock(return_value=("Ubuntu", "22.04")),
)
class TestPackagingAptDpkg(unittest.TestCase):
    """Unit tests for apport.packaging_impl.apt_dpkg."""

    @unittest.mock.patch("apt.Cache", spec=apt.Cache)
    def test_is_distro_package_no_candidate(self, apt_cache_mock):
        """is_distro_package() for package that has no candidate."""
        getitem_mock = apt_cache_mock.return_value.__getitem__
        getitem_mock.return_value = MagicMock(
            spec=apt.Package, installed=None, candidate=None
        )
        self.assertEqual(impl.is_distro_package("adduser"), False)
        getitem_mock.assert_called_once_with("adduser")

    @unittest.mock.patch("apt.Cache", spec=apt.Cache)
    def test_is_distro_package_no_installed_version(self, apt_cache_mock):
        """is_distro_package() for not installed package."""
        getitem_mock = apt_cache_mock.return_value.__getitem__
        getitem_mock.return_value = MagicMock(
            spec=apt.Package,
            installed=MagicMock(spec=apt.package.Version, version=None),
        )
        self.assertEqual(impl.is_distro_package("7zip"), False)
        getitem_mock.assert_called_once_with("7zip")

    @unittest.mock.patch("apt.Cache", spec=apt.Cache)
    def test_is_distro_package_ppa(self, apt_cache_mock):
        """is_distro_package() for a PPA package."""
        version = MagicMock(
            spec=apt.package.Version,
            origins=[MagicMock(spec=apt.package.Origin, origin="LP-PPA")],
            version="0.5.0-0ppa1",
        )
        getitem_mock = apt_cache_mock.return_value.__getitem__
        getitem_mock.return_value = MagicMock(
            spec=apt.Package, candidate=version, installed=version
        )
        self.assertEqual(impl.is_distro_package("bdebstrap"), False)
        getitem_mock.assert_called_once_with("bdebstrap")

    @unittest.mock.patch("os.path.exists")
    @unittest.mock.patch("apt.Cache", spec=apt.Cache)
    def test_is_distro_package_system_image(self, apt_cache_mock, exists_mock):
        """is_distro_package() for a system image without cache."""
        version = MagicMock(
            spec=apt.package.Version,
            origins=[MagicMock(spec=apt.package.Origin, origin="")],
            version="2.23.1-0ubuntu4",
        )
        getitem_mock = apt_cache_mock.return_value.__getitem__
        getitem_mock.return_value = MagicMock(
            spec=apt.Package, candidate=version, installed=version
        )
        exists_mock.return_value = True
        self.assertEqual(impl.is_distro_package("apport"), True)
        getitem_mock.assert_called_once_with("apport")
        exists_mock.assert_called_once_with("/etc/system-image/channel.ini")

    @unittest.skipIf(not WITH_DEB822_SUPPORT, "no deb822 support")
    @unittest.mock.patch(
        "builtins.open",
        new_callable=unittest.mock.mock_open,
        read_data="""
Types: deb deb-src
URIs: http://example.com
Suites: foo foo-bar
Components: main


Types: deb
URIs: http://example2.com
Suites:
 baz
Components: main


""",
    )
    def test_parse_deb822_sources_extra_lines(self, mock_file):
        """Test _parse_deb822_sources with multiple lines separating blocks."""
        entries = _parse_deb822_sources("foo_bar.sources")
        mock_file.assert_called_with("foo_bar.sources", encoding="utf-8")
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].uris[0], "http://example.com")
        self.assertEqual(entries[1].suites[0], "baz")

    def test_read_mirror_file(self) -> None:
        """Test _read_mirror_file with config from GitHub CI."""
        with tempfile.NamedTemporaryFile("w") as mirror_file:
            mirror_file.write(
                "http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n"
                "http://archive.ubuntu.com/ubuntu/\tpriority:2\n"
                "http://security.ubuntu.com/ubuntu/\tpriority:3\n"
            )
            mirror_file.flush()
            mirrors = _read_mirror_file(f"mirror+file:{mirror_file.name}")
        self.assertEqual(
            mirrors,
            [
                "http://azure.archive.ubuntu.com/ubuntu/",
                "http://archive.ubuntu.com/ubuntu/",
                "http://security.ubuntu.com/ubuntu/",
            ],
        )
