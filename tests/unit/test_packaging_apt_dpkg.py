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
    def test_is_distro_package_no_candidate(self, apt_cache_mock: MagicMock) -> None:
        """is_distro_package() for package that has no candidate."""
        getitem_mock = apt_cache_mock.return_value.__getitem__
        getitem_mock.return_value = MagicMock(
            spec=apt.Package, installed=None, candidate=None
        )
        self.assertEqual(impl.is_distro_package("adduser"), False)
        getitem_mock.assert_called_once_with("adduser")

    @unittest.mock.patch("apt.Cache", spec=apt.Cache)
    def test_is_distro_package_no_installed_version(
        self, apt_cache_mock: MagicMock
    ) -> None:
        """is_distro_package() for not installed package."""
        getitem_mock = apt_cache_mock.return_value.__getitem__
        getitem_mock.return_value = MagicMock(
            spec=apt.Package,
            installed=MagicMock(spec=apt.package.Version, version=None),
        )
        self.assertEqual(impl.is_distro_package("7zip"), False)
        getitem_mock.assert_called_once_with("7zip")

    @unittest.mock.patch("apt.Cache", spec=apt.Cache)
    def test_is_distro_package_ppa(self, apt_cache_mock: MagicMock) -> None:
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
    def test_is_distro_package_system_image(
        self, apt_cache_mock: MagicMock, exists_mock: MagicMock
    ) -> None:
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
# Some documentation in the beginning

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
    def test_parse_deb822_sources_extra_lines(self, mock_file: MagicMock) -> None:
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

    @unittest.mock.patch.object(impl, "_get_file2pkg_mapping")
    @unittest.mock.patch.object(impl, "_save_contents_mapping", MagicMock())
    def test_get_file_package_uninstalled_usrmerge(
        self, _get_file2pkg_mapping_mock: MagicMock
    ) -> None:
        """get_file_package() on uninstalled usrmerge packages."""
        # Data from Ubuntu 24.04 (noble)
        _get_file2pkg_mapping_mock.return_value = {
            b"usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2": b"libc6",
            b"usr/lib/x86_64-linux-gnu/libc.so.6": b"libc6",
            b"usr/libx32/libc.so.6": b"libc6-x32",
        }

        pkg = impl.get_file_package(
            "/lib/x86_64-linux-gnu/libc.so.6", True, "/map_cachedir", arch="amd64"
        )

        self.assertEqual(pkg, "libc6")
        _get_file2pkg_mapping_mock.assert_called_with(
            "/map_cachedir", impl.get_distro_codename(), "amd64"
        )

    def test_contents_skip_xenial_header(self) -> None:
        """Test _update_given_file2pkg_mapping skipping xenial Contents header."""
        # Header taken from
        # http://archive.ubuntu.com/ubuntu/dists/xenial/Contents-amd64.gz
        contents = b"""\
This file maps each file available in the Ubuntu
system to the package from which it originates.  It includes packages
from the DIST distribution for the ARCH architecture.

You can use this list to determine which package contains a specific
file, or whether or not a specific file is available.  The list is
updated weekly, each architecture on a different day.

When a file is contained in more than one package, all packages are
listed.  When a directory is contained in more than one package, only
the first is listed.

The best way to search quickly for a file is with the Unix `grep'
utility, as in `grep <regular expression> CONTENTS':

 $ grep nose Contents
 etc/nosendfile                                          net/sendfile
 usr/X11R6/bin/noseguy                                   x11/xscreensaver
 usr/X11R6/man/man1/noseguy.1x.gz                        x11/xscreensaver
 usr/doc/examples/ucbmpeg/mpeg_encode/nosearch.param     graphics/ucbmpeg
 usr/lib/cfengine/bin/noseyparker                        admin/cfengine

This list contains files in all packages, even though not all of the
packages are installed on an actual system at once.  If you want to
find out which packages on an installed Debian system provide a
particular file, you can use `dpkg --search <filename>':

 $ dpkg --search /usr/bin/dselect
 dpkg: /usr/bin/dselect


FILE                                                    LOCATION
:sexsend:sexget:					    universe/web/fex
bin/afio						    multiverse/utils/afio
bin/archdetect						    utils/archdetect-deb
"""
        file2pkg: dict[bytes, bytes] = {}
        open_mock = unittest.mock.mock_open(read_data=contents)
        with unittest.mock.patch("gzip.open", open_mock):
            # pylint: disable-next=protected-access
            impl._update_given_file2pkg_mapping(file2pkg, "/fake_Contents", "xenial")

        self.assertEqual(
            file2pkg, {b"bin/afio": b"afio", b"bin/archdetect": b"archdetect-deb"}
        )
        open_mock.assert_called_once_with("/fake_Contents", "rb")
