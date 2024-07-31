# Copyright (C) 2022 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for apport.packaging_impl.apt_dpkg."""

import pathlib
import sqlite3
import tempfile
import unittest
import unittest.mock
from unittest.mock import MagicMock

import apt
import apt.package

from apport.packaging_impl.apt_dpkg import (
    _map_mirror_to_arch,
    _parse_deb822_sources,
    _Path2Package,
    _read_mirror_file,
    impl,
)


@unittest.mock.patch(
    "apport.packaging_impl.apt_dpkg._AptDpkgPackageInfo.get_os_version",
    MagicMock(return_value=("Ubuntu", "22.04")),
)
class TestPackagingAptDpkg(unittest.TestCase):
    """Unit tests for apport.packaging_impl.apt_dpkg."""

    maxDiff = None

    def setUp(self) -> None:
        # Clear APT cache to allow mocking it
        # pylint: disable-next=protected-access
        impl._apt_cache = None

    def tearDown(self) -> None:
        # Clear APT cache to clear cached mocks
        # pylint: disable-next=protected-access
        impl._apt_cache = None

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

    def test_map_mirror_to_arch_ports_to_primary(self) -> None:
        """Test _map_mirror_to_arch() to map ports to primary."""
        self.assertEqual(
            _map_mirror_to_arch("http://de.ports.ubuntu.com/ubuntu-ports", "amd64"),
            "http://de.archive.ubuntu.com/ubuntu",
        )

    def test_map_mirror_to_arch_ports_unchanged(self) -> None:
        """Test _map_mirror_to_arch() to keep ports unchanged."""
        uri = "http://de.ports.ubuntu.com/ubuntu-ports"
        self.assertEqual(_map_mirror_to_arch(uri, "ppc64el"), uri)

    def test_map_mirror_to_arch_primary_to_ports(self) -> None:
        """Test _map_mirror_to_arch() to map primary to ports."""
        self.assertEqual(
            _map_mirror_to_arch("http://de.archive.ubuntu.com/ubuntu/", "s390x"),
            "http://de.ports.ubuntu.com/ubuntu-ports",
        )

    def test_map_mirror_to_arch_primary_unchanged(self) -> None:
        """Test _map_mirror_to_arch() to keep ports unchanged."""
        uri = "http://de.archive.ubuntu.com/ubuntu"
        self.assertEqual(_map_mirror_to_arch(uri, "amd64"), uri)

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
    def test_get_file_package_uninstalled_usrmerge(
        self, _get_file2pkg_mapping_mock: MagicMock
    ) -> None:
        """get_file_package() on uninstalled usrmerge packages."""
        # Data from Ubuntu 24.04 (noble)
        _get_file2pkg_mapping_mock.return_value = {
            "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2": "libc6",
            "usr/lib/x86_64-linux-gnu/libc.so.6": "libc6",
            "usr/libx32/libc.so.6": "libc6-x32",
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
        contents = """\
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
        file2pkg = _Path2Package()
        open_mock = unittest.mock.mock_open(read_data=contents)
        with unittest.mock.patch("gzip.open", open_mock):
            file2pkg.update_from_contents_file("/fake_Contents", "xenial", 2)

        self.assertEqual(
            dict(file2pkg), {"bin/afio": "afio", "bin/archdetect": "archdetect-deb"}
        )
        open_mock.assert_called_once_with("/fake_Contents", "rt")

    def test_contents_path_filering(self) -> None:
        """Test _update_given_file2pkg_mapping to ignore unrelevant files."""
        # Test content taken from
        # http://archive.ubuntu.com/ubuntu/dists/noble/Contents-amd64.gz
        contents = """\
bin/ip							    net/iproute2
boot/ipxe.efi						    admin/grub-ipxe
etc/dput.cf						    devel/dput
lib/nut/clone						    admin/nut-server
sbin/hdparm						    admin/hdparm
usr/Brother/inf/braddprinter				    multiverse/text/brother-lpr-drivers-laser
usr/aarch64-linux-gnu/include/ar.h			    libdevel/libc6-dev-arm64-cross
usr/bin/git						    vcs/git
usr/bin/xz						    utils/xz-utils
usr/games/etr						    universe/games/extremetuxracer
usr/include/apache2/os.h				    httpd/apache2-dev
usr/include/x86_64-linux-gnu/bits/endian.h		    libdevel/libc6-dev
usr/lib/7zip/7z.so					    universe/utils/7zip
usr/lib/debug/.build-id/31/1c9c9b30d6991fb903ab459173c66eb8e7e895.debug debug/libc6-dbg
usr/libexec/coreutils/libstdbuf.so			    utils/coreutils
usr/libx32/ld.so					    libs/libc6-x32
usr/sbin/zic						    libs/libc-bin
usr/share/dicom3tools/gen.so				    universe/graphics/dicom3tools
usr/share/doc/0install					    universe/admin/0install
usr/share/gocode/src/launchpad.net/mgo			    universe/devel/golang-gopkg-mgo.v2-dev
usr/share/help/C/eog/default.page			    gnome/eog
usr/share/icons/gnome-colors-common/32x32/apps/konsole.png\
  universe/gnome/gnome-colors-common
usr/share/locale/de/LC_MESSAGES/apt.mo			    admin/apt
usr/share/man/de/man1/man.1.gz				    doc/man-db
usr/share/texlive/index.html				    universe/tex/texlive-base
usr/src/broadcom-sta.tar.xz				    restricted/admin/broadcom-sta-source
var/lib/ieee-data/iab.txt				    net/ieee-data
"""

        file2pkg = _Path2Package()
        open_mock = unittest.mock.mock_open(read_data=contents)
        with unittest.mock.patch("gzip.open", open_mock):
            file2pkg.update_from_contents_file("Contents-amd64", "noble", 10)

        self.assertEqual(
            dict(file2pkg),
            {
                "bin/ip": "iproute2",
                "etc/dput.cf": "dput",
                "lib/nut/clone": "nut-server",
                "sbin/hdparm": "hdparm",
                "usr/Brother/inf/braddprinter": "brother-lpr-drivers-laser",
                "usr/bin/git": "git",
                "usr/lib/debug/.build-id/31/1c9c9b30d6991fb903ab459173c66eb8e7e895"
                ".debug": "libc6-dbg",
                "usr/bin/xz": "xz-utils",
                "usr/games/etr": "extremetuxracer",
                "usr/lib/7zip/7z.so": "7zip",
                "usr/libexec/coreutils/libstdbuf.so": "coreutils",
                "usr/libx32/ld.so": "libc6-x32",
                "usr/sbin/zic": "libc-bin",
                "usr/share/dicom3tools/gen.so": "dicom3tools",
            },
        )
        open_mock.assert_called_once_with("Contents-amd64", "rt")

    def test_contents_parse_path_with_spaces(self) -> None:
        """Test _update_given_file2pkg_mapping to parse Contents file correctly."""
        # Test content taken from
        # http://archive.ubuntu.com/ubuntu/dists/noble/Contents-amd64.gz
        contents = (
            "usr/lib/iannix/Tools/JavaScript Library.js\t\t    "
            "universe/sound/iannix\n"
            "usr/lib/python3/dist-packages/ilorest/extensions/BIOS COMMANDS"
            "/__init__.py universe/python/ilorest\n"
        )

        file2pkg = _Path2Package()
        open_mock = unittest.mock.mock_open(read_data=contents)
        with unittest.mock.patch("gzip.open", open_mock):
            file2pkg.update_from_contents_file("Contents-amd64", "noble")

        self.assertEqual(
            dict(file2pkg),
            {
                "usr/lib/iannix/Tools/JavaScript Library.js": "iannix",
                "usr/lib/python3/dist-packages/ilorest/extensions/BIOS COMMANDS"
                "/__init__.py": "ilorest",
            },
        )
        open_mock.assert_called_once_with("Contents-amd64", "rt")

    def test_path2package(self) -> None:
        """Basic tests for _Path2Package class."""
        path2package = _Path2Package()
        self.assertEqual(dict(path2package), {})
        self.assertEqual(len(path2package), 0)
        self.assertTrue(path2package.is_empty())
        path2package["usr/bin/man"] = "man-db"
        path2package["bin/ip"] = "iproute2"
        self.assertEqual(
            dict(path2package), {"bin/ip": "iproute2", "usr/bin/man": "man-db"}
        )
        self.assertEqual(len(path2package), 2)
        self.assertEqual(path2package["bin/ip"], "iproute2")
        self.assertEqual(path2package.get("usr/bin/man"), "man-db")
        self.assertIsNone(path2package.get("usr/src/broadcom-sta.tar.xz"))
        self.assertFalse(path2package.is_empty())
        self.assertIn("bin/ip", path2package)
        self.assertNotIn("usr/bin/git", path2package)
        self.assertNotIn(42, path2package)

    def test_path2package_overwrite(self) -> None:
        """Test _Path2Package to overwrite existing values."""
        path2package = _Path2Package()
        path2package["path/to/file"] = "package1"
        self.assertEqual(path2package["path/to/file"], "package1")
        path2package["path/to/file"] = "package2"
        self.assertEqual(path2package["path/to/file"], "package2")

    def test_path2package_create_and_reopen(self) -> None:
        """Test _Path2Package for openening an existing database."""
        with tempfile.NamedTemporaryFile(suffix=".sqlite3") as db_file:
            path2package = _Path2Package(pathlib.Path(db_file.name))
            self.assertEqual(dict(path2package), {})
            self.assertTrue(path2package.is_empty())
            path2package["bin/ip"] = "iproute2"
            path2package.connection.commit()
            del path2package

            path2package = _Path2Package(pathlib.Path(db_file.name))
            self.assertEqual(dict(path2package), {"bin/ip": "iproute2"})
            self.assertFalse(path2package.is_empty())

    @unittest.mock.patch("sqlite3.connect")
    def test_path2package_clean_deletion_on_failure(
        self, connect_mock: MagicMock
    ) -> None:
        """Test clean _Path2Package deletion on __init__ failure."""
        connect_mock.side_effect = sqlite3.OperationalError
        with self.assertRaises(sqlite3.OperationalError):
            _Path2Package(pathlib.Path("/non-existing.sqlite3"))


class TestPackaging(unittest.TestCase):
    """Unit tests for apport.packaging.PackageInfo class."""

    def setUp(self) -> None:
        # pylint: disable-next=protected-access
        impl._os_version = None

    def tearDown(self) -> None:
        # pylint: disable-next=protected-access
        impl._os_version = None

    @unittest.mock.patch("platform.freedesktop_os_release")
    def test_get_os_version_debian_testing(self, os_release_mock: MagicMock) -> None:
        """Test get_os_version() for Debian testing (no VERSION_ID set)."""
        # platform.freedesktop_os_release() data from base-files 13.7
        os_release_mock.return_value = {
            "NAME": "Debian GNU/Linux",
            "ID": "debian",
            "PRETTY_NAME": "Debian GNU/Linux trixie/sid",
            "VERSION_CODENAME": "trixie",
            "HOME_URL": "https://www.debian.org/",
            "SUPPORT_URL": "https://www.debian.org/support",
            "BUG_REPORT_URL": "https://bugs.debian.org/",
        }
        self.assertEqual(impl.get_os_version(), ("Debian", "n/a"))
        os_release_mock.assert_called_once_with()
