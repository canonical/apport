# Copyright (C) 2024 Canonical Ltd.
# Author: Simon Chopin <simon.chopin@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Unit tests for apport.crash_impl.launchpad"""

import io
import re
import unittest.mock

from apport.crashdb_impl.launchpad import CrashDatabase, upload_blob
from apport.report import Report


def python_crash() -> Report:
    """Generate a report that looks like a Python crash"""
    report = Report("Crash")
    report["Package"] = "python-goo 3epsilon1"
    report["SourcePackage"] = "pygoo"
    report["PackageArchitecture"] = "all"
    report["DistroRelease"] = "Ubuntu 24.04"
    report["ExecutablePath"] = "/usr/bin/pygoo"
    report[
        "Traceback"
    ] = """Traceback (most recent call last):
  File "test.py", line 7, in <module>
    print(_f(5))
  File "test.py", line 5, in _f
    return g_foo00(x+1)
  File "test.py", line 2, in g_foo00
    return x/0
ZeroDivisionError: integer division or modulo by zero"""
    return report


def native_crash() -> Report:
    """Generate a report that looks like a native binary crash"""
    report = Report("Crash")
    report["Signal"] = "6"
    report["SignalName"] = "SIGABRT"
    report["Package"] = "bash"
    report["SourcePackage"] = "bash"
    report["DistroRelease"] = "Ubuntu 24.04"
    report["PackageArchitecture"] = "i386"
    report["Architecture"] = "amd64"
    report["ExecutablePath"] = "/bin/bash"
    report["CoreDump"] = "/var/lib/apport/coredump/core.bash"
    report["AssertionMessage"] = "foo.c:42 main: i > 0"
    return report


def test_python_crash_headers() -> None:
    # pylint: disable=protected-access
    """Test _generate_upload_headers in case of a Python crash"""
    crashdb = CrashDatabase(None, {"distro": "ubuntu"})
    report = python_crash()
    headers = crashdb._generate_upload_headers(report)

    assert "need-duplicate-check" in headers["Tags"].split(" ")
    assert headers.get("Private") == "yes"


def test_native_crash_headers() -> None:
    # pylint: disable=protected-access
    """Test _generate_upload_headers in case of a native crash"""
    crashdb = CrashDatabase(None, {"distro": "ubuntu"})
    report = native_crash()
    headers = crashdb._generate_upload_headers(report)

    assert "i386" in headers["Tags"].split(" ")
    assert "need-i386-retrace" in headers["Tags"].split(" ")
    assert headers.get("Private") == "yes"


def test_private_bug_headers() -> None:
    # pylint: disable=protected-access
    """Test _generate_upload_headers for a bug in a package for which
    the hook explicitly says it should be private"""
    crashdb = CrashDatabase(None, {"distro": "ubuntu"})
    report = Report("Bug")
    report["Package"] = "apport"
    report["SourcePackage"] = "apport"
    report["PackageArchitecture"] = "all"
    report["Architecture"] = "amd64"
    report["DistroRelease"] = "Ubuntu 24.04"
    report["LaunchpadPrivate"] = "yes"
    headers = crashdb._generate_upload_headers(report)

    assert headers.get("Private") == "yes"
    assert not re.search(r"need-[a-z0-9]+-retrace", headers.get("Tags", ""))


@unittest.mock.patch("urllib.request.build_opener")
def test_upload_blob_conform_to_lp(builder_mock: unittest.mock.MagicMock) -> None:
    """Test that upload_blob does NOT encodes form data with CRLF as line separators,
    despite HTTP 1.1 spec"""
    builder_mock.return_value.open.return_value.info.return_value = {
        "X-Launchpad-Blob-Token": 42
    }

    data = io.BytesIO(b"foobarbaz")
    result = upload_blob(data, hostname="invalid.host")

    builder_mock.assert_called_once()
    builder_mock.return_value.open.assert_called_once()
    req = builder_mock.return_value.open.call_args[0][0]
    assert b"foobarbaz" in req.data
    # Check that we have LF-separated headers (because LP expects LF
    # line separators, see LP: #2097632)
    assert re.match(rb"^([-A-Za-z]+: [^\r\n]+\n)+\n", req.data)
    assert result == 42
