# Copyright (C) 2022 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

"""Integration tests for whoopsie-upload-all."""

import io
import os
import shutil
import socket
import tempfile
import unittest
import unittest.mock
from unittest.mock import MagicMock

from tests.helper import import_module_from_file
from tests.paths import get_data_directory

whoopsie_upload_all = import_module_from_file(
    get_data_directory() / "whoopsie-upload-all"
)


class TestWhoopsieUploadAll(unittest.TestCase):
    """Integration tests for whoopsie-upload-all."""

    def setUp(self) -> None:
        self.report_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.report_dir)

    def _write_report(self, content: bytes) -> str:
        report = os.path.join(self.report_dir, "testcase.crash")
        with open(report, "wb") as report_file:
            report_file.write(content)
        return report

    @unittest.mock.patch("sys.stderr", new_callable=io.StringIO)
    def test_process_report_malformed_report(self, stderr_mock: MagicMock) -> None:
        """Test process_report() raises MalformedProblemReport."""
        report = self._write_report(b"AB\xfc:CD\n")
        self.assertIsNone(whoopsie_upload_all.process_report(report))
        self.assertIn(
            "Malformed problem report: 'ascii' codec can't decode byte 0xfc"
            " in position 2: ordinal not in range(128).",
            stderr_mock.getvalue(),
        )

    @unittest.mock.patch("time.sleep")
    def test_wait_uploaded_timeout(self, sleep_mock: MagicMock) -> None:
        """Test wait_uploaded() gives up once the timeout has passed."""
        stamp = os.path.join(self.report_dir, "testcase.upload")
        with open(stamp, "w", encoding="utf-8"):
            pass
        self.assertFalse(whoopsie_upload_all.wait_uploaded({stamp}, 25))
        self.assertEqual(
            sleep_mock.call_args_list,
            [unittest.mock.call(10), unittest.mock.call(10), unittest.mock.call(5)],
        )

    def _notify_socket(self, address: str) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.bind(address)
        sock.settimeout(5)
        return sock

    def test_notify_ready(self) -> None:
        """Test notify_ready() sends READY=1 to NOTIFY_SOCKET."""
        address = os.path.join(self.report_dir, "notify")
        sock = self._notify_socket(address)
        with unittest.mock.patch.dict("os.environ", {"NOTIFY_SOCKET": address}):
            whoopsie_upload_all.notify_ready()
        self.assertEqual(sock.recv(64), b"READY=1")

    def test_notify_ready_abstract_socket(self) -> None:
        """Test notify_ready() with an abstract NOTIFY_SOCKET."""
        name = f"apport-test-{os.getpid()}"
        sock = self._notify_socket(f"\0{name}")
        with unittest.mock.patch.dict("os.environ", {"NOTIFY_SOCKET": f"@{name}"}):
            whoopsie_upload_all.notify_ready()
        self.assertEqual(sock.recv(64), b"READY=1")

    def test_notify_ready_without_socket(self) -> None:
        """Test notify_ready() does nothing without NOTIFY_SOCKET."""
        with (
            unittest.mock.patch.dict("os.environ"),
            unittest.mock.patch("socket.socket") as socket_mock,
        ):
            os.environ.pop("NOTIFY_SOCKET", None)
            whoopsie_upload_all.notify_ready()
        self.assertFalse(socket_mock.called)

    @unittest.mock.patch("sys.argv", ["whoopsie-upload-all", "--timeout", "20"])
    @unittest.mock.patch("subprocess.call", MagicMock(return_value=0))
    def test_main_notifies_before_waiting(self) -> None:
        """Test main() reports the service as started before waiting."""
        stamp = os.path.join(self.report_dir, "testcase.upload")
        calls = MagicMock()
        with (
            unittest.mock.patch("apport.fileutils.report_dir", self.report_dir),
            unittest.mock.patch.object(
                whoopsie_upload_all, "collect_info", return_value={stamp}
            ),
            unittest.mock.patch.object(
                whoopsie_upload_all, "notify_ready", calls.notify_ready
            ),
            unittest.mock.patch.object(
                whoopsie_upload_all, "wait_uploaded", calls.wait_uploaded
            ),
        ):
            calls.wait_uploaded.return_value = True
            whoopsie_upload_all.main()
        self.assertEqual(
            calls.mock_calls,
            [
                unittest.mock.call.notify_ready(),
                unittest.mock.call.wait_uploaded({stamp}, 20),
            ],
        )

    @unittest.mock.patch("sys.argv", ["whoopsie-upload-all", "--timeout", "20"])
    @unittest.mock.patch("subprocess.call", MagicMock(return_value=0))
    def test_main_notifies_without_reports(self) -> None:
        """Test main() reports the service as started without any report."""
        with (
            unittest.mock.patch.object(
                whoopsie_upload_all, "collect_info", return_value=set()
            ),
            unittest.mock.patch.object(
                whoopsie_upload_all, "notify_ready"
            ) as notify_ready_mock,
        ):
            whoopsie_upload_all.main()
        self.assertEqual(notify_ready_mock.mock_calls, [unittest.mock.call()])
