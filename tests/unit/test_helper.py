"""Test test helper functions. Test inception for the win!"""

# pylint: disable=missing-class-docstring,missing-function-docstring

import unittest
from unittest.mock import MagicMock, mock_open, patch

import psutil

from tests.helper import (
    get_init_system,
    wait_for_process_to_appear,
    wait_for_sleeping_state,
    wrap_object,
)


class Multiply:  # pylint: disable=too-few-public-methods
    """Test class for wrap_object test cases."""

    def __init__(self, multiplier: int) -> None:
        self.multiplier = multiplier

    def multiply(self, factor: int) -> int:
        return factor * self.multiplier


class TestTestHelper(unittest.TestCase):
    def test_get_init_systemd(self) -> None:
        open_mock = mock_open(read_data="systemd\n")
        with patch("builtins.open", open_mock):
            self.assertEqual(get_init_system(), "systemd")
        open_mock.assert_called_once_with("/proc/1/comm", encoding="utf-8")

    def test_wrap_object_with_statement(self) -> None:
        with wrap_object(Multiply, "__init__") as mock:
            multiply = Multiply(7)
            self.assertEqual(multiply.multiply(6), 42)
        mock.assert_called_once_with(7)

    @patch("time.sleep")
    @patch("psutil.Process", spec=psutil.Process)
    def test_wait_for_sleeping_state(
        self, process_mock: MagicMock, sleep_mock: MagicMock
    ) -> None:
        """Test wait_for_sleeping_state() helper method."""
        process_mock.return_value.status.side_effect = [
            "not-sleeping",
            "also-not-sleeping",
            "sleeping",
        ]

        wait_for_sleeping_state(1234567890)

        sleep_mock.assert_called_with(0.1)
        self.assertEqual(sleep_mock.call_count, 2)
        self.assertEqual(process_mock.return_value.status.call_count, 3)

    @patch("time.sleep")
    @patch("psutil.Process", spec=psutil.Process)
    def test_wait_for_sleeping_state_timeout(
        self, process_mock: MagicMock, sleep_mock: MagicMock
    ) -> None:
        """Test wait_for_sleeping_state() helper method times out."""
        process_mock.return_value.status.return_value = "never-sleeps"
        with self.assertRaises(TimeoutError):
            wait_for_sleeping_state(1234567890, timeout=10)

        sleep_mock.assert_called_with(0.1)
        self.assertEqual(sleep_mock.call_count, 101)

    @patch("time.sleep")
    @patch("tests.helper.subprocess.check_output")
    def test_wait_for_process_to_appear(
        self, check_output_mock: MagicMock, sleep_mock: MagicMock
    ) -> None:
        """Test wait_for_process_to_appear() helper method."""
        check_output_mock.side_effect = [
            b"100 101 102",  # pre-existing processes
            b"100 101 102 103",  # 103 is new
        ]
        pid: int = wait_for_process_to_appear("/bin/sleep", {100, 101, 102})

        self.assertEqual(pid, 103)
        sleep_mock.assert_called_with(0.1)
        self.assertEqual(sleep_mock.call_count, 1)

    @patch("time.sleep")
    @patch("tests.helper.subprocess.check_output")
    def test_wait_for_process_to_appear_timeout(
        self, check_output_mock: MagicMock, sleep_mock: MagicMock
    ) -> None:
        """Test wait_for_process_to_appear() helper method times out."""
        check_output_mock.return_value = b""
        with self.assertRaises(TimeoutError):
            wait_for_process_to_appear("/bin/sleep", set(), timeout=10)

        sleep_mock.assert_called_with(0.1)
        self.assertEqual(sleep_mock.call_count, 101)

    @patch("time.sleep")
    @patch("tests.helper.subprocess.check_output")
    def test_wait_for_process_to_appear_multiple(
        self, check_output_mock: MagicMock, sleep_mock: MagicMock
    ) -> None:
        """Test wait_for_process_to_appear() helper method raises AssertionError.

        wait_for_process_to_appear expects to find only one PID.
        """
        check_output_mock.side_effect = [
            b"100 101 102",  # pre-existing processes
            b"100 101 102 103 104",  # 103 and 104 are new
        ]
        with self.assertRaises(AssertionError):
            wait_for_process_to_appear("/bin/sleep", {100, 101, 102})

        sleep_mock.assert_called_with(0.1)
        self.assertEqual(sleep_mock.call_count, 1)
