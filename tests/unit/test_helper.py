"""Test test helper functions. Test inception for the win!"""

# pylint: disable=missing-class-docstring,missing-function-docstring

import unittest

from tests.helper import get_init_system, wrap_object


class Multiply:  # pylint: disable=too-few-public-methods
    """Test class for wrap_object test cases."""

    def __init__(self, multiplier):
        self.multiplier = multiplier

    def multiply(self, factor: int) -> int:
        return factor * self.multiplier


class TestTestHelper(unittest.TestCase):
    def test_get_init_systemd(self):
        open_mock = unittest.mock.mock_open(read_data="systemd\n")
        with unittest.mock.patch("builtins.open", open_mock):
            self.assertEqual(get_init_system(), "systemd")
        open_mock.assert_called_once_with("/proc/1/comm", encoding="utf-8")

    def test_wrap_object_with_statement(self):
        with wrap_object(Multiply, "__init__") as mock:
            multiply = Multiply(7)
            self.assertEqual(multiply.multiply(6), 42)
        mock.assert_called_once_with(7)
