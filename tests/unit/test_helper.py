"""Test test helper functions. Test inception for the win!"""

import unittest

from tests.helper import get_init_system, wrap_object


class Multiply:
    """Test class for wrap_object test cases."""

    def __init__(self, multiplier):
        self.multiplier = multiplier

    def multiply(self, x: int) -> int:
        return x * self.multiplier


class T(unittest.TestCase):
    def test_get_init_systemd(self):
        open_mock = unittest.mock.mock_open(read_data="systemd\n")
        with unittest.mock.patch("builtins.open", open_mock):
            self.assertEqual(get_init_system(), "systemd")
        open_mock.assert_called_once_with("/proc/1/comm", encoding="utf-8")

    def test_wrap_object_with_statement(self):
        with wrap_object(Multiply, "__init__") as mock:
            m = Multiply(7)
            self.assertEqual(m.multiply(6), 42)
        mock.assert_called_once_with(7)
