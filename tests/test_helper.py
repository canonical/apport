"""Test test helper functions. Test inception for the win!"""

import os
import sys
import unittest

from tests.helper import pidof, read_shebang, wrap_object


class Multiply:
    """Test class for wrap_object test cases."""

    def __init__(self, multiplier):
        self.multiplier = multiplier

    def multiply(self, x: int) -> int:
        return x * self.multiplier


class T(unittest.TestCase):
    def test_pidof_non_existing_program(self):
        self.assertEqual(pidof("non-existing"), set())

    def test_pidof_running_python(self):
        pids = pidof(sys.executable)
        self.assertGreater(len(pids), 0)
        self.assertIn(os.getpid(), pids)

    def test_read_shebang_binary(self):
        self.assertEqual(read_shebang(sys.executable), None)

    def test_read_shebang_shell_script(self):
        self.assertEqual(read_shebang("/usr/bin/ldd"), "/bin/bash")

    def test_wrap_object_with_statement(self):
        with wrap_object(Multiply, "__init__") as mock:
            m = Multiply(7)
            self.assertEqual(m.multiply(6), 42)
        mock.assert_called_once_with(7)
