"""Test test helper functions. Test inception for the win!"""

import os
import sys
import unittest

from tests.helper import pidof, read_shebang


class TestHelper(unittest.TestCase):
    # pylint: disable=missing-class-docstring,missing-function-docstring

    def test_pidof_non_existing_program(self) -> None:
        self.assertEqual(pidof("non-existing"), set())

    def test_pidof_running_python(self) -> None:
        pids = pidof(sys.executable)
        self.assertGreater(len(pids), 0)
        self.assertIn(os.getpid(), pids)

    def test_read_shebang_binary(self) -> None:
        self.assertIsNone(read_shebang(sys.executable))

    def test_read_shebang_shell_script(self) -> None:
        self.assertEqual(read_shebang("/usr/bin/ldd"), "/bin/bash")
