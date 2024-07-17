"""Test test helper functions. Test inception for the win!"""

import os
import sys
import unittest

from tests.helper import pids_of, read_shebang


class TestHelper(unittest.TestCase):
    # pylint: disable=missing-class-docstring,missing-function-docstring

    def test_pids_of_non_existing_program(self) -> None:
        self.assertEqual(pids_of("non-existing"), set())

    def test_pids_of_running_python(self) -> None:
        pids = pids_of(sys.executable)
        self.assertGreater(len(pids), 0)
        self.assertIn(os.getpid(), pids)

    def test_read_shebang_binary(self) -> None:
        self.assertIsNone(read_shebang(sys.executable))

    def test_read_shebang_shell_script(self) -> None:
        self.assertEqual(read_shebang("/usr/bin/ldd"), "/bin/bash")
