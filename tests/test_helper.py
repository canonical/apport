"""Test test helper functions. Test inception for the win!"""

import os
import sys
import unittest

from tests.helper import pidof


class T(unittest.TestCase):
    def test_pidof_non_existing_program(self):
        self.assertEqual(pidof("non-existing"), set())

    def test_pidof_running_python(self):
        pids = pidof(sys.executable)
        self.assertGreater(len(pids), 0)
        self.assertIn(os.getpid(), pids)


if __name__ == "__main__":
    unittest.main()
