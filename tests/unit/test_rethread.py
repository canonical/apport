"""Unit tests for the apport.REThread module."""

import sys
import time
import traceback
import unittest

import apport.REThread


def idle(seconds: float) -> None:
    """Test thread to just wait a bit."""
    time.sleep(seconds)


def div(x: int, y: int) -> float:
    """Test thread to divide two numbers."""
    return x / y


class T(unittest.TestCase):
    """Unit tests for the apport.REThread module."""

    def test_return_value(self) -> None:
        """Return value works properly."""
        t = apport.REThread.REThread(target=div, args=(42, 2))
        t.start()
        t.join()
        # exc_raise() should be a no-op on successful functions
        t.exc_raise()
        self.assertEqual(t.return_value(), 21)
        self.assertIsNone(t.exc_info())

    def test_no_return_value(self) -> None:
        """apport.REThread.REThread works if run() does not return anything."""
        t = apport.REThread.REThread(target=idle, args=(0.5,))
        t.start()
        # thread must be joined first
        self.assertRaises(AssertionError, t.return_value)
        t.join()
        self.assertIsNone(t.return_value())
        self.assertIsNone(t.exc_info())

    def test_exception(self) -> None:
        """Exception in thread is caught and passed."""
        t = apport.REThread.REThread(target=div, args=(1, 0))
        t.start()
        t.join()
        # thread did not terminate normally, no return value
        self.assertRaises(AssertionError, t.return_value)
        self.assertIs(t.exc_info()[0], ZeroDivisionError)
        exc = traceback.format_exception(
            t.exc_info()[0], t.exc_info()[1], t.exc_info()[2]
        )
        self.assertTrue(
            exc[-1].startswith("ZeroDivisionError"),
            f"not a ZeroDivisionError:{str(exc)}",
        )
        self.assertIn("\n    return x / y\n", exc[-2])

    def test_exc_raise(self) -> None:
        """exc_raise() raises caught thread exception."""
        t = apport.REThread.REThread(target=div, args=(1, 0))
        t.start()
        t.join()
        # thread did not terminate normally, no return value
        self.assertRaises(AssertionError, t.return_value)
        raised = False
        try:
            t.exc_raise()
        except ZeroDivisionError:
            raised = True
            error = sys.exc_info()
            exc = traceback.format_exception(error[0], error[1], error[2])
            self.assertIn("\n    return x / y\n", exc[-2])
        self.assertTrue(raised)

    def test_exc_raise_complex(self) -> None:
        """Exceptions that can't be simply created are reraised correctly.

        A unicode error takes several arguments on construction, so trying to
        recreate it by just passing an instance to the class, as the Python 3
        reraise expression did, will fail. See lp:1024836 for details.
        """
        t = apport.REThread.REThread(target=str.encode, args=("\xff", "ascii"))
        t.start()
        t.join()
        self.assertRaises(UnicodeError, t.exc_raise)
