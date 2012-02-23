import unittest, time, traceback, sys

import apport.REThread

def idle(seconds):
    '''Test thread to just wait a bit.'''

    time.sleep(seconds)

def div(x, y):
    '''Test thread to divide two numbers.'''

    return x / y

class T(unittest.TestCase):
    def test_return_value(self):
        '''return value works properly.'''

        t = apport.REThread.REThread(target=div, args=(42, 2))
        t.start()
        t.join()
        # exc_raise() should be a no-op on successful functions
        t.exc_raise()
        self.assertEqual(t.return_value(), 21)
        self.assertEqual(t.exc_info(), None)

    def test_no_return_value(self):
        '''apport.REThread.REThread works if run() does not return anything.'''

        t = apport.REThread.REThread(target=idle, args=(0.5,))
        t.start()
        # thread must be joined first
        self.assertRaises(AssertionError, t.return_value)
        t.join()
        self.assertEqual(t.return_value(), None)
        self.assertEqual(t.exc_info(), None)

    def test_exception(self):
        '''exception in thread is caught and passed.'''

        t = apport.REThread.REThread(target=div, args=(1, 0))
        t.start()
        t.join()
        # thread did not terminate normally, no return value
        self.assertRaises(AssertionError, t.return_value)
        self.assertTrue(t.exc_info()[0] == ZeroDivisionError)
        exc = traceback.format_exception(t.exc_info()[0], t.exc_info()[1],
            t.exc_info()[2])
        self.assertTrue(exc[-1].startswith('ZeroDivisionError'), 'not a ZeroDivisionError:' + str(exc))
        self.assertTrue(exc[-2].endswith('return x / y\n'))

    def test_exc_raise(self):
        '''exc_raise() raises caught thread exception.'''

        t = apport.REThread.REThread(target=div, args=(1, 0))
        t.start()
        t.join()
        # thread did not terminate normally, no return value
        self.assertRaises(AssertionError, t.return_value)
        raised = False
        try:
            t.exc_raise()
        except:
            raised = True
            e = sys.exc_info()
            exc = traceback.format_exception(e[0], e[1], e[2])
            self.assertTrue(exc[-1].startswith('ZeroDivisionError'), 'not a ZeroDivisionError:' + str(e))
            self.assertTrue(exc[-2].endswith('return x / y\n'))
        self.assertTrue(raised)

unittest.main()

