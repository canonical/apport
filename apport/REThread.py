'''Enhanced Thread with support for return values and exception propagation.'''

# Copyright (C) 2007 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import threading, sys

class REThread(threading.Thread):
    '''Thread with return values and exception propagation.'''

    def __init__(self, group=None, target=None, name=None, args=(), kwargs={},
            verbose=None):
        '''Initialize Thread, identical to threading.Thread.__init__().'''

        threading.Thread.__init__(self, group, target, name, args, kwargs,
            verbose)
        self.__target = target
        self.__args = args
        self.__kwargs = kwargs
        self._retval = None
        self._exception = None

    def run(self):
        '''Run target function, identical to threading.Thread.run().'''

        if self.__target:
            try:
                self._retval = self.__target(*self.__args, **self.__kwargs)
            except:
                if sys:
                    self._exception = sys.exc_info()

    def return_value(self):
        '''Return value from target function.

        This can only be called after the thread has finished, i. e. when
        isAlive() is False and did not terminate with an exception.
        '''
        assert not self.isAlive()
        assert not self._exception
        return self._retval

    def exc_info(self):
        '''Return (type, value, traceback) of the exception caught in run().'''

        return self._exception

    def exc_raise(self):
        '''Raise the exception caught in the thread.

        Do nothing if no exception was caught.
        '''
        if self._exception:
            raise self._exception[0], self._exception[1], self._exception[2]

#
# Unit test
#

if __name__ == '__main__':
    import unittest, time, traceback, exceptions

    def idle(seconds):
        '''Test thread to just wait a bit.'''

        time.sleep(seconds)

    def div(x, y):
        '''Test thread to divide two numbers.'''

        return x / y

    class _REThreadTest(unittest.TestCase):
        def test_return_value(self):
            '''return value works properly.'''

            t = REThread(target=div, args=(42, 2))
            t.start()
            t.join()
            # exc_raise() should be a no-op on successful functions
            t.exc_raise()
            self.assertEqual(t.return_value(), 21)
            self.assertEqual(t.exc_info(), None)

        def test_no_return_value(self):
            '''REThread works if run() does not return anything.'''

            t = REThread(target=idle, args=(0.5,))
            t.start()
            # thread must be joined first
            self.assertRaises(AssertionError, t.return_value)
            t.join()
            self.assertEqual(t.return_value(), None)
            self.assertEqual(t.exc_info(), None)

        def test_exception(self):
            '''exception in thread is caught and passed.'''

            t = REThread(target=div, args=(1, 0))
            t.start()
            t.join()
            # thread did not terminate normally, no return value
            self.assertRaises(AssertionError, t.return_value)
            self.assert_(t.exc_info()[0] == exceptions.ZeroDivisionError)
            exc = traceback.format_exception(t.exc_info()[0], t.exc_info()[1],
                t.exc_info()[2])
            self.assert_(exc[-1].startswith('ZeroDivisionError'))
            self.assert_(exc[-2].endswith('return x / y\n'))

        def test_exc_raise(self):
            '''exc_raise() raises caught thread exception.'''

            t = REThread(target=div, args=(1, 0))
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
                self.assert_(exc[-1].startswith('ZeroDivisionError'))
                self.assert_(exc[-2].endswith('return x / y\n'))
            self.assert_(raised)

    unittest.main()

