"""Enhanced Thread with support for return values and exception propagation."""

# Copyright (C) 2007 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

# pylint: disable=invalid-name
# pylint: enable=invalid-name

import sys
import threading


class REThread(threading.Thread):
    """Thread with return values and exception propagation."""

    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None):
        """Initialize Thread, identical to threading.Thread.__init__()."""
        if kwargs is None:
            kwargs = {}

        threading.Thread.__init__(self, group, target, name, args, kwargs)
        self.__target = target
        self.__args = args
        self.__kwargs = kwargs
        self._retval = None
        self._exception = None

    def run(self):
        """Run target function, identical to threading.Thread.run()."""
        if self.__target:
            try:
                self._retval = self.__target(*self.__args, **self.__kwargs)
            except BaseException:  # pylint: disable=broad-except
                if sys:  # pylint: disable=using-constant-test
                    self._exception = sys.exc_info()

    def return_value(self):
        """Return value from target function.

        This can only be called after the thread has finished, i. e. when
        is_alive() is False and did not terminate with an exception.
        """
        assert not self.is_alive()
        assert not self._exception
        return self._retval

    def exc_info(self):
        """Return (type, value, traceback) of the exception caught in run()."""
        return self._exception

    def exc_raise(self):
        """Raise the exception caught in the thread.

        Do nothing if no exception was caught.
        """
        if self._exception:
            raise self._exception[1].with_traceback(self._exception[2])
