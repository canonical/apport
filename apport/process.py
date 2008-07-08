# -*- coding: iso-8859-1 -*-
#
# process.py - example of ProcessEvent subclassing
# Copyright (C) 2006  S�bastien Martini <sebastien.martini@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

import sys, os
from pyinotify import ProcessEvent

test_executable = '/usr/share/apport/apport-gtk'

class PExample(ProcessEvent):
    """
    PExample class: introduces how to subclass ProcessEvent.
    """
    def process_default(self, event):
        """
        override default processing method
        """
        print 'PExample::process_default'
        # call base method
        super(PExample, self).process_default(event)

    def process_IN_CLOSE_WRITE(self, event):
        """
        process 'IN_MODIFY' events
        """
        print 'PExample::process_IN_CLOSE_WRITE'
        pid = os.fork()
        if pid == 0:
            os.environ['DISPLAY']=':0'
            sys.stdin.close()
            os.setsid()
            os.execve(test_executable, [test_executable], os.environ)
            assert False, 'Could not execute ' + test_executable
