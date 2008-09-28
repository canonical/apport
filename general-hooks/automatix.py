'''Do not send any crashes when automatix is or was installed, since it usually
causes a mess in the system and causes a lot of package installation failures.

Copyright (C) 2007 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import apport.packaging

def add_info(report):
    try:
        if apport.packaging.get_version('automatix') or \
            apport.packaging.get_version('automatix2'):
            report['UnreportableReason'] = 'You have installed automatix on your \
system. This is known to cause a lot of instability, thus problem reports \
will not be sent to the %s developers.' % report.get('DistroRelease',
    'distribution').split()[0]
    except ValueError, e:
        return
