import time
import unittest
from io import BytesIO

import apport.fileutils
import apport.packaging


class T(unittest.TestCase):
    def test_likely_packaged(self):
        '''likely_packaged()'''

        self.assertEqual(apport.fileutils.likely_packaged('/bin/bash'), True)
        self.assertEqual(apport.fileutils.likely_packaged('/usr/bin/foo'), True)
        self.assertEqual(apport.fileutils.likely_packaged('/usr/local/bin/foo'), False)
        self.assertEqual(apport.fileutils.likely_packaged('/home/test/bin/foo'), False)
        self.assertEqual(apport.fileutils.likely_packaged('/tmp/foo'), False)
        # ignore crashes in /var/lib (LP#122859, LP#414368)
        self.assertEqual(apport.fileutils.likely_packaged('/var/lib/foo'), False)

    def test_get_recent_crashes(self):
        '''get_recent_crashes()'''

        # incomplete fields
        r = BytesIO(b'''ProblemType: Crash''')
        self.assertEqual(apport.fileutils.get_recent_crashes(r), 0)

        r = BytesIO(b'''ProblemType: Crash\nDate: Wed Aug 01 00:00:01 1990\n''')
        self.assertEqual(apport.fileutils.get_recent_crashes(r), 0)

        # ancient report
        r = BytesIO(
            b'ProblemType: Crash\n'
            b'Date: Wed Aug 01 00:00:01 1990\n'
            b'CrashCounter: 3\n'
        )
        self.assertEqual(apport.fileutils.get_recent_crashes(r), 0)

        # old report (one day + one hour ago)
        date = time.ctime(time.mktime(time.localtime()) - 25 * 3600)
        r = BytesIO(f'ProblemType: Crash\nDate: {date}\nCrashCounter: 3\n'.encode())
        self.assertEqual(apport.fileutils.get_recent_crashes(r), 0)

        # current report (one hour ago)
        date = time.ctime(time.mktime(time.localtime()) - 3600)
        r = BytesIO(f'ProblemType: Crash\nDate: {date}\nCrashCounter: 3\n'.encode())
        self.assertEqual(apport.fileutils.get_recent_crashes(r), 3)

    def test_get_dbus_socket(self):
        '''get_dbus_socket()'''

        tests = [("unix:path=/run/user/1000/bus", "/run/user/1000/bus"),
                 ("unix:path=/run/user/1000/bus;unix:path=/run/user/0/bus", None),
                 ("unix:path=%2Frun/user/1000/bus", None),
                 ("unix:path=/run/user/1000/bus,path=/run/user/0/bus", None),
                 ("unix:path=/etc/passwd", None),
                 ("unix:path=/run/user/../../etc/passwd", None),
                 ("unix:path=/run/user/1000/bus=", None),
                 ("", None),
                 ("tcp:host=localhost,port=8100", None)]

        for (addr, result) in tests:
            self.assertEqual(apport.fileutils.get_dbus_socket(addr), result)

    def test_get_starttime(self):
        '''get_starttime()'''

        template = ('2022799 (%s) S 1834041 2022799 2022799 34820 '
                    '2022806 4194304 692 479 0 0 2 0 0 0 20 0 1 0 '
                    '34034895 13750272 1270 18446744073709551615 '
                    '94876723015680 94876723738373 140731174338544 '
                    '0 0 0 65536 3670020 1266777851 1 0 0 17 7 0 0 0 0 0 '
                    '94876723969264 94876724016644 94876748173312 '
                    '140731174345133 140731174345138 140731174345138 '
                    '140731174346734 0\n')

        for name in ['goodname', 'bad name', '(badname', 'badname)',
                     '(badname)', '((badname))', 'badname(', ')badname',
                     'bad) name', 'bad) name\\']:
            starttime = apport.fileutils.get_starttime(template % name)
            self.assertEqual(starttime, 34034895)

    def test_get_uid_and_gid(self):
        '''get_uid_and_gid()'''

        # Python 3's open uses universal newlines, which means all
        # line endings get replaced with \n, so we don't need to test
        # different line ending combinations
        template = ('Name:\t%s\n'
                    'Umask:\t0002\n'
                    'State:\tS (sleeping)\n'
                    'Tgid:\t2288405\n'
                    'Ngid:\t0\n'
                    'Pid:\t2288405\n'
                    'PPid:\t2167353\n'
                    'TracerPid:\t0\n'
                    'Uid:\t1000\t1000\t1000\t1000\n'
                    'Gid:\t2000\t2000\t2000\t2000\n'
                    'FDSize:\t256\n'
                    'Groups:\t4 20 24 27 30 46 108 120 131 132 135 137 1000 \n'
                    'NStgid:\t2288405\n'
                    'NSpid:\t2288405\n'
                    'NSpgid:\t2288405\n'
                    'NSsid:\t2288405\n'
                    'VmPeak:\t   13428 kB\n'
                    'VmSize:\t   13428 kB\n'
                    'VmLck:\t       0 kB\n'
                    'VmPin:\t       0 kB\n'
                    'VmHWM:\t    5200 kB\n'
                    'VmRSS:\t    5200 kB\n'
                    'RssAnon:\t    1700 kB\n'
                    'RssFile:\t    3500 kB\n'
                    'RssShmem:\t       0 kB\n'
                    'VmData:\t    1600 kB\n'
                    'VmStk:\t     132 kB\n'
                    'VmExe:\t     708 kB\n'
                    'VmLib:\t    1748 kB\n'
                    'VmPTE:\t      68 kB\n'
                    'VmSwap:\t       0 kB\n'
                    'HugetlbPages:\t       0 kB\n'
                    'CoreDumping:\t0\n'
                    'THP_enabled:\t1\n'
                    'Threads:\t1\n'
                    'SigQ:\t0/62442\n'
                    'SigPnd:\t0000000000000000\n'
                    'ShdPnd:\t0000000000000000\n'
                    'SigBlk:\t0000000000010000\n'
                    'SigIgn:\t0000000000380004\n'
                    'SigCgt:\t000000004b817efb\n'
                    'CapInh:\t0000000000000000\n'
                    'CapPrm:\t0000000000000000\n'
                    'CapEff:\t0000000000000000\n'
                    'CapBnd:\t000000ffffffffff\n'
                    'CapAmb:\t0000000000000000\n'
                    'NoNewPrivs:\t0\n'
                    'Seccomp:\t0\n'
                    'Speculation_Store_Bypass:\tthread vulnerable\n'
                    'Cpus_allowed:\tff\n'
                    'Cpus_allowed_list:\t0-7\n'
                    'Mems_allowed:\t00000000,00000000,00000000,00000000,'
                    '00000000,00000000,00000000,00000000,00000000,'
                    '00000000,00000000,00000000,00000000,00000000,'
                    '00000000,00000000,00000000,00000000,00000000,'
                    '00000000,00000000,00000000,00000000,00000000,'
                    '00000000,00000000,00000000,00000000,00000000,'
                    '00000000,00000000,00000001\n'
                    'Mems_allowed_list:\t0\n'
                    'voluntary_ctxt_switches:\t133\n'
                    'nonvoluntary_ctxt_switches:\t0\n')

        for name in ['goodname', 'Uid:', '\nUid:', 'Uid: 1000 1000 1000\n',
                     'a\nUid: 0\nGid: 0', 'a\nUid: 0\nGid:']:
            (uid, gid) = apport.fileutils.get_uid_and_gid(template % name)
            self.assertEqual(uid, 1000)
            self.assertEqual(gid, 2000)
