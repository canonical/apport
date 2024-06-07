"""Unit tests for the apport.report module."""

# pylint: disable=too-many-lines
# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import datetime
import io
import os
import pathlib
import re
import subprocess
import tempfile
import textwrap
import unittest
import unittest.mock
from unittest.mock import MagicMock

import apport.packaging
import apport.report
import problem_report

DIVIDE_BY_ZERO_PROC_MAPS = f"""\
558164bd3000-558164bd4000 r--p 00000000 fc:00 44306916 \
                  /usr/bin/divide-by-zero
558164bd4000-558164bd5000 r-xp 00001000 fc:00 44306916 \
                  /usr/bin/divide-by-zero
558164bd5000-558164bd6000 r--p 00002000 fc:00 44306916 \
                  /usr/bin/divide-by-zero
558164bd6000-558164bd7000 r--p 00002000 fc:00 44306916 \
                  /usr/bin/divide-by-zero
558164bd7000-558164bd8000 rw-p 00003000 fc:00 44306916 \
                  /usr/bin/divide-by-zero
7f70d0600000-7f70d0626000 r--p 00000000 fc:00 44304501 \
                  /usr/lib/x86_64-linux-gnu/libc.so.6
7f70d0626000-7f70d07a5000 r-xp 00026000 fc:00 44304501 \
                  /usr/lib/x86_64-linux-gnu/libc.so.6
7f70d07a5000-7f70d07fa000 r--p 001a5000 fc:00 44304501 \
                  /usr/lib/x86_64-linux-gnu/libc.so.6
7f70d07fa000-7f70d07fe000 r--p 001f9000 fc:00 44304501 \
                  /usr/lib/x86_64-linux-gnu/libc.so.6
7f70d07fe000-7f70d0800000 rw-p 001fd000 fc:00 44304501 \
                  /usr/lib/x86_64-linux-gnu/libc.so.6
7f70d0800000-7f70d080d000 rw-p 00000000 00:00 0{" "}
7f70d0967000-7f70d096a000 rw-p 00000000 00:00 0{" "}
7f70d0989000-7f70d098b000 rw-p 00000000 00:00 0{" "}
7f70d098b000-7f70d098c000 r--p 00000000 fc:00 44303536 \
                  /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f70d098c000-7f70d09b6000 r-xp 00001000 fc:00 44303536 \
                  /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f70d09b6000-7f70d09c0000 r--p 0002b000 fc:00 44303536 \
                  /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f70d09c0000-7f70d09c2000 r--p 00035000 fc:00 44303536 \
                  /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f70d09c2000-7f70d09c4000 rw-p 00037000 fc:00 44303536 \
                  /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7fffd4d90000-7fffd4db2000 rw-p 00000000 00:00 0 \
                         [stack]
7fffd4ddd000-7fffd4de1000 r--p 00000000 00:00 0 \
                         [vvar]
7fffd4de1000-7fffd4de3000 r-xp 00000000 00:00 0 \
                         [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 \
                 [vsyscall]
"""
DIVIDE_BY_ZERO_PROC_STATUS = f"""\
Name:	divide-by-zero
Umask:	0002
State:	S (sleeping)
Tgid:	284582
Ngid:	0
Pid:	284582
PPid:	276410
TracerPid:	0
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
FDSize:	256
Groups:	4 20 24 27 30 46 118 122 133 134 135 1000 1001{" "}
NStgid:	284582
NSpid:	284582
NSpgid:	284582
NSsid:	276410
Kthread:	0
VmPeak:	    2652 kB
VmSize:	    2528 kB
VmLck:	       0 kB
VmPin:	       0 kB
VmHWM:	    1024 kB
VmRSS:	    1024 kB
RssAnon:	       0 kB
RssFile:	    1024 kB
RssShmem:	       0 kB
VmData:	      92 kB
VmStk:	     136 kB
VmExe:	       4 kB
VmLib:	    1708 kB
VmPTE:	      40 kB
VmSwap:	       0 kB
HugetlbPages:	       0 kB
CoreDumping:	1
THP_enabled:	1
untag_mask:	0xffffffffffffffff
Threads:	1
SigQ:	0/254102
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000000000
SigIgn:	0000000000000000
SigCgt:	0000000000000000
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	0
Seccomp_filters:	0
Speculation_Store_Bypass:	thread vulnerable
SpeculationIndirectBranch:	conditional enabled
Cpus_allowed:	ffffffff
Cpus_allowed_list:	0-31
Mems_allowed:	{"00000000," * 31}00000001
Mems_allowed_list:	0
voluntary_ctxt_switches:	3
nonvoluntary_ctxt_switches:	0
"""
DIVIDE_BY_ZERO_REPORT = f"""\
ProblemType: Crash
CurrentDesktop: Unity:Unity7:ubuntu
Date: Mon Oct 30 13:40:03 2023
ExecutablePath: /usr/bin/divide-by-zero
ExecutableTimestamp: 1688310044
ProcCmdline: divide-by-zero
ProcCwd: /home/user/something
ProcEnviron:
 LANG=de_DE.UTF-8
 LANGUAGE=de_DE:en
 LC_ADDRESS=de_DE.UTF-8
 LC_IDENTIFICATION=de_DE.UTF-8
 LC_MEASUREMENT=de_DE.UTF-8
 LC_MONETARY=de_DE.UTF-8
 LC_NAME=de_DE.UTF-8
 LC_NUMERIC=de_DE.UTF-8
 LC_PAPER=de_DE.UTF-8
 LC_TELEPHONE=de_DE.UTF-8
 LC_TIME=de_DE.UTF-8
 PATH=(custom, no user)
 SHELL=/bin/bash
 TERM=xterm-256color
 XDG_RUNTIME_DIR=<set>
ProcMaps:
{re.sub("^", " ", DIVIDE_BY_ZERO_PROC_MAPS.rstrip(), flags=re.MULTILINE)}
ProcStatus:
{re.sub("^", " ", DIVIDE_BY_ZERO_PROC_STATUS.rstrip(), flags=re.MULTILINE)}
Signal: 4
SignalName: SIGILL
"""
_DIVIDE_BY_ZERO_ENVIRONMENT = [
    "SHELL=/bin/bash",
    "SESSION_MANAGER=local/hostname:@/tmp/.ICE-unix/6144"
    ",unix/hostname:/tmp/.ICE-unix/6144",
    "QT_ACCESSIBILITY=1",
    "COLORTERM=truecolor",
    "XDG_CONFIG_DIRS=/etc/xdg/xdg-unity:/etc/xdg",
    "SSH_AGENT_LAUNCHER=openssh",
    "HISTCONTROL=ignoreboth",
    "XDG_MENU_PREFIX=gnome-",
    "GNOME_DESKTOP_SESSION_ID=this-is-deprecated",
    "GTK_IM_MODULE=ibus",
    "HISTSIZE=1000000",
    "LANGUAGE=de_DE:en",
    "UNITY_HAS_3D_SUPPORT=true",
    "LC_ADDRESS=de_DE.UTF-8",
    "LC_NAME=de_DE.UTF-8",
    "SSH_AUTH_SOCK=/run/user/1000/keyring/ssh",
    "XMODIFIERS=@im=ibus",
    "DESKTOP_SESSION=unity",
    "LC_MONETARY=de_DE.UTF-8",
    "EDITOR=/usr/bin/vim.basic",
    "GTK_MODULES=gail:atk-bridge:unity-gtk-module",
    "ZEITGEIST_DATA_PATH=/home/user/.local/share/zeitgeist",
    "PWD=/home/user/something",
    "XDG_SESSION_DESKTOP=unity",
    "LOGNAME=user",
    "XDG_SESSION_TYPE=x11",
    "GPG_AGENT_INFO=/run/user/1000/gnupg/S.gpg-agent:0:1",
    "SYSTEMD_EXEC_PID=19518",
    "XAUTHORITY=/run/user/1000/gdm/Xauthority",
    "WINDOWPATH=2",
    "HOME=/home/user",
    "USERNAME=user",
    "IM_CONFIG_PHASE=1",
    "LC_PAPER=de_DE.UTF-8",
    "LANG=de_DE.UTF-8",
    "XDG_CURRENT_DESKTOP=Unity:Unity7:ubuntu",
    "VTE_VERSION=7400",
    "GNOME_TERMINAL_SCREEN=/org/gnome/Terminal/screen"
    "/28a9c759_0c8e_4dbb_ac97_ab266bc17659",
    "QTWEBENGINE_DICTIONARIES_PATH=/usr/share/hunspell-bdic/",
    "GTK_CSD=0",
    "CLUTTER_IM_MODULE=ibus",
    "LESSCLOSE=/usr/bin/lesspipe %s %s",
    "XDG_SESSION_CLASS=user",
    "TERM=xterm-256color",
    "LC_IDENTIFICATION=de_DE.UTF-8",
    "LESSOPEN=| /usr/bin/lesspipe %s",
    "LIBVIRT_DEFAULT_URI=qemu:///system",
    "USER=user",
    "GNOME_TERMINAL_SERVICE=:1.197",
    "DISPLAY=:0",
    "SHLVL=1",
    "LC_TELEPHONE=de_DE.UTF-8",
    "QT_IM_MODULE=ibus",
    "LC_MEASUREMENT=de_DE.UTF-8",
    "GNOME_SESSION_XDG_SESSION_PATH=",
    "XDG_RUNTIME_DIR=/run/user/1000",
    "COMPIZ_CONFIG_PROFILE=ubuntu",
    "DEBUGINFOD_URLS=https://debuginfod.ubuntu.com",
    "LC_TIME=de_DE.UTF-8",
    "GTK3_MODULES=xapp-gtk3-module",
    "XDG_DATA_DIRS=/usr/share/unity:/usr/share/gnome:/usr/local/share/"
    ":/usr/share/:/var/lib/snapd/desktop",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ":/usr/games:/usr/local/games:/snap/bin",
    "GDMSESSION=unity",
    "HISTFILESIZE=1000000",
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
    "LC_NUMERIC=de_DE.UTF-8",
    "UNITY_DEFAULT_PROFILE=unity",
    "OLDPWD=/home/user/previous_path",
    "_=/usr/bin/divide-by-zero",
]
_CET = datetime.timezone(datetime.timedelta(seconds=3600), "CET")
DIVIDE_BY_ZERO_SYSTEMD_COREDUMP = {
    "COREDUMP_CGROUP": "/user.slice/user-1000.slice/user"
    "@1000.service/app.slice/app-org.gnome.Terminal.slice"
    "/vte-spawn-3e85b382-d004-42dd-890d-bb72fe095fe8.scope",
    "COREDUMP_CMDLINE": "divide-by-zero",
    "COREDUMP_COMM": "divide-by-zero",
    "COREDUMP_CWD": "/home/user/something",
    "COREDUMP_ENVIRON": "\n".join(_DIVIDE_BY_ZERO_ENVIRONMENT) + "\n",
    "COREDUMP_EXE": "/usr/bin/divide-by-zero",
    "COREDUMP_GID": 1000,
    "COREDUMP_HOSTNAME": "hostname",
    "COREDUMP_OPEN_FDS": "0:/dev/pts/2\npos:\t0\nflags:\t02002002\n"
    "mnt_id:\t27\nino:\t5\n"
    "\n1:/dev/pts/2\npos:\t0\nflags:\t02002002\nmnt_id:\t27\nino:\t5\n"
    "\n2:/dev/pts/2\npos:\t0\nflags:\t02002002\nmnt_id:\t27\nino:\t5\n",
    "COREDUMP_OWNER_UID": "1000",
    "COREDUMP_PACKAGE_JSON": '{"elfType":"coredump","elfArchitecture":"AMD x86-64"}',
    "COREDUMP_PID": 284582,
    "COREDUMP_PROC_AUXV": b"!" + b"\x00" * 8 + b"\x10\xde\xd4\xff\x7f\x00\x003",
    "COREDUMP_PROC_CGROUP": "0::/user.slice/user-1000.slice/user"
    "@1000.service/app.slice/app-org.gnome.Terminal.slice"
    "/vte-spawn-3e85b382-d004-42dd-890d-bb72fe095fe8.scope\n",
    "COREDUMP_PROC_LIMITS": "[redacted]",
    "COREDUMP_PROC_MAPS": DIVIDE_BY_ZERO_PROC_MAPS,
    "COREDUMP_PROC_MOUNTINFO": "24 31 0:22 / /sys"
    " rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw\n",
    "COREDUMP_PROC_STATUS": DIVIDE_BY_ZERO_PROC_STATUS,
    "COREDUMP_RLIMIT": "9223372036854775808",
    "COREDUMP_ROOT": "/",
    "COREDUMP_SIGNAL": 4,
    "COREDUMP_SIGNAL_NAME": "SIGILL",
    "COREDUMP_SLICE": "user-1000.slice",
    "COREDUMP_TIMESTAMP": datetime.datetime(2023, 10, 30, 13, 40, 3, tzinfo=_CET),
    "COREDUMP_UID": 1000,
    "COREDUMP_UNIT": "user@1000.service",
    "COREDUMP_USER_UNIT": "vte-spawn-3e85b382-d004-42dd-890d-bb72fe095fe8.scope",
}
DIVIDE_BY_ZERO_EXECUTABLE_STAT = os.stat_result(
    (33261, 88736832, 64512, 1, 0, 0, 14648, 1704369903, 1688310044, 1698059154)
)


class T(unittest.TestCase):
    # pylint: disable=missing-class-docstring,missing-function-docstring
    # pylint: disable=protected-access
    maxDiff = None

    def test_has_useful_stacktrace(self):
        """has_useful_stacktrace()."""
        r = apport.report.Report()
        self.assertFalse(r.has_useful_stacktrace())

        r["StacktraceTop"] = ""
        self.assertFalse(r.has_useful_stacktrace())

        r["StacktraceTop"] = "?? ()"
        self.assertFalse(r.has_useful_stacktrace())

        r["StacktraceTop"] = "?? ()\n?? ()"
        self.assertFalse(r.has_useful_stacktrace())

        r["StacktraceTop"] = "read () from /lib/libc.6.so\n?? ()"
        self.assertFalse(r.has_useful_stacktrace())

        r["StacktraceTop"] = "read () from /lib/libc.6.so\n?? ()\n?? ()\n?? ()"
        self.assertFalse(r.has_useful_stacktrace())

        r["StacktraceTop"] = (
            "read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so"
        )
        self.assertTrue(r.has_useful_stacktrace())

        r["StacktraceTop"] = (
            "read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so\n?? ()"
        )
        self.assertTrue(r.has_useful_stacktrace())

        r["StacktraceTop"] = (
            "read () from /lib/libc.6.so\nfoo (i=1)"
            " from /usr/lib/libfoo.so\n?? ()\n?? ()"
        )
        self.assertTrue(r.has_useful_stacktrace())

        r["StacktraceTop"] = (
            "read () from /lib/libc.6.so\n?? ()\n"
            "foo (i=1) from /usr/lib/libfoo.so\n"
            "?? ()\n"
            "?? ()"
        )
        self.assertFalse(r.has_useful_stacktrace())

    def test_standard_title(self):
        # TODO: Split into separate test cases
        # pylint: disable=too-many-statements
        """standard_title()."""
        report = apport.report.Report()
        self.assertIsNone(report.standard_title())

        # named signal crash
        report["Signal"] = "11"
        report["SignalName"] = "SIGSEGV"
        report["ExecutablePath"] = "/bin/bash"
        report["StacktraceTop"] = textwrap.dedent(
            """\
            foo()
            bar(x=3)
            baz()
            """
        )
        self.assertEqual(report.standard_title(), "bash crashed with SIGSEGV in foo()")

        # unnamed signal crash
        report["Signal"] = "42"
        del report["SignalName"]
        self.assertEqual(
            report.standard_title(), "bash crashed with signal 42 in foo()"
        )

        # do not crash on empty StacktraceTop
        report["StacktraceTop"] = ""
        self.assertEqual(report.standard_title(), "bash crashed with signal 42")

        # do not create bug title with unknown function name
        report["StacktraceTop"] = "??()\nfoo()"
        self.assertEqual(
            report.standard_title(), "bash crashed with signal 42 in foo()"
        )

        # if we do not know any function name, don't mention ??
        report["StacktraceTop"] = "??()\n??()"
        self.assertEqual(report.standard_title(), "bash crashed with signal 42")

        # assertion message
        report["Signal"] = "6"
        report["SignalName"] = "SIGABRT"
        report["ExecutablePath"] = "/bin/bash"
        report["AssertionMessage"] = "foo.c:42 main: i > 0"
        self.assertEqual(
            report.standard_title(), "bash assert failure: foo.c:42 main: i > 0"
        )

        # Python crash
        report = apport.report.Report()
        report["ExecutablePath"] = "/usr/share/apport/apport-gtk"
        report[
            "Traceback"
        ] = """\
Traceback (most recent call last):
File "/usr/share/apport/apport-gtk", line 202, in <module>
app.run_argv()
File "/var/lib/python-support/python2.5/apport/ui.py", line 161, in run_argv
self.run_crashes()
File "/var/lib/python-support/python2.5/apport/ui.py", line 104, in run_crashes
self.run_crash(f)
File "/var/lib/python-support/python2.5/apport/ui.py", line 115, in run_crash
response = self.ui_present_crash(desktop_entry)
File "/usr/share/apport/apport-gtk", line 67, in ui_present_crash
subprocess.call(['pgrep', '-x',
NameError: global name 'subprocess' is not defined"""
        self.assertEqual(
            report.standard_title(),
            "apport-gtk crashed with NameError in ui_present_crash():"
            " global name 'subprocess' is not defined",
        )

        # slightly weird Python crash
        report = apport.report.Report()
        report["ExecutablePath"] = "/usr/share/apport/apport-gtk"
        report["Traceback"] = (
            "TypeError: Cannot create a consistent method resolution\n"
            "order (MRO) for bases GObject, CanvasGroupableIface,"
            " CanvasGroupable"
        )
        self.assertEqual(
            report.standard_title(),
            "apport-gtk crashed with TypeError:"
            " Cannot create a consistent method resolution",
        )

        # Python crash with custom message
        report = apport.report.Report()
        report["ExecutablePath"] = "/usr/share/apport/apport-gtk"
        report["Traceback"] = textwrap.dedent(
            """\
            Traceback (most recent call last):
              File "/x/foo.py", line 242, in setup_chooser
                raise "Moo"
            Mo?o[a-1]
            """
        )

        self.assertEqual(
            report.standard_title(),
            "apport-gtk crashed with Mo?o[a-1] in setup_chooser()",
        )

        # Python crash with custom message with newlines (LP #190947)
        report = apport.report.Report()
        report["ExecutablePath"] = "/usr/share/apport/apport-gtk"
        report[
            "Traceback"
        ] = """\
Traceback (most recent call last):
  File "/x/foo.py", line 242, in setup_chooser
    raise "\nKey: "+key+" isn't set.\n\
Restarting AWN usually solves this issue\n"

Key: /apps/avant-window-navigator/app/active_png isn't set.
Restarting AWN usually solves this issue"""

        t = report.standard_title()
        self.assertTrue(t.startswith("apport-gtk crashed with"))
        self.assertTrue(t.endswith("setup_chooser()"))

        # Python crash at top level in module
        report = apport.report.Report()
        report["ExecutablePath"] = "/usr/bin/gnome-about"
        report[
            "Traceback"
        ] = """\
Traceback (most recent call last):
  File "/usr/bin/gnome-about", line 30, in <module>
    import pygtk
  File "/usr/lib/pymodules/python2.6/pygtk.py", line 28, in <module>
    import nonexistent
ImportError: No module named nonexistent
"""
        self.assertEqual(
            report.standard_title(),
            "gnome-about crashed with ImportError"
            " in /usr/lib/pymodules/python2.6/pygtk.py:"
            " No module named nonexistent",
        )

        # Python crash at top level in main program
        report = apport.report.Report()
        report["ExecutablePath"] = "/usr/bin/dcut"
        report["Traceback"] = textwrap.dedent(
            """\
            Traceback (most recent call last):
              File "/usr/bin/dcut", line 28, in <module>
                import nonexistent
            ImportError: No module named nonexistent
            """
        )
        self.assertEqual(
            report.standard_title(),
            "dcut crashed with ImportError in __main__: No module named nonexistent",
        )

        # package install problem
        report = apport.report.Report("Package")
        report["Package"] = "bash"

        # no ErrorMessage
        self.assertEqual(
            report.standard_title(), "package bash failed to install/upgrade"
        )

        # empty ErrorMessage
        report["ErrorMessage"] = ""
        self.assertEqual(
            report.standard_title(), "package bash failed to install/upgrade"
        )

        # nonempty ErrorMessage
        report["ErrorMessage"] = "botched\nnot found\n"
        self.assertEqual(
            report.standard_title(), "package bash failed to install/upgrade: not found"
        )

        # matching package/system architectures
        report["Signal"] = "11"
        report["SignalName"] = "SIGSEGV"
        report["ExecutablePath"] = "/bin/bash"
        report["StacktraceTop"] = textwrap.dedent(
            """\
            foo()
            bar(x=3)
            baz()
            """
        )
        report["PackageArchitecture"] = "amd64"
        report["Architecture"] = "amd64"
        self.assertEqual(report.standard_title(), "bash crashed with SIGSEGV in foo()")

        # non-native package (on multiarch)
        report["PackageArchitecture"] = "i386"
        self.assertEqual(
            report.standard_title(),
            "bash crashed with SIGSEGV in foo() [non-native i386 package]",
        )

        # Arch: all package (matches every system architecture)
        report["PackageArchitecture"] = "all"
        self.assertEqual(report.standard_title(), "bash crashed with SIGSEGV in foo()")

        report = apport.report.Report("KernelOops")
        report["OopsText"] = (
            "------------[ cut here ]------------\n"
            "kernel BUG at /tmp/oops.c:5!\n"
            "invalid opcode: 0000 [#1] SMP"
        )
        self.assertEqual(report.standard_title(), "kernel BUG at /tmp/oops.c:5!")

    def test_gen_stacktrace_top(self):
        """_gen_stacktrace_top()."""
        # nothing to chop off
        r = apport.report.Report()
        r["Stacktrace"] = textwrap.dedent(
            """\
            #0  0x10000488 in h (p=0x0) at crash.c:25
            #1  0x100004c8 in g (x=1, y=42) at crash.c:26
            #2  0x10000514 in f (x=1) at crash.c:27
            #3  0x10000530 in e (x=1) at crash.c:28
            #4  0x10000530 in d (x=1) at crash.c:29
            #5  0x10000530 in c (x=1) at crash.c:30
            #6  0x10000550 in main () at crash.c:31
            """
        )
        r._gen_stacktrace_top()
        self.assertEqual(
            r["StacktraceTop"],
            textwrap.dedent(
                """\
                h (p=0x0) at crash.c:25
                g (x=1, y=42) at crash.c:26
                f (x=1) at crash.c:27
                e (x=1) at crash.c:28
                d (x=1) at crash.c:29"""
            ),
        )

        # nothing to chop off: some addresses missing (LP #269133)
        r = apport.report.Report()
        r["Stacktrace"] = textwrap.dedent(
            """\
            #0 h (p=0x0) at crash.c:25
            #1  0x100004c8 in g (x=1, y=42) at crash.c:26
            #2 f (x=1) at crash.c:27
            #3  0x10000530 in e (x=1) at crash.c:28
            #4  0x10000530 in d (x=1) at crash.c:29
            #5  0x10000530 in c (x=1) at crash.c:30
            #6  0x10000550 in main () at crash.c:31
            """
        )
        r._gen_stacktrace_top()
        self.assertEqual(
            r["StacktraceTop"],
            textwrap.dedent(
                """\
                h (p=0x0) at crash.c:25
                g (x=1, y=42) at crash.c:26
                f (x=1) at crash.c:27
                e (x=1) at crash.c:28
                d (x=1) at crash.c:29"""
            ),
        )

        # single signal handler invocation
        r = apport.report.Report()
        r["Stacktrace"] = textwrap.dedent(
            """\
            #0  0x10000488 in raise () from /lib/libpthread.so.0
            #1  0x100004c8 in ??
            #2  <signal handler called>
            #3  0x10000530 in e (x=1) at crash.c:28
            #4  0x10000530 in d (x=1) at crash.c:29
            #5  0x10000530 in c (x=1) at crash.c:30
            #6  0x10000550 in main () at crash.c:31
            """
        )
        r._gen_stacktrace_top()
        self.assertEqual(
            r["StacktraceTop"],
            textwrap.dedent(
                """\
                e (x=1) at crash.c:28
                d (x=1) at crash.c:29
                c (x=1) at crash.c:30
                main () at crash.c:31"""
            ),
        )

        # single signal handler invocation: some addresses missing
        r = apport.report.Report()
        r["Stacktrace"] = textwrap.dedent(
            """\
            #0  0x10000488 in raise () from /lib/libpthread.so.0
            #1  ??
            #2  <signal handler called>
            #3  0x10000530 in e (x=1) at crash.c:28
            #4  d (x=1) at crash.c:29
            #5  0x10000530 in c (x=1) at crash.c:30
            #6  0x10000550 in main () at crash.c:31
            """
        )
        r._gen_stacktrace_top()
        self.assertEqual(
            r["StacktraceTop"],
            textwrap.dedent(
                """\
                e (x=1) at crash.c:28
                d (x=1) at crash.c:29
                c (x=1) at crash.c:30
                main () at crash.c:31"""
            ),
        )

        # stacked signal handler; should only cut the first one
        r = apport.report.Report()
        r["Stacktrace"] = textwrap.dedent(
            """\
            #0  0x10000488 in raise () from /lib/libpthread.so.0
            #1  0x100004c8 in ??
            #2  <signal handler called>
            #3  0x10000530 in e (x=1) at crash.c:28
            #4  0x10000530 in d (x=1) at crash.c:29
            #5  0x10000123 in raise () from /lib/libpthread.so.0
            #6  <signal handler called>
            #7  0x10000530 in c (x=1) at crash.c:30
            #8  0x10000550 in main () at crash.c:31
            """
        )
        r._gen_stacktrace_top()
        self.assertEqual(
            r["StacktraceTop"],
            textwrap.dedent(
                """\
                e (x=1) at crash.c:28
                d (x=1) at crash.c:29
                raise () from /lib/libpthread.so.0
                <signal handler called>
                c (x=1) at crash.c:30"""
            ),
        )

        # Gnome assertion; should unwind the logs and assert call
        r = apport.report.Report()
        r[
            "Stacktrace"
        ] = """\
#0  0xb7d39cab in IA__g_logv (log_domain=<value optimized out>,\
 log_level=G_LOG_LEVEL_ERROR,
    format=0xb7d825f0 "file %s: line %d (%s):\
 assertion failed: (%s)", args1=0xbfee8e3c "xxx")\
 at /build/buildd/glib2.0-2.13.5/glib/gmessages.c:493
#1  0xb7d39f29 in IA__g_log (log_domain=0xb7edbfd0 "libgnomevfs",\
 log_level=G_LOG_LEVEL_ERROR,
    format=0xb7d825f0 "file %s: line %d (%s): assertion failed: (%s)")\
 at /build/buildd/glib2.0-2.13.5/glib/gmessages.c:517
#2  0xb7d39fa6 in IA__g_assert_warning (log_domain=0xb7edbfd0 "libgnomevfs",\
 file=0xb7ee1a26 "gnome-vfs-volume.c", line=254,
    pretty_function=0xb7ee1920 "gnome_vfs_volume_unset_drive_private",\
 expression=0xb7ee1a39 "volume->priv->drive == drive")
    at /build/buildd/glib2.0-2.13.5/glib/gmessages.c:552
No locals.
#3  0xb7ec6c11 in gnome_vfs_volume_unset_drive_private (volume=0x8081a30,\
 drive=0x8078f00) at gnome-vfs-volume.c:254
        __PRETTY_FUNCTION__ = "gnome_vfs_volume_unset_drive_private"
#4  0x08054db8 in _gnome_vfs_volume_monitor_disconnected\
 (volume_monitor=0x8070400, drive=0x8078f00) at gnome-vfs-volume-monitor.c:963
        vol_list = (GList *) 0x8096d30
        current_vol = (GList *) 0x8097470
#5  0x0805951e in _hal_device_removed (hal_ctx=0x8074da8, udi=0x8093be4\
 "/org/freedesktop/Hal/devices/volume_uuid_92FC9DFBFC9DDA35")
    at gnome-vfs-hal-mounts.c:1316
        backing_udi = <value optimized out>
#6  0xb7ef1ead in filter_func (connection=0x8075288, message=0x80768d8,\
 user_data=0x8074da8) at libhal.c:820
        udi = <value optimized out>
        object_path = 0x8076d40 "/org/freedesktop/Hal/Manager"
        error = {name = 0x0, message = 0x0, placeholder1 = 1,\
 placeholder2 = 0, placeholder3 = 0, placeholder4 = 1, placeholder5 = 0,\
 padding1 = 0xb7e50c00}
#7  0xb7e071d2 in dbus_connection_dispatch (connection=0x8075288)\
 at dbus-connection.c:4267
#8  0xb7e33dfd in ?? () from /usr/lib/libdbus-glib-1.so.2"""
        r._gen_stacktrace_top()
        self.assertEqual(
            r["StacktraceTop"],
            """\
gnome_vfs_volume_unset_drive_private (volume=0x8081a30, drive=0x8078f00)\
 at gnome-vfs-volume.c:254
_gnome_vfs_volume_monitor_disconnected (volume_monitor=0x8070400,\
 drive=0x8078f00) at gnome-vfs-volume-monitor.c:963
_hal_device_removed (hal_ctx=0x8074da8, udi=0x8093be4\
 "/org/freedesktop/Hal/devices/volume_uuid_92FC9DFBFC9DDA35")
filter_func (connection=0x8075288, message=0x80768d8, user_data=0x8074da8)\
 at libhal.c:820
dbus_connection_dispatch (connection=0x8075288) at dbus-connection.c:4267""",
        )

        # XError (taken from LP#848808)
        r = apport.report.Report()
        r[
            "Stacktrace"
        ] = """\
#0  0x007cf416 in __kernel_vsyscall ()
No symbol table info available.
#1  0x01017c8f in __GI_raise (sig=6)\
 at ../nptl/sysdeps/unix/sysv/linux/raise.c:64
#2  0x0101b2b5 in __GI_abort () at abort.c:92
#3  0x0807daab in meta_bug (format=0x80b0c60 "Unexpected X error: %s serial\
 %ld error_code %d request_code %d minor_code %d)\n") at core/util.c:398
#4  0x0806989c in x_error_handler (error=0xbf924acc, xdisplay=0x9104b88)\
 at core/errors.c:247
#5  x_error_handler (xdisplay=0x9104b88, error=0xbf924acc) at core/errors.c:203
#6  0x00e97d3b in _XError (dpy=0x9104b88, rep=0x9131840)\
 at ../../src/XlibInt.c:1583
#7  0x00e9490d in handle_error (dpy=0x9104b88, err=0x9131840, in_XReply=0)\
 at ../../src/xcb_io.c:212
#8  0x00e94967 in handle_response (dpy=0x9104b88, response=0x9131840,\
 in_XReply=0) at ../../src/xcb_io.c:324
#9  0x00e952fe in _XReadEvents (dpy=0x9104b88) at ../../src/xcb_io.c:425
#10 0x00e93663 in XWindowEvent (dpy=0x9104b88, w=16777220, mask=4194304,\
 event=0xbf924c6c) at ../../src/WinEvent.c:79
#11 0x0806071c in meta_display_get_current_time_roundtrip (display=0x916d7d0)\
 at core/display.c:1217
#12 0x08089f64 in meta_window_show (window=0x91ccfc8) at core/window.c:2165
#13 implement_showing (window=0x91ccfc8, showing=1) at core/window.c:1583
#14 0x080879cc in meta_window_flush_calc_showing (window=0x91ccfc8)\
 at core/window.c:1806"""
        r._gen_stacktrace_top()
        self.assertEqual(
            r["StacktraceTop"],
            """\
meta_display_get_current_time_roundtrip (display=0x916d7d0)\
 at core/display.c:1217
meta_window_show (window=0x91ccfc8) at core/window.c:2165
implement_showing (window=0x91ccfc8, showing=1) at core/window.c:1583
meta_window_flush_calc_showing (window=0x91ccfc8) at core/window.c:1806""",
        )

        # another XError (taken from LP#834403)
        r = apport.report.Report()
        r[
            "Stacktrace"
        ] = """\
#0  g_logv (log_domain=0x7fd41db08a46 "Gdk", log_level=<optimized out>,\
 format=0x7fd41db12e87 "%s", args1=0x7fff50bf0c18)\
 at /build/buildd/glib2.0-2.29.16/./glib/gmessages.c:577
#1  0x00007fd42006bb92 in g_log (log_domain=<optimized out>,\
 log_level=<optimized out>, format=<optimized out>)\
 at /build/buildd/glib2.0-2.29.16/./glib/gmessages.c:591
#2  0x00007fd41dae86f3 in _gdk_x11_display_error_event\
 (display=<optimized out>, error=<optimized out>)\
 at /build/buildd/gtk+3.0-3.1.12/./gdk/x11/gdkdisplay-x11.c:2374
#3  0x00007fd41daf5647 in gdk_x_error (error=0x7fff50bf0dc0,\
 xdisplay=<optimized out>)\
 at /build/buildd/gtk+3.0-3.1.12/./gdk/x11/gdkmain-x11.c:312
#4  gdk_x_error (xdisplay=<optimized out>, error=0x7fff50bf0dc0)\
 at /build/buildd/gtk+3.0-3.1.12/./gdk/x11/gdkmain-x11.c:275
#5  0x00007fd41d5a301f in _XError (dpy=0x2425370, rep=<optimized out>)\
 at ../../src/XlibInt.c:1583
#6  0x00007fd41d59fdd1 in handle_error (dpy=0x2425370, err=0x7fd408707980,\
 in_XReply=<optimized out>) at ../../src/xcb_io.c:212
#7  0x00007fd41d5a0d27 in _XReply (dpy=0x2425370, rep=0x7fff50bf0f60,\
 extra=0, discard=0) at ../../src/xcb_io.c:698
#8  0x00007fd41d5852fb in XGetWindowProperty (dpy=0x2425370, w=0,\
 property=348, offset=0, length=2, delete=<optimized out>, req_type=348,\
 actual_type=0x7fff50bf1038, actual_format=0x7fff50bf105c,\
 nitems=0x7fff50bf1040, bytesafter=0x7fff50bf1048, prop=0x7fff50bf1050)\
 at ../../src/GetProp.c:61
#9  0x00007fd41938269e in window_is_xembed (w=<optimized out>,\
 d=<optimized out>) at canberra-gtk-module.c:373
#10 dispatch_sound_event (d=0x32f6a30) at canberra-gtk-module.c:454
#11 dispatch_queue () at canberra-gtk-module.c:815"""
        r._gen_stacktrace_top()
        self.assertEqual(
            r["StacktraceTop"],
            """\
XGetWindowProperty (dpy=0x2425370, w=0, property=348, offset=0, length=2,\
 delete=<optimized out>, req_type=348, actual_type=0x7fff50bf1038,\
 actual_format=0x7fff50bf105c, nitems=0x7fff50bf1040,\
 bytesafter=0x7fff50bf1048, prop=0x7fff50bf1050) at ../../src/GetProp.c:61
window_is_xembed (w=<optimized out>, d=<optimized out>)\
 at canberra-gtk-module.c:373
dispatch_sound_event (d=0x32f6a30) at canberra-gtk-module.c:454
dispatch_queue () at canberra-gtk-module.c:815""",
        )

        # problem with too old gdb, only assertion, nothing else
        r = apport.report.Report()
        r["Stacktrace"] = textwrap.dedent(
            """\
            #0  0x00987416 in __kernel_vsyscall ()
            No symbol table info available.
            #1  0x00ebecb1 in *__GI_raise (sig=6)
                    selftid = 945
            #2  0x00ec218e in *__GI_abort () at abort.c:59
                    save_stage = Unhandled dwarf expression opcode 0x9f
            """
        )
        r._gen_stacktrace_top()
        self.assertEqual(r["StacktraceTop"], "")

        # ignore uninteresting frames
        r = apport.report.Report()
        r["Stacktrace"] = textwrap.dedent(
            """\
            #0  0x00987416 in __kernel_vsyscall ()
            #1  __strchr_sse42 () at strchr.S:97
            #2 h (p=0x0) at crash.c:25
            #3  0x100004c8 in g (x=1, y=42) at crash.c:26
            #4  0x10000999 in __memmove_ssse3 ()
            #5 f (x=1) at crash.c:27
            #6  0x10000530 in e (x=1) at crash.c:28
            #7  0x10000999 in __strlen_sse2_back () at strchr.S:42
            #8  0x10000530 in d (x=1) at crash.c:29
            #9  0x10000530 in c (x=1) at crash.c:30
            #10 0x10000550 in main () at crash.c:31
            """
        )
        r._gen_stacktrace_top()
        self.assertEqual(
            r["StacktraceTop"],
            textwrap.dedent(
                """\
                h (p=0x0) at crash.c:25
                g (x=1, y=42) at crash.c:26
                f (x=1) at crash.c:27
                e (x=1) at crash.c:28
                d (x=1) at crash.c:29"""
            ),
        )

    @unittest.mock.patch("shutil.which", MagicMock(return_value=None))
    def test_gdb_add_info_no_gdb(self):
        r = apport.report.Report()
        r["Signal"] = "6"
        r["SignalName"] = "SIGABRT"
        r["ExecutablePath"] = "/bin/bash"
        r["CoreDump"] = "/var/lib/apport/coredump/core.bash"
        r["AssertionMessage"] = "foo.c:42 main: i > 0"
        with self.assertRaises(FileNotFoundError):
            r.add_gdb_info()

    def test_crash_signature(self):
        """crash_signature()."""
        r = apport.report.Report()
        self.assertIsNone(r.crash_signature())

        # signal crashes
        r["Signal"] = "42"
        r["ExecutablePath"] = "/bin/crash"

        r["StacktraceTop"] = textwrap.dedent(
            """\
            foo_bar (x=1) at crash.c:28
            d01 (x=1) at crash.c:29
            raise () from /lib/libpthread.so.0
            <signal handler called>
            __frob::~frob (x=1) at crash.c:30"""
        )

        self.assertEqual(
            r.crash_signature(),
            "/bin/crash:42:foo_bar:d01:raise:<signal handler called>:__frob::~frob",
        )

        r["StacktraceTop"] = textwrap.dedent(
            """\
            foo_bar (x=1) at crash.c:28
            ??
            raise () from /lib/libpthread.so.0
            <signal handler called>
            __frob (x=1) at crash.c:30"""
        )
        self.assertIsNone(r.crash_signature())

        r["StacktraceTop"] = ""
        self.assertIsNone(r.crash_signature())

        # Python crashes
        del r["Signal"]
        r["Traceback"] = textwrap.dedent(
            """\
            Traceback (most recent call last):
              File "test.py", line 7, in <module>
                print(_f(5))
              File "test.py", line 5, in _f
                return g_foo00(x+1)
              File "test.py", line 2, in g_foo00
                return x/0
            ZeroDivisionError: integer division or modulo by zero"""
        )
        self.assertEqual(
            r.crash_signature(), "/bin/crash:ZeroDivisionError:test.py@7:_f:g_foo00"
        )

        # sometimes Python traces do not have file references
        r["Traceback"] = "TypeError: function takes exactly 0 arguments (1 given)"
        self.assertEqual(r.crash_signature(), "/bin/crash:TypeError")

        r["Traceback"] = "FooBar"
        self.assertIsNone(r.crash_signature())

        # kernel
        r["ProblemType"] = "KernelCrash"
        r[
            "Stacktrace"
        ] = """
crash 4.0-8.9
GNU gdb 6.1
GDB is free software, covered by the GNU General Public License, and you are
welcome to change it and/or distribute copies of it under certain conditions.
Type "show copying" to see the conditions.
There is absolutely no warranty for GDB.  Type "show warranty" for details.
This GDB was configured as "i686-pc-linux-gnu"...

      KERNEL: /usr/lib/debug/boot/vmlinux-2.6.31-2-generic
    DUMPFILE: /tmp/tmpRJZy_O
        CPUS: 1
        DATE: Thu Jul  9 12:58:08 2009
      UPTIME: 00:00:57
LOAD AVERAGE: 0.15, 0.05, 0.02
       TASKS: 173
    NODENAME: egon-desktop
     RELEASE: 2.6.31-2-generic
     VERSION: #16-Ubuntu SMP Mon Jul 6 20:38:51 UTC 2009
     MACHINE: i686  (2137 Mhz)
      MEMORY: 2 GB
       PANIC: "[   57.879776] Oops: 0002 [#1] SMP " (check log for details)
         PID: 0
     COMMAND: "swapper"
        TASK: c073c180  [THREAD_INFO: c0784000]
         CPU: 0
       STATE: TASK_RUNNING (PANIC)

PID: 0      TASK: c073c180  CPU: 0   COMMAND: "swapper"
 #0 [c0785ba0] sysrq_handle_crash at c03917a3
    [RA: c03919c6  SP: c0785ba0  FP: c0785ba0  SIZE: 4]
    c0785ba0: c03919c6
 #1 [c0785ba0] __handle_sysrq at c03919c4
    [RA: c0391a91  SP: c0785ba4  FP: c0785bc8  SIZE: 40]
    c0785ba4: c06d4bab  c06d42d2  f6534000  00000004
    c0785bb4: 00000086  0000002e  00000001  f6534000
    c0785bc4: c0785bcc  c0391a91
 #2 [c0785bc8] handle_sysrq at c0391a8c
    [RA: c0389961  SP: c0785bcc  FP: c0785bd0  SIZE: 8]
    c0785bcc: c0785c0c  c0389961
 #3 [c0785bd0] kbd_keycode at c038995c
    [RA: c0389b8b  SP: c0785bd4  FP: c0785c10  SIZE: 64]
    c0785bd4: c056f96a  c0785be4  00000096  c07578c0
    c0785be4: 00000001  f6ac6e00  f6ac6e00  00000001
    c0785bf4: 00000000  00000000  0000002e  0000002e
    c0785c04: 00000001  f70d6850  c0785c1c  c0389b8b
 #4 [c0785c10] kbd_event at c0389b86
    [RA: c043140c  SP: c0785c14  FP: c0785c20  SIZE: 16]
    c0785c14: c0758040  f6910900  c0785c3c  c043140c
 #5 [c0785c20] input_pass_event at c0431409
    [RA: c04332ce  SP: c0785c24  FP: c0785c40  SIZE: 32]
    c0785c24: 00000001  0000002e  00000001  f70d6000
    c0785c34: 00000001  0000002e  c0785c64  c04332ce
 #6 [c0785c40] input_handle_event at c04332c9
    [RA: c0433ac6  SP: c0785c44  FP: c0785c68  SIZE: 40]
    c0785c44: 00000001  ffff138d  0000003d  00000001
    c0785c54: f70d6000  00000001  f70d6000  0000002e
    c0785c64: c0785c84  c0433ac6
 #7 [c0785c68] input_event at c0433ac1
    [RA: c0479806  SP: c0785c6c  FP: c0785c88  SIZE: 32]
    c0785c6c: 00000001  00000092  f70d677c  f70d70b4
    c0785c7c: 0000002e  f70d7000  c0785ca8  c0479806
 #8 [c0785c88] hidinput_hid_event at c0479801
    [RA: c0475b31  SP: c0785c8c  FP: c0785cac  SIZE: 36]
    c0785c8c: 00000001  00000007  c0785c00  f70d6000
    c0785c9c: f70d70b4  f70d5000  f70d7000  c0785cc4
    c0785cac: c0475b31
    [RA: 0  SP: c0785ffc  FP: c0785ffc  SIZE: 0]
   PID    PPID  CPU   TASK    ST  %MEM     VSZ    RSS  COMM
>     0      0   0  c073c180  RU   0.0       0      0  [swapper]
      1      0   1  f7038000  IN   0.1    3096   1960  init
      2      0   0  f7038c90  IN   0.0       0      0  [kthreadd]
    271      2   1  f72bf110  IN   0.0       0      0  [bluetooth]
    325      2   1  f71c25b0  IN   0.0       0      0  [khungtaskd]
   1404      2   0  f6b5bed0  IN   0.0       0      0  [kpsmoused]
   1504      2   1  f649cb60  IN   0.0       0      0  [hd-audio0]
   2055      1   0  f6a18000  IN   0.0    1824    536  getty
   2056      1   0  f6a1d7f0  IN   0.0    1824    536  getty
   2061      1   0  f6a1f110  IN   0.1    3132   1604  login
   2062      1   1  f6a18c90  IN   0.0    1824    540  getty
   2063      1   1  f6b58c90  IN   0.0    1824    540  getty
   2130      1   0  f6b5f110  IN   0.0    2200   1032  acpid
   2169      1   0  f69ebed0  IN   0.0    2040    664  syslogd
   2192      1   1  f65b3ed0  IN   0.0    1976    532  dd
   2194      1   1  f6b5a5b0  IN   0.1    3996   2712  klogd
   2217      1   0  f6b74b60  IN   0.1    3008   1120  dbus-daemon
   2251      1   1  f65b3240  IN   0.1   19688   2604  console-kit-dae
RUNQUEUES[0]: c6002320
 RT PRIO_ARRAY: c60023c0
 CFS RB_ROOT: c600237c
  PID: 9      TASK: f703f110  CPU: 0   COMMAND: "events/0"
"""
        self.assertEqual(
            r.crash_signature(),
            "kernel:sysrq_handle_crash:__handle_sysrq:handle_sysrq:kbd_keycode"
            ":kbd_event:input_pass_event:input_handle_event:input_event"
            ":hidinput_hid_event",
        )

        # assertion failures
        r = apport.report.Report()
        r["Signal"] = "6"
        r["SignalName"] = "SIGABRT"
        r["ExecutablePath"] = "/bin/bash"
        r["AssertionMessage"] = "foo.c:42 main: i > 0"
        self.assertEqual(r.crash_signature(), "/bin/bash:foo.c:42 main: i > 0")

        # kernel oops
        report = apport.report.Report("KernelOops")
        report[
            "OopsText"
        ] = """
BUG: unable to handle kernel paging request at ffffb4ff
IP: [<c11e4690>] ext4_get_acl+0x80/0x210
*pde = 01874067 *pte = 00000000
Oops: 0000 [#1] SMP
Modules linked in: bnep rfcomm bluetooth dm_crypt olpc_xo1 scx200_acb\
 snd_cs5535audio snd_ac97_codec ac97_bus snd_pcm snd_seq_midi snd_rawmidi\
 snd_seq_midi_event snd_seq snd_timer snd_seq_device snd cs5535_gpio soundcore\
 snd_page_alloc binfmt_misc geode_aes cs5535_mfd geode_rng msr vesafb usbhid\
 hid 8139too pata_cs5536 8139cp

Pid: 1798, comm: gnome-session-c Not tainted 3.0.0-11-generic #17-Ubuntu First\
 International Computer, Inc.  ION603/ION603
EIP: 0060:[<c11e4690>] EFLAGS: 00010286 CPU: 0
EIP is at ext4_get_acl+0x80/0x210
EAX: f5d3009c EBX: f5d30088 ECX: 00000000 EDX: f5d301d8
ESI: ffffb4ff EDI: 00008000 EBP: f29b3dc8 ESP: f29b3da4
 DS: 007b ES: 007b FS: 00d8 GS: 00e0 SS: 0068
Process gnome-session-c (pid: 1798, ti=f29b2000 task=f2bd72c0 task.ti=f29b2000)
Stack:
 f29b3db0 c113bb90 f5d301d8 f29b3de4 c11b9016 f5d3009c f5d30088 f5d30088
 00000001 f29b3ddc c11e4cca 00000001 f5d30088 000081ed f29b3df0 c11313b7
 00000021 00000021 f5d30088 f29b3e08 c1131b45 c11e4c80 f5d30088 00000021
Call Trace:
 [<c113bb90>] ? d_splice_alias+0x40/0x50
 [<c11b9016>] ? ext4_lookup.part.30+0x56/0x120
 [<c11e4cca>] ext4_check_acl+0x4a/0x90
 [<c11313b7>] acl_permission_check+0x97/0xa0
 [<c1131b45>] generic_permission+0x25/0xc0
 [<c11e4c80>] ? ext4_xattr_set_acl+0x160/0x160
 [<c1131c79>] inode_permission+0x99/0xd0
 [<c11e4c80>] ? ext4_xattr_set_acl+0x160/0x160
 [<c1131d1b>] may_open+0x6b/0x110
 [<c1134566>] do_last+0x1a6/0x640
 [<c113595d>] path_openat+0x9d/0x350
 [<c10de692>] ? unlock_page+0x42/0x50
 [<c10fb960>] ? __do_fault+0x3b0/0x4b0
 [<c1135c41>] do_filp_open+0x31/0x80
 [<c124c743>] ? aa_dup_task_context+0x33/0x60
 [<c1250eed>] ? apparmor_cred_prepare+0x2d/0x50
 [<c112e9ef>] open_exec+0x2f/0x110
 [<c112eef7>] ? check_unsafe_exec+0xb7/0xf0
 [<c112efba>] do_execve_common+0x8a/0x270
 [<c112f1b7>] do_execve+0x17/0x20
 [<c100a0a7>] sys_execve+0x37/0x70
 [<c15336ae>] ptregs_execve+0x12/0x18
 [<c152c8d4>] ? syscall_call+0x7/0xb
Code: 8d 76 00 8d 93 54 01 00 00 8b 32 85 f6 74 e2 8d 43 14 89 55 e4 89 45 f0\
 e8 2e 7e 34 00 8b 55 e4 8b 32 83 fe ff 74 07 85 f6 74 03 <3e> ff 06 8b 45 f0\
 e8 25 19 e4 ff 90 83 fe ff 75 b5 81 ff 00 40
EIP: [<c11e4690>] ext4_get_acl+0x80/0x210 SS:ESP 0068:f29b3da4
CR2: 00000000ffffb4ff
---[ end trace b567e6a3070ffb42 ]---
"""
        self.assertEqual(
            report.crash_signature(),
            "kernel paging request:ext4_get_acl+0x80/0x210"
            ":ext4_check_acl+0x4a/0x90:acl_permission_check+0x97/0xa0"
            ":generic_permission+0x25/0xc0:inode_permission+0x99/0xd0"
            ":may_open+0x6b/0x110:do_last+0x1a6/0x640:path_openat+0x9d/0x350"
            ":do_filp_open+0x31/0x80:open_exec+0x2f/0x110"
            ":do_execve_common+0x8a/0x270:do_execve+0x17/0x20"
            ":sys_execve+0x37/0x70:ptregs_execve+0x12/0x18",
        )

    def test_nonascii_data(self):
        """Methods get along with non-ASCII data."""
        # fake os.uname() into reporting a non-ASCII name
        uname = os.uname()
        uname_mock = os.uname_result(
            (uname[0], b"t\xe2\x99\xaax".decode("UTF-8"), uname[2], uname[3], uname[4])
        )
        with unittest.mock.patch("os.uname", return_value=uname_mock):
            pr = apport.report.Report()
            utf8_val = b"\xc3\xa4 " + uname_mock[1].encode("UTF-8") + b" \xe2\x99\xa5 "
            pr["ProcUnicodeValue"] = utf8_val.decode("UTF-8")
            pr["ProcByteArrayValue"] = utf8_val

            pr.anonymize()

            exp_utf8 = b"\xc3\xa4 hostname \xe2\x99\xa5 "
            self.assertEqual(pr["ProcUnicodeValue"], exp_utf8.decode("UTF-8"))
            self.assertEqual(pr["ProcByteArrayValue"], exp_utf8)

    def test_address_to_offset(self):
        """_address_to_offset()"""
        pr = apport.report.Report()

        self.assertRaises(AssertionError, pr._address_to_offset, 0)

        pr[
            "ProcMaps"
        ] = """
00400000-004df000 r-xp 00000000 08:02 1044485                  /bin/bash
006de000-006df000 r--p 000de000 08:02 1044485                  /bin/bash
01596000-01597000 rw-p 00000000 00:00 0
01597000-015a4000 rw-p 00000000 00:00 0                        [heap]
7f491f868000-7f491f88a000 r-xp 00000000 08:02 526219       \
    /lib/x86_64-linux-gnu/libtinfo.so.5.9
7f491fa8f000-7f491fc24000 r-xp 00000000 08:02 522605       \
    /lib/x86_64-linux-gnu/libc-2.13.so
7f491fc24000-7f491fe23000 ---p 00195000 08:02 522605       \
    /lib/with spaces !/libfoo.so
7fff6e57b000-7fff6e59c000 rw-p 00000000 00:00 0                [stack]
7fff6e5ff000-7fff6e600000 r-xp 00000000 00:00 0                [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0        [vsyscall]
"""

        self.assertEqual(pr._address_to_offset(0x41D703), "/bin/bash+1d703")
        self.assertEqual(
            pr._address_to_offset(0x00007F491FAC5687),
            "/lib/x86_64-linux-gnu/libc-2.13.so+36687",
        )

        self.assertIsNone(pr._address_to_offset(0x006DDFFF))
        self.assertEqual(pr._address_to_offset(0x006DE000), "/bin/bash+0")
        self.assertEqual(pr._address_to_offset(0x006DF000), "/bin/bash+1000")
        self.assertIsNone(pr._address_to_offset(0x006DF001))
        self.assertIsNone(pr._address_to_offset(0))
        self.assertIsNone(pr._address_to_offset(0x10))

        self.assertEqual(
            pr._address_to_offset(0x7F491FC24010), "/lib/with spaces !/libfoo.so+10"
        )

    def test_address_to_offset_arm(self):
        """_address_to_offset() for ARM /proc/pid/maps"""
        pr = apport.report.Report()
        pr[
            "ProcMaps"
        ] = """
00008000-0000e000 r-xp 00000000 08:01 13243326   /usr/lib/dconf/dconf-service
00017000-00038000 rw-p 00000000 00:00 0          [heap]
40017000-4001d000 rw-p 00000000 00:00 0
40026000-400f2000 r-xp 00000000 08:01 13110792\
   /usr/lib/arm-linux-gnueabihf/libgio-2.0.so.0.3400.0
400f2000-400f9000 ---p 000cc000 08:01 13110792\
   /usr/lib/arm-linux-gnueabihf/libgio-2.0.so.0.3400.0
4020d000-4020f000 rw-p 00000000 00:00 0
4020f000-402e5000 r-xp 00000000 08:01 13108294\
   /lib/arm-linux-gnueabihf/libc-2.15.so
402e5000-402ed000 ---p 000d6000 08:01 13108294\
   /lib/arm-linux-gnueabihf/libc-2.15.so
40d21000-40e00000 ---p 00000000 00:00 0
befdf000-bf000000 rw-p 00000000 00:00 0          [stack]
ffff0000-ffff1000 r-xp 00000000 00:00 0          [vectors]
"""
        self.assertEqual(
            pr._address_to_offset(0x402261E6),
            "/lib/arm-linux-gnueabihf/libc-2.15.so+171e6",
        )
        self.assertEqual(
            pr._address_to_offset(0x4002601F),
            "/usr/lib/arm-linux-gnueabihf/libgio-2.0.so.0.3400.0+1f",
        )

    def test_crash_signature_addresses(self):
        """crash_signature_addresses()"""
        pr = apport.report.Report()
        self.assertIsNone(pr.crash_signature_addresses())

        pr["ExecutablePath"] = "/bin/bash"
        pr["Signal"] = "42"
        pr[
            "ProcMaps"
        ] = """
00400000-004df000 r-xp 00000000 08:02 1044485                  /bin/bash
006de000-006df000 r--p 000de000 08:02 1044485                  /bin/bash
01596000-01597000 rw-p 00000000 00:00 0
01597000-015a4000 rw-p 00000000 00:00 0                        [heap]
7f491f868000-7f491f88a000 r-xp 00000000 08:02 526219       \
    /lib/x86_64-linux-gnu/libtinfo.so.5.9
7f491fa8f000-7f491fc24000 r-xp 00000000 08:02 522605       \
    /lib/x86_64-linux-gnu/libc-2.13.so
7f491fc24000-7f491fe23000 ---p 00195000 08:02 522605       \
    /lib/with spaces !/libfoo.so
7fff6e57b000-7fff6e59c000 rw-p 00000000 00:00 0                [stack]
7fff6e5ff000-7fff6e600000 r-xp 00000000 00:00 0                [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0        [vsyscall]
"""

        # no Stacktrace field
        self.assertIsNone(pr.crash_signature_addresses())

        # good stack trace
        pr[
            "Stacktrace"
        ] = """
#0  0x00007f491fac5687 in kill () at ../sysdeps/unix/syscall-template.S:82
No locals.
#1  0x000000000043fd51 in kill_pid ()
#2  g_main_context_iterate (context=0x1731680) at gmain.c:3068
#3  0x000000000042eb76 in ?? ()
#4  0x00000000004324d8 in ??
No symbol table info available.
#5  0x00000000004707e3 in parse_and_execute ()
#6  0x000000000041d703 in _start ()
"""
        self.assertEqual(
            pr.crash_signature_addresses(),
            "/bin/bash:42:/lib/x86_64-linux-gnu/libc-2.13.so+36687"
            ":/bin/bash+3fd51:/bin/bash+2eb76:/bin/bash+324d8:/bin/bash+707e3"
            ":/bin/bash+1d703",
        )

        # all resolvable, but too short
        pr["Stacktrace"] = (
            "#0  0x00007f491fac5687 in kill ()"
            " at ../sysdeps/unix/syscall-template.S:82"
        )
        self.assertIsNone(pr.crash_signature_addresses())

        # one unresolvable, but long enough
        pr[
            "Stacktrace"
        ] = """
#0  0x00007f491fac5687 in kill () at ../sysdeps/unix/syscall-template.S:82
No locals.
#1  0x000001000043fd51 in kill_pid ()
#2  g_main_context_iterate (context=0x1731680) at gmain.c:3068
#3  0x000000000042eb76 in ?? ()
#4  0x00000000004324d8 in ??
No symbol table info available.
#5  0x00000000004707e3 in parse_and_execute ()
#6  0x000000000041d715 in main ()
#7  0x000000000041d703 in _start ()
"""
        sig = pr.crash_signature_addresses()
        self.assertIsNotNone(sig)

        # one true unresolvable, and some "low address" artifacts; should be
        # identical to the one above
        pr[
            "Stacktrace"
        ] = """
#0  0x00007f491fac5687 in kill () at ../sysdeps/unix/syscall-template.S:82
No locals.
#1  0x000001000043fd51 in kill_pid ()
#2  0x0000000000000010 in ??
#3  g_main_context_iterate (context=0x1731680) at gmain.c:3068
#4  0x000000000042eb76 in ?? ()
#5  0x0000000000000000 in ?? ()
#6  0x0000000000000421 in ?? ()
#7  0x00000000004324d8 in ??
No symbol table info available.
#8  0x00000000004707e3 in parse_and_execute ()
#9  0x000000000041d715 in main ()
#10 0x000000000041d703 in _start ()
"""
        self.assertEqual(pr.crash_signature_addresses(), sig)

        # two unresolvables, 2/7 is too much
        pr[
            "Stacktrace"
        ] = """
#0  0x00007f491fac5687 in kill () at ../sysdeps/unix/syscall-template.S:82
No locals.
#1  0x000001000043fd51 in kill_pid ()
#2  g_main_context_iterate (context=0x1731680) at gmain.c:3068
#3  0x000001000042eb76 in ?? ()
#4  0x00000000004324d8 in ??
No symbol table info available.
#5  0x00000000004707e3 in parse_and_execute ()
#6  0x000000000041d715 in main ()
#7  0x000000000041d703 in _start ()
"""
        self.assertIsNone(pr.crash_signature_addresses())

    @staticmethod
    @unittest.mock.patch("os.geteuid")
    def test_missing_uid(geteuid_mock: MagicMock) -> None:
        """check_ignored() works for removed user"""
        geteuid_mock.return_value = 123456789
        pr = apport.report.Report()
        pr["ExecutablePath"] = "/bin/bash"
        pr.check_ignored()
        geteuid_mock.assert_called_once_with()

    def test_suspend_resume(self):
        pr = apport.report.Report()
        pr["ProblemType"] = "KernelOops"
        pr["Failure"] = "suspend/resume"
        pr["MachineType"] = "Cray XT5"
        pr["dmi.bios.version"] = "ABC123 (1.0)"
        expected = "suspend/resume:Cray XT5:ABC123 (1.0)"
        self.assertEqual(expected, pr.crash_signature())

        # There will not always be a BIOS version
        del pr["dmi.bios.version"]
        expected = "suspend/resume:Cray XT5"
        self.assertEqual(expected, pr.crash_signature())

    def test_add_hooks_info_invalid_source(self) -> None:
        """Test Report.add_hooks_info() with invalid source package name."""
        report = apport.report.Report()
        result = report.add_hooks_info(package="bash", srcpackage="in/valid")

        self.assertFalse(result)
        self.assertEqual(
            report.get("UnreportableReason"), "invalid SourcePackage: in/valid"
        )

    def test_add_snap_contact_info_launchpad(self):
        """add_snap_contact_info()

        Test that report is against Launchpad
        """
        pr = apport.report.Report()
        snap = (
            "https://bugs.launchpad.net/ubuntu/+source/"
            "chromium-browser/+bugs?field.tag=snap"
        )
        pr.add_snap_contact_info(snap)
        self.assertEqual("ubuntu/+source/chromium-browser", pr["SnapSource"])
        self.assertEqual("snap", pr["SnapTags"])

    def test_add_snap_contact_launchpad_distro(self) -> None:
        """add_snap_contact_info() with https://launchpad.net/distros/ contact"""
        report = apport.report.Report()
        snap_contact = "https://launchpad.net/distros/ubuntu/+source/thunderbird"

        report.add_snap_contact_info(snap_contact)

        self.assertEqual(set(report.keys()), {"ProblemType", "Date", "SnapSource"})
        self.assertEqual("ubuntu/+source/thunderbird", report["SnapSource"])

    def test_add_snap_contact_info_github(self):
        """add_snap_contact_info()

        Test that report is against Github
        """
        pr = apport.report.Report()
        snap = "https://github.com/lxc/lxd/issues"
        pr.add_snap_contact_info(snap)
        self.assertEqual("lxc", pr["SnapGitOwner"])
        self.assertEqual("lxd", pr["SnapGitName"])
        self.assertEqual("snap-github", pr["CrashDB"])

    @unittest.mock.patch("os.stat")
    def test_report_from_systemd_coredump_default(self, stat_mock: MagicMock) -> None:
        """Test converting systemd-coredump with default settings."""
        stat_mock.return_value = DIVIDE_BY_ZERO_EXECUTABLE_STAT
        coredump = DIVIDE_BY_ZERO_SYSTEMD_COREDUMP.copy()
        with tempfile.TemporaryDirectory() as tmpdir:
            coredump_file = (
                pathlib.Path(tmpdir)
                / "core.divide-by-zero.1000.7ec30fc09da94efb8b4bdb75d2b8dc40"
                ".284582.1698669603000000.zst"
            )
            coredump_file.write_bytes(
                b"(\xb5/\xfd$T-\x02\x00\xd2\x04\x0f\x11\xa0\xed\x80Ie\xb7[\xf8\x97\xe6"
                b"\x1e\xae\x92\x8d\xfdn\x8e@\xa0\xa7zr\xbf\xd5\xa3\x97\xf0\x9c\x9b:\xef"
                b"\xca}f{\xbe\xefI\x17\xb9\x88\x8e\x9a\xb3\x84\xe5mY~\xdf\xf0}\xaaO\x95"
                b"\xfaa\xd3\x8e\x01\x00\r\x99z\x02\xb1\xef\x7f\xc4"
            )
            coredump["COREDUMP_FILENAME"] = str(coredump_file)

            report = apport.report.Report.from_systemd_coredump(coredump)
            report_output = io.BytesIO()
            report.write(report_output)

        expected_report = (
            DIVIDE_BY_ZERO_REPORT + "CoreDump: base64\n"
            " KLUv/SRULQIA0gQPEaDtgEllt1v4l+YerpKN/W6OQKCnenK/1aOX8JybOu/"
            "KfWZ7vu9JF7mIjpqzhOVtWX7f8H2qT5X6YdOOAQANmXoCse9/xA==\n"
        )
        self.assertEqual(report_output.getvalue().decode(), expected_report)
        stat_mock.assert_called_once_with("/usr/bin/divide-by-zero")

    @unittest.mock.patch("os.stat")
    def test_report_from_systemd_coredump_missing_crash(
        self, stat_mock: MagicMock
    ) -> None:
        """Test converting systemd-coredump with a missing crash file."""
        stat_mock.return_value = DIVIDE_BY_ZERO_EXECUTABLE_STAT
        coredump = DIVIDE_BY_ZERO_SYSTEMD_COREDUMP.copy()
        coredump["COREDUMP_FILENAME"] = "/non-existing/core.tracker-extract.1000.zst"

        with self.assertLogs(level="WARNING") as warning_logs:
            report = apport.report.Report.from_systemd_coredump(coredump)
            report_output = io.BytesIO()
            report.write(report_output)

        self.assertEqual(report_output.getvalue().decode(), DIVIDE_BY_ZERO_REPORT)
        stat_mock.assert_called_once_with("/usr/bin/divide-by-zero")
        self.assertIn(
            "Ignoring COREDUMP_FILENAME '/non-existing/core.tracker-extract.1000.zst'"
            " because it does not exist.",
            warning_logs.output[0],
        )

    @unittest.mock.patch("os.stat")
    def test_report_from_systemd_coredump_storage_journal(
        self, stat_mock: MagicMock
    ) -> None:
        """Test converting systemd-coredump with Storage=journal."""
        stat_mock.return_value = DIVIDE_BY_ZERO_EXECUTABLE_STAT
        coredump = DIVIDE_BY_ZERO_SYSTEMD_COREDUMP.copy()
        coredump["COREDUMP"] = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"

        report = apport.report.Report.from_systemd_coredump(coredump)
        report_output = io.BytesIO()
        report.write(report_output)

        expected_report = (
            DIVIDE_BY_ZERO_REPORT + "CoreDump: base64\n"
            " H4sICAAAAAAC/0NvcmVEdW1wAA==\n"
            " q3f1cWNiZGSAAgC2f6EYDwAAAA==\n"
        )
        self.assertEqual(report_output.getvalue().decode(), expected_report)
        stat_mock.assert_called_once_with("/usr/bin/divide-by-zero")

    @unittest.mock.patch("os.stat")
    def test_report_from_systemd_coredump_storage_none(
        self, stat_mock: MagicMock
    ) -> None:
        """Test converting systemd-coredump with Storage=none."""
        stat_mock.return_value = DIVIDE_BY_ZERO_EXECUTABLE_STAT
        report = apport.report.Report.from_systemd_coredump(
            DIVIDE_BY_ZERO_SYSTEMD_COREDUMP
        )
        report_output = io.BytesIO()
        report.write(report_output)
        self.assertEqual(report_output.getvalue().decode(), DIVIDE_BY_ZERO_REPORT)
        stat_mock.assert_called_once_with("/usr/bin/divide-by-zero")

    def test_add_kernel_crash_info_no_vmcore(self) -> None:
        """add_kernel_crash_info() on a non-kernel crash."""
        report = apport.report.Report()
        self.assertFalse(report.add_kernel_crash_info())

    @unittest.mock.patch("subprocess.run")
    def test_add_kernel_crash_info(self, run_mock: MagicMock) -> None:
        """add_kernel_crash_info() on a fake vmcore."""
        run_mock.return_value = subprocess.CompletedProcess(
            args=MagicMock(), returncode=0, stdout=b"kernel stack trace", stderr=b""
        )
        report = apport.report.Report("KernelCrash")
        report["VmCore"] = problem_report.CompressedValue(b"\x01" * 100, name="VmCore")
        # add_os_info() keys Architecture, DistroRelease, Uname from Ubuntu 24.04
        report["Architecture"] = "amd64"
        report["DistroRelease"] = "Ubuntu 24.04"
        report["Uname"] = "Linux 6.8.0-31-generic x86_64"

        self.assertTrue(report.add_kernel_crash_info())

        self.assertEqual(report.get("Stacktrace"), b"kernel stack trace")
        run_mock.assert_called_once()
        called_cmd = run_mock.call_args[0][0]
        self.assertEqual(
            called_cmd[:-1], ["crash", "/usr/lib/debug/boot/vmlinux-6.8.0-31-generic"]
        )
        tmpfile = called_cmd[-1]
        self.assertRegex(tmpfile, r"^/.*/apport_vmcore_\w{8}$")
        self.assertFalse(pathlib.Path(tmpfile).exists())

    @unittest.mock.patch("subprocess.run")
    def test_add_kernel_crash_info_fail(self, run_mock: MagicMock) -> None:
        """add_kernel_crash_info() on a fake vmcore where crash fails."""
        run_mock.return_value = subprocess.CompletedProcess(
            args=MagicMock(),
            returncode=1,
            stdout=b"read_maps: unable to read header from $vmcore, errno = 0",
            stderr=b"",
        )
        report = apport.report.Report("KernelCrash")
        report["VmCore"] = b"\x01" * 100
        # add_os_info() keys Architecture, DistroRelease, Uname from Ubuntu 24.04
        report["Architecture"] = "amd64"
        report["DistroRelease"] = "Ubuntu 24.04"
        report["Uname"] = "Linux 6.8.0-31-generic x86_64"

        self.assertFalse(report.add_kernel_crash_info())

        self.assertNotIn("Stacktrace", report)
        run_mock.assert_called_once()
        called_cmd = run_mock.call_args[0][0]
        self.assertEqual(
            called_cmd[:-1], ["crash", "/usr/lib/debug/boot/vmlinux-6.8.0-31-generic"]
        )
        tmpfile = called_cmd[-1]
        self.assertRegex(tmpfile, r"^/.*/apport_vmcore_\w{8}$")
        self.assertFalse(pathlib.Path(tmpfile).exists())
