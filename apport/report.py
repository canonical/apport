"""Representation of and data collection for a problem report."""

# Copyright (C) 2006 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import atexit
import errno
import fnmatch
import glob
import grp
import importlib.util
import io
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import traceback
import urllib.error
import urllib.parse
import urllib.request
import xml.dom
import xml.dom.minidom
import xml.parsers.expat

import apport.fileutils
import apport.logging
import problem_report
from apport.hookutils import kill_pkttyagent
from apport.packaging_impl import impl as packaging

_data_dir = os.environ.get("APPORT_DATA_DIR", "/usr/share/apport")
GENERAL_HOOK_DIR = f"{_data_dir}/general-hooks/"
PACKAGE_HOOK_DIR = f"{_data_dir}/package-hooks/"
_opt_dir = "/opt"

# path of the ignore file
_ignore_file = os.environ.get("APPORT_IGNORE_FILE", "~/.apport-ignore.xml")

# system-wide blacklist
_blacklist_dir = "/etc/apport/blacklist.d"
_whitelist_dir = "/etc/apport/whitelist.d"

# programs that we consider interpreters
interpreters = [
    "sh",
    "bash",
    "dash",
    "csh",
    "tcsh",
    "python*",
    "ruby*",
    "php",
    "perl*",
    "mono*",
    "awk",
]

#
# helper functions
#


def _transitive_dependencies(package, depends_set):
    """Recursively add dependencies of package to depends_set."""
    try:
        packaging.get_version(package)
    except ValueError:
        return
    for d in packaging.get_dependencies(package):
        if d not in depends_set:
            depends_set.add(d)
            _transitive_dependencies(d, depends_set)


def _read_proc_link(path, pid=None, dir_fd=None):
    """Use readlink() to resolve link.

    Return a string representing the path to which the symbolic link points.
    """
    if dir_fd is not None:
        return os.readlink(path, dir_fd=dir_fd)

    return os.readlink("/proc/%s/%s" % (pid, path))


def _read_proc_file(path, pid=None, dir_fd=None):
    """Read file content.

    Return its content, or return a textual error if it failed.
    """
    try:
        if dir_fd is not None:
            proc_file = os.open(
                path, os.O_RDONLY | os.O_CLOEXEC, dir_fd=dir_fd
            )
        else:
            proc_file = "/proc/%s/%s" % (pid, path)

        with io.open(proc_file, "rb") as fd:
            return fd.read().strip().decode("UTF-8", errors="replace")
    except OSError as error:
        return "Error: " + str(error)


def _read_maps(proc_pid_fd):
    """Read /proc/pid/maps.

    Since /proc/$pid/maps may become unreadable unless we are ptracing the
    process, detect this, and attempt to attach/detach.
    """
    maps = "Error: unable to read /proc maps file"

    try:
        with open(
            "maps",
            opener=lambda path, mode: os.open(path, mode, dir_fd=proc_pid_fd),
            encoding="utf-8",
        ) as fd:
            maps = fd.read().strip()
    except OSError as error:
        return "Error: " + str(error)
    return maps


def _command_output(  # pylint: disable=redefined-builtin
    command, input=None, env=None
):
    """Run command and capture its output.

    Try to execute given command (argv list) and return its stdout, or return
    a textual error if it failed.
    """
    try:
        # gdb can timeout when trying to retrace some core files, giving it
        # 30 minutes to run should be more than enough.
        sp = subprocess.run(
            command,
            check=False,
            env=env,
            input=input,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=1800,
        )
    except subprocess.TimeoutExpired as error:
        out = error.stdout.decode("UTF-8", errors="replace")
        raise OSError(
            f"Error: command {str(error.cmd)} timed out"
            f" after {error.timeout} seconds: {out}"
        ) from error
    if sp.returncode == 0:
        return sp.stdout
    out = sp.stdout.decode("UTF-8", errors="replace")
    raise OSError(
        "Error: command %s failed with exit code %i: %s"
        % (str(command), sp.returncode, out)
    )


def _check_bug_pattern(report, pattern):
    """Check if given report matches the given bug pattern XML DOM node.

    Return the bug URL on match, otherwise None.
    """
    if "url" not in pattern.attributes:
        return None

    for c in pattern.childNodes:
        # regular expression condition
        if c.nodeType == xml.dom.Node.ELEMENT_NODE and c.nodeName == "re":
            try:
                key = c.attributes["key"].nodeValue
            except KeyError:
                continue
            if key not in report:
                return None
            c.normalize()
            if (
                c.hasChildNodes()
                and c.childNodes[0].nodeType == xml.dom.Node.TEXT_NODE
            ):
                regexp = c.childNodes[0].nodeValue
                v = report[key]
                if isinstance(v, problem_report.CompressedValue):
                    v = v.get_value()
                    regexp = regexp.encode("UTF-8")
                elif isinstance(v, bytes):
                    regexp = regexp.encode("UTF-8")
                try:
                    re_c = re.compile(regexp)
                except (re.error, TypeError, ValueError):
                    continue
                if not re_c.search(v):
                    return None

    return pattern.attributes["url"].nodeValue


def _check_bug_patterns(report, patterns):
    try:
        dom = xml.dom.minidom.parseString(patterns)
    except (xml.parsers.expat.ExpatError, UnicodeEncodeError):
        return None

    for pattern in dom.getElementsByTagName("pattern"):
        url = _check_bug_pattern(report, pattern)
        if url:
            return url

    return None


def _dom_remove_space(node):
    """Recursively remove whitespace from given XML DOM node."""
    for c in node.childNodes:
        if c.nodeType == xml.dom.Node.TEXT_NODE and c.nodeValue.strip() == "":
            c.unlink()
            node.removeChild(c)
        else:
            _dom_remove_space(c)


def _run_hook(report, ui, hook):
    if not os.path.exists(hook):
        return False

    symb = {}
    try:
        with open(hook, encoding="utf-8") as fd:
            # legacy, pylint: disable=exec-used
            exec(compile(fd.read(), hook, "exec"), symb)
        try:
            symb["add_info"](report, ui)
        except TypeError as error:
            if str(error).startswith("add_info()"):
                # older versions of apport did not pass UI, and hooks that
                # do not require it don't need to take it
                symb["add_info"](report)
            else:
                raise
    except StopIteration:
        return True
    except Exception:  # pylint: disable=broad-except
        hookname = os.path.splitext(os.path.basename(hook))[0].replace(
            "-", "_"
        )
        report["HookError_" + hookname] = traceback.format_exc()
        apport.logging.error("hook %s crashed:", hook)
        traceback.print_exc()

    return False


def _which_extrapath(command, extra_path):
    """Return path of command, preferring extra_path."""
    path = None
    if extra_path:
        path = os.pathsep.join([extra_path, os.environ.get("PATH", "")])

    return shutil.which(command, path=path)


#
# Report class
#


class Report(problem_report.ProblemReport):
    """A problem report specific to apport (crash or bug).

    This class wraps a standard ProblemReport and adds methods for collecting
    standard debugging data.
    """

    def __init__(self, problem_type="Crash", date=None):
        """Initialize a fresh problem report.

        date is the desired date/time string; if None (default), the current
        local time is used.

        If the report is attached to a process ID, this should be set in
        self.pid, so that e. g. hooks can use it to collect additional data.
        """
        problem_report.ProblemReport.__init__(self, problem_type, date)
        self.pid = None
        self._proc_maps_cache = None

    @staticmethod
    def _customized_package_suffix(package):
        """Return a string suitable for appending to Package/Dependencies.

        If package has only unmodified files, return the empty string. If not,
        return ' [modified: ...]' with a list of modified files.
        """
        suffix = ""
        mod = packaging.get_modified_files(package)
        if mod:
            suffix += " [modified: %s]" % " ".join(mod)
        try:
            if not packaging.is_distro_package(package):
                origin = packaging.get_package_origin(package)
                if origin:
                    suffix += " [origin: %s]" % origin
                else:
                    suffix += " [origin: unknown]"
        except ValueError:
            # no-op for nonexisting packages
            pass

        return suffix

    def add_package(self, package):
        """Add Package: field.

        Determine the version of the given package (uses "(not installed") for
        uninstalled packages) and add Package: field to report.
        This also checks for any modified files.

        Return determined package version (None for uninstalled).
        """
        try:
            version = packaging.get_version(package)
        except ValueError:
            # package not installed
            version = None
        self["Package"] = "%s %s%s" % (
            package,
            version or "(not installed)",
            self._customized_package_suffix(package),
        )

        return version

    def add_package_info(self, package=None):
        """Add packaging information.

        If package is not given, the report must have ExecutablePath.
        This adds:
        - Package: package name and installed version
        - SourcePackage: source package name (if possible to determine)
        - PackageArchitecture: processor architecture this package was built
          for
        - Dependencies: package names and versions of all dependencies and
          pre-dependencies; this also checks if the files are unmodified and
          appends a list of all modified files
        """
        if not package:
            # the kernel does not have a executable path but a package
            if (
                "ExecutablePath" not in self
                and self["ProblemType"] == "KernelCrash"
            ):
                package = self["Package"]
            else:
                package = apport.fileutils.find_file_package(
                    self["ExecutablePath"]
                )
            if not package:
                return

        version = self.add_package(package)

        if version or "SourcePackage" not in self:
            try:
                self["SourcePackage"] = packaging.get_source(package)
            except ValueError:
                # might not exist for non-free third-party packages or snaps
                pass
        if not version:
            return

        self["PackageArchitecture"] = packaging.get_architecture(package)

        # get set of all transitive dependencies
        dependencies = set([])
        _transitive_dependencies(package, dependencies)

        # get dependency versions
        self["Dependencies"] = ""
        for dep in sorted(dependencies):
            try:
                v = packaging.get_version(dep)
            except ValueError:
                # can happen with uninstalled alternate dependencies
                continue

            if self["Dependencies"]:
                self["Dependencies"] += "\n"
            self["Dependencies"] += "%s %s%s" % (
                dep,
                v,
                self._customized_package_suffix(dep),
            )

    def add_snap_info(self, snap):
        """Add info about an installed Snap.

        This adds a Snap: field, containing name, version and channel.
        It adds a SnapSource: field, if the snap has a Launchpad contact
        defined.
        """
        self["Snap"] = "%s %s (%s)" % (
            snap.get("name"),
            snap.get("version"),
            snap.get("channel", "unknown"),
        )
        snapname = snap.get("name")
        self["Snap.Changes"] = _command_output(
            ["snap", "changes", "--abs-time", snapname]
        )
        self["Snap.Connections"] = _command_output(
            ["snap", "connections", snapname]
        )
        self["Snap.Info.%s" % snapname] = _command_output(
            ["snap", "info", "--abs-time", snapname]
        )
        import yaml  # pylint: disable=import-outside-toplevel

        with open(
            "/snap/%s/current/meta/snap.yaml" % snapname, encoding="utf-8"
        ) as f:
            snap_meta = yaml.safe_load(f)
        if "base" in snap_meta:
            base = snap_meta["base"]
            self["Snap.Info.%s" % base] = _command_output(
                ["snap", "info", "--abs-time", base]
            )
        providers = []
        if "plugs" in snap_meta:
            for plug in snap_meta["plugs"]:
                dp = snap_meta["plugs"][plug].get("default-provider")
                if dp and dp not in providers:
                    providers.append(dp)
        for provider in providers:
            self["Snap.Info.%s" % provider] = _command_output(
                ["snap", "info", "--abs-time", provider]
            )
        # Automatically handle snaps which have a Launchpad contact defined
        if snap.get("contact"):
            self.add_snap_contact_info(snap.get("contact"))

    def add_snap_contact_info(self, snap_contact: str) -> None:
        """Load report with information about where it should be filed.

        Parse project (e.g. 'subiquity') or source package string
        (e.g. 'ubuntu/+source/gnome-calculator') from snap 'contact'.
        Additionaly, extract any tag/tags defined in the contact URL.
        """
        p = (
            r"^https?:\/\/.*launchpad\.net\/"
            r"((?:[^\/]+\/\+source\/)?[^\/]+)(?:.*field\.tags?=([^&]+))?"
        )
        m = re.search(p, urllib.parse.unquote(snap_contact))
        if m and m.group(1):
            self["SnapSource"] = m.group(1)
            if m.group(2):
                self["SnapTags"] = m.group(2)

    def add_os_info(self):
        """Add operating system information.

        This adds:
        - DistroRelease: NAME and VERSION from /etc/os-release, or
          'lsb_release -sir' output
        - Architecture: system architecture in distro specific notation
        - Uname: uname -srm output
        """
        if "DistroRelease" not in self:
            self["DistroRelease"] = "%s %s" % apport.packaging.get_os_version()
        if "Uname" not in self:
            u = os.uname()
            self["Uname"] = "%s %s %s" % (u[0], u[2], u[4])
        if "Architecture" not in self:
            self["Architecture"] = packaging.get_system_architecture()

    def add_user_info(self):
        """Add information about the user.

        This adds:
        - UserGroups: system groups the user is in
        """
        # Use effective uid in case privileges were dropped
        user = pwd.getpwuid(os.geteuid())[0]
        groups = [
            name
            for name, p, gid, memb in grp.getgrall()
            if user in memb and gid < 1000
        ]
        groups.sort()
        if groups:
            self["UserGroups"] = " ".join(groups)
        else:
            # the docs indicate this is optional but a lot of tests expect
            # UserGroups to exist
            self["UserGroups"] = "N/A"

    def _check_interpreted(self):
        """Check if process is a script.

        Use ExecutablePath, ProcStatus and ProcCmdline to determine if
        process is an interpreted script. If so, set InterpreterPath
        accordingly.
        """
        if "ExecutablePath" not in self:
            return

        exebasename = os.path.basename(self["ExecutablePath"])

        # check if we consider ExecutablePath an interpreter; we have to do
        # this, otherwise 'gedit /tmp/foo.txt' would be detected as interpreted
        # script as well
        if not any(
            filter(lambda i: fnmatch.fnmatch(exebasename, i), interpreters)
        ):
            return

        # first, determine process name
        name = None
        for line in self["ProcStatus"].splitlines():
            try:
                (k, v) = line.split("\t", 1)
            except ValueError:
                continue
            if k == "Name:":
                name = v
                break
        if not name:
            return

        cmdargs = self["ProcCmdline"].split("\0")
        bindirs = ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"]

        # filter out interpreter options
        while len(cmdargs) >= 2 and cmdargs[1].startswith("-"):
            # check for -m
            if (
                name.startswith("python")
                and cmdargs[1] == "-m"
                and len(cmdargs) >= 3
            ):
                path = self._python_module_path(cmdargs[2])
                if path:
                    self["InterpreterPath"] = self["ExecutablePath"]
                    self["ExecutablePath"] = path
                else:
                    self["UnreportableReason"] = (
                        "Cannot determine path of python module %s"
                        % cmdargs[2]
                    )
                return

            del cmdargs[1]

        # catch scripts explicitly called with interpreter
        if len(cmdargs) >= 2:
            # ensure that cmdargs[1] is an absolute path
            if cmdargs[1].startswith(".") and "ProcCwd" in self:
                cmdargs[1] = os.path.join(self["ProcCwd"], cmdargs[1])
            if os.access(cmdargs[1], os.R_OK):
                self["InterpreterPath"] = self["ExecutablePath"]
                self["ExecutablePath"] = os.path.realpath(cmdargs[1])

        # catch directly executed scripts
        if "InterpreterPath" not in self and name != exebasename:
            for p in bindirs:
                if os.access(p + cmdargs[0], os.R_OK):
                    argvexe = p + cmdargs[0]
                    if os.path.basename(os.path.realpath(argvexe)) == name:
                        self["InterpreterPath"] = self["ExecutablePath"]
                        self["ExecutablePath"] = argvexe
                    break

        # special case: crashes from twistd are usually the fault of the
        # launched program
        if (
            "InterpreterPath" in self
            and os.path.basename(self["ExecutablePath"]) == "twistd"
        ):
            self["InterpreterPath"] = self["ExecutablePath"]
            exe = self._twistd_executable()
            if exe:
                self["ExecutablePath"] = exe
            else:
                self[
                    "UnreportableReason"
                ] = "Cannot determine twistd client program"

    def _twistd_executable(self):
        """Determine the twistd client program from ProcCmdline."""
        args = self["ProcCmdline"].split("\0")[2:]

        # search for a -f/--file, -y/--python or -s/--source argument
        while args:
            arg = args[0].split("=", 1)
            if (
                arg[0].startswith("--file")
                or arg[0].startswith("--python")
                or arg[0].startswith("--source")
            ):
                if len(arg) == 2:
                    return arg[1]
                return args[1]
            if len(arg[0]) > 1 and arg[0][0] == "-" and arg[0][1] != "-":
                opts = arg[0][1:]
                if "f" in opts or "y" in opts or "s" in opts:
                    return args[1]

            args.pop(0)

        return None

    @staticmethod
    def _python_module_path(module):
        """Determine path of given Python module."""
        try:
            spec = importlib.util.find_spec(module)
        except ImportError:
            return None
        if spec is None:
            return None
        return spec.origin

    def add_proc_info(self, pid=None, proc_pid_fd=None, extraenv=None):
        """Add /proc/pid information.

        If neither pid nor self.pid are given, it defaults to the process'
        current pid and sets self.pid.

        This adds the following fields:
        - ExecutablePath: /proc/pid/exe contents; if the crashed process is
          interpreted, this contains the script path instead
        - InterpreterPath: /proc/pid/exe contents if the crashed process is
          interpreted; otherwise this key does not exist
        - ExecutableTimestamp: time stamp of ExecutablePath, for comparing at
          report time
        - ProcEnviron: A subset of the process' environment (only some standard
          variables that do not disclose potentially sensitive information,
          plus the ones mentioned in extraenv)
        - ProcCmdline: /proc/pid/cmdline contents
        - ProcStatus: /proc/pid/status contents
        - ProcMaps: /proc/pid/maps contents
        - ProcAttrCurrent: /proc/pid/attr/current contents, if not "unconfined"
        - CurrentDesktop: Value of $XDG_CURRENT_DESKTOP, if present
        - _LogindSession: logind cgroup path, if present (Used for filtering
          out crashes that happened in a session that is not running any more)
        """
        if not proc_pid_fd:
            if not pid:
                pid = self.pid or os.getpid()
            if not self.pid:
                self.pid = int(pid)
            pid = str(pid)
            try:
                proc_pid_fd = os.open(
                    "/proc/%s" % pid, os.O_RDONLY | os.O_PATH | os.O_DIRECTORY
                )
            except PermissionError as error:
                raise ValueError("not accessible") from error
            except OSError as error:
                if error.errno == errno.ENOENT:
                    raise ValueError("invalid process") from error
                raise

        try:
            self["ProcCwd"] = _read_proc_link("cwd", pid, proc_pid_fd)
        except OSError:
            pass
        self.add_proc_environ(
            pid=pid, proc_pid_fd=proc_pid_fd, extraenv=extraenv
        )
        self["ProcStatus"] = _read_proc_file("status", pid, proc_pid_fd)
        self["ProcCmdline"] = _read_proc_file(
            "cmdline", pid, proc_pid_fd
        ).rstrip("\0")
        self["ProcMaps"] = _read_maps(proc_pid_fd)
        if "ExecutablePath" not in self:
            try:
                self["ExecutablePath"] = _read_proc_link(
                    "exe", pid, proc_pid_fd
                )
            except PermissionError as error:
                raise ValueError("not accessible") from error
            except OSError as error:
                if error.errno == errno.ENOENT:
                    raise ValueError("invalid process") from error
                raise
        for p in ("rofs", "rwfs", "squashmnt", "persistmnt"):
            if self["ExecutablePath"].startswith("/%s/" % p):
                self["ExecutablePath"] = self["ExecutablePath"][
                    len("/%s" % p) :
                ]
                break
        if not os.path.exists(self["ExecutablePath"]):
            raise ValueError("%s does not exist" % self["ExecutablePath"])

        # check if we have an interpreted program
        self._check_interpreted()

        self["ExecutableTimestamp"] = str(
            int(os.stat(self["ExecutablePath"]).st_mtime)
        )

        # make ProcCmdline ASCII friendly, do shell escaping
        self["ProcCmdline"] = (
            self["ProcCmdline"]
            .replace("\\", "\\\\")
            .replace(" ", "\\ ")
            .replace("\0", " ")
        )

        # grab AppArmor or SELinux context
        # If no LSM is loaded, reading will return -EINVAL
        try:
            # On Linux 2.6.28+, 'current' is world readable, but read() gives
            # EPERM; Python 2.5.3+ crashes on that (LP: #314065)
            if os.getuid() == 0:
                val = _read_proc_file("attr/current", pid, proc_pid_fd)
                if val != "unconfined":
                    self["ProcAttrCurrent"] = val
        except OSError:
            pass

        ret = self.get_logind_session(pid, proc_pid_fd)
        if ret:
            self["_LogindSession"] = ret[0]

    def add_proc_environ(self, pid=None, extraenv=None, proc_pid_fd=None):
        """Add environment information.

        If pid is not given, it defaults to the process' current pid.

        This adds the following fields:
        - ProcEnviron: A subset of the process' environment (only some standard
          variables that do not disclose potentially sensitive information,
          plus the ones mentioned in extraenv)
        - CurrentDesktop: Value of $XDG_CURRENT_DESKTOP, if present
        """
        safe_vars = [
            "SHELL",
            "TERM",
            "LANGUAGE",
            "LANG",
            "LC_CTYPE",
            "LC_COLLATE",
            "LC_TIME",
            "LC_NUMERIC",
            "LC_MONETARY",
            "LC_MESSAGES",
            "LC_PAPER",
            "LC_NAME",
            "LC_ADDRESS",
            "LC_TELEPHONE",
            "LC_MEASUREMENT",
            "LC_IDENTIFICATION",
            "LOCPATH",
        ]
        if extraenv:
            safe_vars += extraenv

        if not proc_pid_fd:
            if not pid:
                pid = os.getpid()
            pid = str(pid)
            proc_pid_fd = os.open(
                "/proc/%s" % pid, os.O_RDONLY | os.O_PATH | os.O_DIRECTORY
            )

        self["ProcEnviron"] = ""
        env = _read_proc_file("environ", pid, proc_pid_fd).replace("\n", "\\n")
        if env.startswith("Error:"):
            self["ProcEnviron"] = env
        else:
            for line in env.split("\0"):
                if line.split("=", 1)[0] in safe_vars:
                    if self["ProcEnviron"]:
                        self["ProcEnviron"] += "\n"
                    self["ProcEnviron"] += line
                elif line.startswith("PATH="):
                    p = line.split("=", 1)[1]
                    if "/home" in p or "/tmp" in p:
                        if self["ProcEnviron"]:
                            self["ProcEnviron"] += "\n"
                        self["ProcEnviron"] += "PATH=(custom, user)"
                    elif (
                        p != "/usr/local/sbin:/usr/local/bin"
                        ":/usr/sbin:/usr/bin:/sbin:/bin:/usr/games"
                    ):
                        if self["ProcEnviron"]:
                            self["ProcEnviron"] += "\n"
                        self["ProcEnviron"] += "PATH=(custom, no user)"
                elif line.startswith("XDG_RUNTIME_DIR="):
                    if self["ProcEnviron"]:
                        self["ProcEnviron"] += "\n"
                    self["ProcEnviron"] += "XDG_RUNTIME_DIR=<set>"
                elif line.startswith("LD_PRELOAD="):
                    if self["ProcEnviron"]:
                        self["ProcEnviron"] += "\n"
                    self["ProcEnviron"] += "LD_PRELOAD=<set>"
                elif line.startswith("LD_LIBRARY_PATH="):
                    if self["ProcEnviron"]:
                        self["ProcEnviron"] += "\n"
                    self["ProcEnviron"] += "LD_LIBRARY_PATH=<set>"
                elif line.startswith("XDG_CURRENT_DESKTOP="):
                    self["CurrentDesktop"] = line.split("=", 1)[1]

    def add_kernel_crash_info(self):
        """Add information from kernel crash.

        This needs a VmCore in the Report.
        """
        if "VmCore" not in self:
            return False
        unlink_core = False
        ret = False
        try:
            if hasattr(self["VmCore"], "find"):
                (fd, core) = tempfile.mkstemp()
                os.write(fd, self["VmCore"])
                os.close(fd)
                unlink_core = True
            kver = self["Uname"].split()[1]
            command = ["crash", "/usr/lib/debug/boot/vmlinux-%s" % kver, core]
            try:
                crash = subprocess.run(
                    command,
                    check=False,
                    input=b"bt -a -f\nps\nrunq\nquit\n",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
            except OSError:
                return False
            ret = crash.returncode == 0
            if ret:
                # FIXME: split it up nicely etc
                self["Stacktrace"] = crash.stdout
        finally:
            if unlink_core:
                os.unlink(core)
        return ret

    def add_gdb_info(self, rootdir=None, gdb_sandbox=None):
        """Add information from gdb.

        This requires that the report has a CoreDump and an
        ExecutablePath. This adds the following fields:
        - Registers: Output of gdb's 'info registers' command
        - Disassembly: Output of gdb's 'x/16i $pc' command
        - Stacktrace: Output of gdb's 'bt full' command
        - ThreadStacktrace: Output of gdb's 'thread apply all bt full' command
        - StacktraceTop: simplified stacktrace (topmost 5 functions) for inline
          inclusion into bug reports and easier processing
        - AssertionMessage: Value of __abort_msg, __glib_assert_msg, or
          __nih_abort_msg if present

        The optional rootdir can specify a root directory which has the
        executable, libraries, and debug symbols. This does not require
        chroot() or root privileges, it just instructs gdb to search for the
        files there.

        Raises a OSError if the core dump is invalid/truncated, or OSError if
        calling gdb fails, or FileNotFoundError if gdb or the crashing
        executable cannot be found.
        """
        if "CoreDump" not in self or "ExecutablePath" not in self:
            return

        gdb_reports = {
            "Registers": "info registers",
            "Disassembly": "x/16i $pc",
            "Stacktrace": "bt full",
            "ThreadStacktrace": "thread apply all bt full",
            "AssertionMessage": "print __abort_msg->msg",
            "GLibAssertionMessage": "print __glib_assert_msg",
            "NihAssertionMessage": "print (char*) __nih_abort_msg",
        }
        gdb_cmd, environ = self.gdb_command(rootdir, gdb_sandbox)
        if not gdb_cmd:
            raise FileNotFoundError(
                errno.ENOENT,
                os.strerror(errno.ENOENT),
                "gdb not found in retracing env",
            )

        gdb_cmd += [
            "--batch",
            # limit maximum backtrace depth (to avoid looped stacks)
            "--ex",
            "set backtrace limit 2000",
            "-iex",
            "set debuginfod enable off",
        ]

        value_keys = []
        # append the actual commands and something that acts as a separator
        for name, cmd in gdb_reports.items():
            value_keys.append(name)
            gdb_cmd += ["--ex", "p -99", "--ex", cmd]
        # End with our separator, ensures gdb's return code is as expected
        value_keys.append("separator")
        gdb_cmd += ["--ex", "p -99"]

        out = _command_output(gdb_cmd, env=environ).decode(
            "UTF-8", errors="replace"
        )

        # check for truncated stack trace
        if (
            "is truncated: expected core file size" in out
            or "is not a core dump" in out
        ):
            if "warning:" in out:
                warnings = "\n".join(
                    [line for line in out.splitlines() if "warning:" in line]
                )
            elif "Warning:" in out:
                warnings = "\n".join(
                    [line for line in out.splitlines() if "Warning:" in line]
                )
            else:
                warnings = out.splitlines()[0]
            reason = "Invalid core dump: " + warnings.strip()
            self["UnreportableReason"] = reason
            raise OSError(reason)

        first_line = out.split("\n", maxsplit=1)[0]
        if first_line.endswith("No such file or directory."):
            raise FileNotFoundError(
                errno.ENOENT,
                os.strerror(errno.ENOENT),
                "executable file for coredump not found",
            )

        # split the output into the various fields
        part_re = re.compile(r"^\$\d+\s*=\s*-99$", re.MULTILINE)
        parts = part_re.split(out)
        # drop the gdb startup text prior to first separator
        parts.pop(0)
        for part in parts:
            self[value_keys.pop(0)] = part.replace("\n\n", "\n.\n").strip()

        # glib's assertion has precedence, since it internally uses
        # abort(), and then glib's __abort_msg is bogus
        if "GLibAssertionMessage" in self:
            if '"ERROR:' in self["GLibAssertionMessage"]:
                self["AssertionMessage"] = self["GLibAssertionMessage"]
            del self["GLibAssertionMessage"]

        # same reason for libnih's assertion messages
        if "NihAssertionMessage" in self:
            if self["NihAssertionMessage"].startswith("$"):
                self["AssertionMessage"] = self["NihAssertionMessage"]
            del self["NihAssertionMessage"]

        # clean up AssertionMessage
        if "AssertionMessage" in self:
            # chop off "$n = 0x...." prefix, drop empty ones
            m = re.match(
                r'^\$\d+\s+=\s+0x[0-9a-fA-F]+\s+"(.*)"\s*$',
                self["AssertionMessage"],
            )
            if m:
                self["AssertionMessage"] = m.group(1)
                if self["AssertionMessage"].endswith("\\n"):
                    self["AssertionMessage"] = self["AssertionMessage"][0:-2]
            else:
                del self["AssertionMessage"]

        if "Stacktrace" in self:
            self._gen_stacktrace_top()
            addr_signature = self.crash_signature_addresses()
            if addr_signature:
                self["StacktraceAddressSignature"] = addr_signature

    def _gen_stacktrace_top(self):
        """Build field StacktraceTop as the top five functions of Stacktrace.

        Signal handler invocations and related functions are skipped since they
        are generally not useful for triaging and duplicate detection.
        """
        unwind_functions = set(
            [
                "g_logv",
                "g_log",
                "IA__g_log",
                "IA__g_logv",
                "g_assert_warning",
                "IA__g_assert_warning",
                "__GI_abort",
                "_XError",
            ]
        )
        toptrace = [""] * 5
        depth = 0
        unwound = False
        unwinding = False
        unwinding_xerror = False
        bt_fn_re = re.compile(
            r"^#(\d+)\s+"
            r"(?:0x(?:\w+)\s+in\s+\*?(.*)|(<signal handler called>)\s*)$"
        )
        bt_fn_noaddr_re = re.compile(
            r"^#(\d+)\s+(?:(.*)|(<signal handler called>)\s*)$"
        )
        # some internal functions like the SSE stubs cause unnecessary jitter
        ignore_functions_re = re.compile(
            r"^(__.*_s?sse\d+(?:_\w+)?|__kernel_vsyscall)$"
        )

        for line in self["Stacktrace"].splitlines():
            m = bt_fn_re.match(line)
            if not m:
                m = bt_fn_noaddr_re.match(line)
                if not m:
                    continue

            if not unwound or unwinding:
                if m.group(2):
                    fn = m.group(2).split()[0].split("(")[0]
                else:
                    fn = None

                # handle XErrors
                if unwinding_xerror:
                    if fn.startswith("_X") or fn in [
                        "handle_response",
                        "handle_error",
                        "XWindowEvent",
                    ]:
                        continue
                    unwinding_xerror = False

                if m.group(3) or fn in unwind_functions:
                    unwinding = True
                    depth = 0
                    toptrace = [""] * 5
                    if m.group(3):
                        # we stop unwinding when we found a <signal handler>,
                        # but we continue unwinding otherwise, as e. g. a glib
                        # abort is usually sitting on top of an XError
                        unwound = True

                    if fn == "_XError":
                        unwinding_xerror = True
                    continue
                unwinding = False

            frame = m.group(2) or m.group(3)
            function = frame.split()[0]
            if depth < len(toptrace) and not ignore_functions_re.match(
                function
            ):
                toptrace[depth] = frame
                depth += 1
        self["StacktraceTop"] = "\n".join(toptrace).strip()

    def add_hooks_info(self, ui, package=None, srcpackage=None):
        """Run hook script for collecting package specific data.

        A hook script needs to be in PACKAGE_HOOK_DIR/<Package>.py or in
        GENERAL_HOOK_DIR/*.py and has to contain a function 'add_info(report,
        ui)' that takes and modifies a Report, and gets an UserInterface
        reference for interactivity.

        return True if the hook requested to stop the report filing process,
        False otherwise.
        """
        assert ui is not None
        ret = self._add_hooks_info(ui, package, srcpackage)
        kill_pkttyagent()
        return ret

    def _add_hooks_info(self, ui, package, srcpackage):
        # determine package names, unless already given as arguments
        # avoid path traversal
        if not package:
            package = self.get("Package")
        if package:
            package = package.split()[0]
            if "/" in package:
                self["UnreportableReason"] = "invalid Package: %s" % package
                return None
        if not srcpackage:
            srcpackage = self.get("SourcePackage")
        if srcpackage:
            srcpackage = srcpackage.split()[0]
            if "/" in srcpackage:
                self["UnreportableReason"] = (
                    "invalid SourcePackage: %s" % package
                )
                return None

        hook_dirs = [PACKAGE_HOOK_DIR]
        # also search hooks in /opt, when program is from there
        opt_path = None
        exec_path = os.path.realpath(self.get("ExecutablePath", ""))
        if exec_path.startswith(_opt_dir):
            opt_path = exec_path
        elif package:
            # check package contents
            try:
                for f in apport.packaging.get_files(package):
                    if f.startswith(_opt_dir) and os.path.isfile(f):
                        opt_path = f
                        break
            except ValueError:
                # uninstalled package
                pass

        if opt_path:
            while len(opt_path) >= len(_opt_dir):
                hook_dirs.append(
                    os.path.join(opt_path, "share", "apport", "package-hooks")
                )
                opt_path = os.path.dirname(opt_path)

        # common hooks
        for hook in glob.glob(GENERAL_HOOK_DIR + "/*.py"):
            if _run_hook(self, ui, hook):
                return True

        # binary package hook
        if package:
            for hook_dir in hook_dirs:
                if _run_hook(
                    self, ui, os.path.join(hook_dir, package + ".py")
                ):
                    return True

        # source package hook
        if srcpackage:
            for hook_dir in hook_dirs:
                if _run_hook(
                    self,
                    ui,
                    os.path.join(hook_dir, "source_%s.py" % srcpackage),
                ):
                    return True

        return False

    def search_bug_patterns(self, url):
        r"""Check bug patterns loaded from the specified url.

        Return bug URL on match, or None otherwise.

        The url must refer to a valid XML document with the following syntax:
        root element := <patterns>
        patterns := <pattern url="http://bug.url"> *
        pattern := <re key="report_key">regular expression*</re> +

        For example:
        <?xml version="1.0"?>
        <patterns>
            <pattern url="http://bugtracker.net/bugs/1">
                <re key="Foo">ba.*r</re>
            </pattern>
            <pattern url="http://bugtracker.net/bugs/2">
                <re key="Package">^\\S* 1-2$</re>
                <!-- test for a particular version -->
                <re key="Foo">write_(hello|goodbye)</re>
            </pattern>
        </patterns>
        """
        # some distros might not want to support these
        if not url:
            return None

        try:
            with urllib.request.urlopen(url) as request:
                patterns = request.read().decode("UTF-8", errors="replace")
        except (OSError, urllib.error.URLError):
            # doesn't exist or failed to load
            return None

        if "<title>404 Not Found" in patterns:
            return None

        url = _check_bug_patterns(self, patterns)
        if url:
            return url

        return None

    @staticmethod
    def _get_ignore_dom():
        """Read ignore list XML file and return a DOM tree.

        Return an empty DOM tree if file does not exist.

        Raises ValueError if the file exists but is invalid XML.
        """
        # Properly handle dropped privileges
        homedir = pwd.getpwuid(os.geteuid())[5]
        ifpath = _ignore_file.replace("~", homedir)

        contents = ""
        fd = None
        f = None

        try:
            fd = os.open(ifpath, os.O_NOFOLLOW | os.O_RDONLY)
            st = os.fstat(fd)
            if stat.S_ISREG(st.st_mode):
                f = os.fdopen(fd, "r")
                # Limit size to prevent DoS
                contents = f.read(50000)
        except OSError:
            pass
        finally:
            if f is not None:
                f.close()
            elif fd is not None:
                os.close(fd)

        if contents == "":
            # create a document from scratch
            dom = xml.dom.getDOMImplementation().createDocument(
                None, "apport", None
            )
        else:
            try:
                dom = xml.dom.minidom.parseString(contents)
            except xml.parsers.expat.ExpatError as error:
                raise ValueError(
                    "%s has invalid format: %s" % (_ignore_file, str(error))
                ) from error

        # remove whitespace so that writing back the XML does not accumulate
        # whitespace
        dom.documentElement.normalize()
        _dom_remove_space(dom.documentElement)

        return dom

    def check_ignored(self):
        """Check if current report should not be presented.

        Reports can be suppressed by per-user blacklisting in
        ~/.apport-ignore.xml (in the real UID's home) and
        /etc/apport/blacklist.d/. For environments where you are only
        interested in crashes of some programs, you can also create a whitelist
        in /etc/apport/whitelist.d/, everything which does not match gets
        ignored then.

        This requires the ExecutablePath attribute. Throws a ValueError if the
        file has an invalid format.

        Privileges may need to be dropped before calling this.
        """
        assert "ExecutablePath" in self

        # check blacklist
        try:
            for f in os.listdir(_blacklist_dir):
                try:
                    with open(
                        os.path.join(_blacklist_dir, f), encoding="utf-8"
                    ) as fd:
                        for line in fd:
                            if line.strip() == self["ExecutablePath"]:
                                return True
                except OSError:
                    continue
        except OSError:
            pass

        # check whitelist
        try:
            whitelist = set()
            for f in os.listdir(_whitelist_dir):
                try:
                    with open(
                        os.path.join(_whitelist_dir, f), encoding="utf-8"
                    ) as fd:
                        for line in fd:
                            whitelist.add(line.strip())
                except OSError:
                    continue

            if whitelist and self["ExecutablePath"] not in whitelist:
                return True
        except OSError:
            pass

        try:
            dom = self._get_ignore_dom()
        except (ValueError, KeyError):
            apport.logging.error("Could not get ignore file:")
            traceback.print_exc()
            return False

        try:
            cur_mtime = int(os.stat(self["ExecutablePath"]).st_mtime)
        except OSError:
            # if it does not exist any more, do nothing
            return False

        # search for existing entry and update it
        try:
            for ignore in dom.getElementsByTagName("ignore"):
                if ignore.getAttribute("program") == self["ExecutablePath"]:
                    if float(ignore.getAttribute("mtime")) >= cur_mtime:
                        return True
        except (ValueError, KeyError):
            pass

        return False

    def mark_ignore(self):
        """Ignore future crashes of this executable.

        Add a ignore list entry for this report to ~/.apport-ignore.xml, so
        that future reports for this ExecutablePath are not presented to the
        user any more.

        Throws a ValueError if the file already exists and has an invalid
        format.

        Privileges may need to be dropped before calling this.
        """
        assert "ExecutablePath" in self

        dom = self._get_ignore_dom()
        try:
            mtime = str(int(os.stat(self["ExecutablePath"]).st_mtime))
        except OSError as error:
            # file went away underneath us, ignore
            if error.errno == errno.ENOENT:
                return
            raise

        # search for existing entry and update it
        for ignore in dom.getElementsByTagName("ignore"):
            if ignore.getAttribute("program") == self["ExecutablePath"]:
                ignore.setAttribute("mtime", mtime)
                break
        else:
            # none exists yet, create new ignore node if none exists yet
            e = dom.createElement("ignore")
            e.setAttribute("program", self["ExecutablePath"])
            e.setAttribute("mtime", mtime)
            dom.documentElement.appendChild(e)

        # Write back file
        # Properly handle dropped privileges
        homedir = pwd.getpwuid(os.geteuid())[5]
        ignore_file_path = _ignore_file.replace("~", homedir)

        with open(ignore_file_path, "w", encoding="utf-8") as fd:
            dom.writexml(fd, addindent="  ", newl="\n")

        dom.unlink()

    def has_useful_stacktrace(self):
        """Check whether StackTrace can be considered 'useful'.

        The current heuristic is to consider it useless if it either is shorter
        than three lines and has any unknown function, or for longer traces, a
        minority of known functions.
        """
        if not self.get("StacktraceTop"):
            return False

        unknown_fn = [
            f.startswith("??") for f in self["StacktraceTop"].splitlines()
        ]

        if len(unknown_fn) < 3:
            return unknown_fn.count(True) == 0

        return unknown_fn.count(True) <= len(unknown_fn) / 2.0

    def stacktrace_top_function(self):
        """Return topmost function in StacktraceTop."""
        for line in self.get("StacktraceTop", "").splitlines():
            fname = line.split("(")[0].strip()
            if fname != "??":
                return fname

        return None

    def standard_title(self):
        """Create an appropriate title for a crash database entry.

        This contains the topmost function name from the stack trace and the
        signal (for signal crashes) or the Python exception (for unhandled
        Python exceptions).

        Return None if the report is not a crash or a default title could not
        be generated.
        """
        # assertion failure
        if (
            self.get("Signal") == "6"
            and "ExecutablePath" in self
            and "AssertionMessage" in self
        ):
            return "%s assert failure: %s" % (
                os.path.basename(self["ExecutablePath"]),
                self["AssertionMessage"],
            )

        # signal crash
        if (
            "Signal" in self
            and "ExecutablePath" in self
            and "StacktraceTop" in self
        ):

            signal_names = {
                "4": "SIGILL",
                "6": "SIGABRT",
                "8": "SIGFPE",
                "11": "SIGSEGV",
                "13": "SIGPIPE",
            }

            fn = self.stacktrace_top_function()
            if fn:
                fn = " in %s()" % fn
            else:
                fn = ""

            arch_mismatch = ""
            if (
                "Architecture" in self
                and "PackageArchitecture" in self
                and self["Architecture"] != self["PackageArchitecture"]
                and self["PackageArchitecture"] != "all"
            ):
                arch_mismatch = (
                    " [non-native %s package]" % self["PackageArchitecture"]
                )

            return "%s crashed with %s%s%s" % (
                os.path.basename(self["ExecutablePath"]),
                signal_names.get(
                    self.get("Signal"), "signal " + self.get("Signal")
                ),
                fn,
                arch_mismatch,
            )

        # Python exception
        if "Traceback" in self and "ExecutablePath" in self:

            trace = self["Traceback"].splitlines()

            if len(trace) < 1:
                return None
            if len(trace) < 3:
                return "%s crashed with %s" % (
                    os.path.basename(self["ExecutablePath"]),
                    trace[0],
                )

            trace_re = re.compile(r'^\s*File\s*"(\S+)".* in (.+)$')
            i = len(trace) - 1
            function = "unknown"
            while i >= 0:
                m = trace_re.match(trace[i])
                if m:
                    module_path = m.group(1)
                    function = m.group(2)
                    break
                i -= 1

            path = os.path.basename(self["ExecutablePath"])
            last_line = trace[-1]
            exception = last_line.split(":")[0]
            m = re.match("^%s: (.+)$" % re.escape(exception), last_line)
            if m:
                message = m.group(1)
            else:
                message = None

            if function == "<module>":
                if module_path == self["ExecutablePath"]:
                    context = "__main__"
                else:
                    # Maybe use os.path.basename?
                    context = module_path
            else:
                context = "%s()" % function

            title = "%s crashed with %s in %s" % (path, exception, context)

            if message:
                title += ": %s" % message

            return title

        # package problem
        if self.get("ProblemType") == "Package" and "Package" in self:

            title = "package %s failed to install/upgrade" % self["Package"]
            if self.get("ErrorMessage"):
                title += ": " + self["ErrorMessage"].splitlines()[-1]

            return title

        if self.get("ProblemType") == "KernelOops" and "OopsText" in self:

            oops = self["OopsText"]
            if oops.startswith("------------[ cut here ]------------"):
                title = oops.split("\n", 2)[1]
            else:
                title = oops.split("\n", 1)[0]

            return title

        if self.get("ProblemType") == "KernelOops" and "Failure" in self:
            # Title the report with suspend or hibernate as appropriate,
            # and mention any non-free modules loaded up front.
            title = ""
            if "MachineType" in self:
                title += "[" + self["MachineType"] + "] "
            title += self["Failure"] + " failure"
            if "NonfreeKernelModules" in self:
                title += " [non-free: " + self["NonfreeKernelModules"] + "]"
            title += "\n"

            return title

        return None

    def obsolete_packages(self):
        """Return list of obsolete packages in Package and Dependencies."""
        obsolete = []
        for line in (
            self.get("Package", "") + "\n" + self.get("Dependencies", "")
        ).splitlines():
            if not line:
                continue
            pkg, ver = line.split()[:2]
            avail = packaging.get_available_version(pkg)
            if (
                ver is not None
                and ver != "None"
                and avail is not None
                and packaging.compare_versions(ver, avail) < 0
            ):
                obsolete.append(pkg)
        return obsolete

    def crash_signature(self):
        """Get a signature string for a crash.

        This is suitable for identifying duplicates.

        For signal crashes this the concatenation of ExecutablePath, Signal
        number, and StacktraceTop function names, separated by a colon. If
        StacktraceTop has unknown functions or the report lacks any of those
        fields, return None. In this case, you can use
        crash_signature_addresses() to get a less precise duplicate signature
        based on addresses instead of symbol names.

        For assertion failures, it is the concatenation of ExecutablePath
        and assertion message, separated by colons.

        For Python crashes, this concatenates the ExecutablePath, exception
        name, and Traceback function names, again separated by a colon.

        For suspend/resume failures, this concatenates whether it was a suspend
        or resume failure with the hardware identifier and the BIOS version, if
        it exists.
        """
        if "ExecutablePath" not in self:
            if not self["ProblemType"] in ("KernelCrash", "KernelOops"):
                return None

        # kernel crash
        if "Stacktrace" in self and self["ProblemType"] == "KernelCrash":
            sig = "kernel"
            regex = re.compile(r"^\s*\#\d+\s\[\w+\]\s(\w+)")
            for line in self["Stacktrace"].splitlines():
                m = regex.match(line)
                if m:
                    sig += ":" + (m.group(1))
            return sig

        # assertion failures
        if self.get("Signal") == "6" and "AssertionMessage" in self:
            sig = self["ExecutablePath"] + ":" + self["AssertionMessage"]
            # filter out addresses, to help match duplicates more sanely
            return re.sub(r"0x[0-9a-f]{6,}", "ADDR", sig)

        # signal crashes
        if "StacktraceTop" in self and "Signal" in self:
            sig = "%s:%s" % (self["ExecutablePath"], self["Signal"])
            bt_fn_re = re.compile(
                r"^(?:([\w:~]+).*|(<signal handler called>)\s*)$"
            )

            lines = self["StacktraceTop"].splitlines()
            if len(lines) < 2:
                return None

            for line in lines:
                m = bt_fn_re.match(line)
                if m:
                    sig += ":" + (m.group(1) or m.group(2))
                else:
                    # this will also catch ??
                    return None
            return sig

        # Python crashes
        if "Traceback" in self:
            trace = self["Traceback"].splitlines()

            sig = ""
            if len(trace) == 1:
                # sometimes, Python exceptions do not have file references
                m = re.match(r"(\w+): ", trace[0])
                if not m:
                    return None
                return self["ExecutablePath"] + ":" + m.group(1)
            if len(trace) < 3:
                return None

            loc_re = re.compile(r'^\s+File "([^"]+).*line (\d+).*\sin (.*)$')
            for line in trace:
                m = loc_re.match(line)
                if m:
                    # if we have a function name, use this; for a a crash
                    # outside of a function/method, fall back to the source
                    # file location
                    if m.group(3) != "<module>":
                        sig += ":" + m.group(3)
                    else:
                        # resolve symlinks for more stable signatures
                        f = m.group(1)
                        if os.path.islink(f):
                            f = os.path.realpath(f)
                        sig += ":%s@%s" % (f, m.group(2))

            exc_name = trace[-1].split(":")[0]
            try:
                exc_name += "(%s)" % self["_PythonExceptionQualifier"]
            except KeyError:
                pass
            return self["ExecutablePath"] + ":" + exc_name + sig

        if self["ProblemType"] == "KernelOops" and "Failure" in self:
            if "suspend" in self["Failure"] or "resume" in self["Failure"]:
                # Suspend / resume failure
                sig = self["Failure"]
                if self.get("MachineType"):
                    sig += ":%s" % self["MachineType"]
                if self.get("dmi.bios.version"):
                    sig += ":%s" % self["dmi.bios.version"]
                return sig

        # KernelOops crashes
        if "OopsText" in self:
            in_trace_body = False
            parts = []
            for line in self["OopsText"].split("\n"):
                if line.startswith("BUG: unable to handle"):
                    parsed = re.search("^BUG: unable to handle (.*) at ", line)
                    if parsed:
                        match = parsed.group(1)
                        assert match, (
                            "could not parse expected problem type line: %s"
                            % line
                        )
                        parts.append(match)

                if line.startswith("IP: "):
                    match = self._extract_function_and_address(line)
                    if match:
                        parts.append(match)

                elif line.startswith("Call Trace:"):
                    in_trace_body = True

                elif in_trace_body:
                    match = None
                    if line and line[0] == " ":
                        match = self._extract_function_and_address(line)
                        if match:
                            parts.append(match)
                    else:
                        in_trace_body = False
            if parts:
                return ":".join(parts)
        return None

    @staticmethod
    def _extract_function_and_address(line):
        parsed = re.search(r"\[.*\] (.*)$", line)
        if parsed:
            match = parsed.group(1)
            assert match, "could not parse expected call trace line: %s" % line
            if match[0] != "?":
                return match
        return None

    def crash_signature_addresses(self):
        """Compute heuristic duplicate signature for a signal crash.

        This should be used if crash_signature() fails, i. e. Stacktrace does
        not have enough symbols.

        This approach only uses addresses in the stack trace and does not rely
        on symbol resolution. As we can't unwind these stack traces, we cannot
        limit them to the top five frames and thus will end up with several or
        many different signatures for a particular crash. But these can be
        computed and synchronously checked with a crash database at the client
        side, which avoids having to upload and process the full report. So on
        the server-side crash database we will only have to deal with all the
        equivalence classes (i. e. same crash producing a number of possible
        signatures) instead of every single report.

        Return None when signature cannot be determined.
        """
        if (
            "ProcMaps" not in self
            or "Stacktrace" not in self
            or "Signal" not in self
        ):
            return None
        if "Errno 13" in self["ProcMaps"]:
            return None

        stack = []
        failed = 0
        for line in self["Stacktrace"].splitlines():
            if line.startswith("#"):
                addr = line.split()[1]
                if not addr.startswith("0x"):
                    continue
                # we do want to know about ValueErrors here, so don't catch
                addr = int(addr, 16)
                # ignore impossibly low addresses; these are usually artifacts
                # from gdb when not having debug symbols
                if addr < 0x1000:
                    continue
                offset = self._address_to_offset(addr)
                if offset:
                    # avoid ':' in ELF paths, we use that as separator
                    stack.append(offset.replace(":", ".."))
                else:
                    failed += 1

            # stack unwinding chops off ~ 5 functions, and we need some more
            # accuracy because we do not have symbols; but beyond a depth of 15
            # we get too much noise, so we can abort there
            if len(stack) >= 15:
                break

        # we only accept a small minority (< 20%) of failed resolutions,
        # otherwise we discard
        if failed > 0 and len(stack) / failed < 4:
            return None

        # we also discard if the trace is too short
        if (failed == 0 and len(stack) < 3) or (failed > 0 and len(stack) < 6):
            return None

        return "%s:%s:%s" % (
            self["ExecutablePath"],
            self["Signal"],
            ":".join(stack),
        )

    def anonymize(self):
        """Remove user identifying strings from the report.

        This particularly removes the user name, host name, and IPs
        from attributes which contain data read from the environment, and
        removes the ProcCwd attribute completely.
        """
        replacements = []
        # Do not replace "root"
        if os.getuid() > 0:
            # Use effective uid in case privileges were dropped
            p = pwd.getpwuid(os.geteuid())
            if len(p[0]) >= 2:
                replacements.append(
                    (re.compile(r"\b%s\b" % re.escape(p[0])), "username")
                )
            replacements.append(
                (re.compile(r"\b%s\b" % re.escape(p[5])), "/home/username")
            )

            for s in p[4].split(","):
                s = s.strip()
                if len(s) > 2:
                    replacements.append(
                        (
                            re.compile(r"(\b|\s)%s\b" % re.escape(s)),
                            r"\1User Name",
                        )
                    )

        hostname = os.uname()[1]
        if len(hostname) >= 2:
            replacements.append(
                (re.compile(r"\b%s\b" % re.escape(hostname)), "hostname")
            )

        try:
            del self["ProcCwd"]
        except KeyError:
            pass

        for k in self:
            is_proc_field = k.startswith("Proc") and k not in [
                "ProcCpuinfo",
                "ProcMaps",
                "ProcStatus",
                "ProcInterrupts",
                "ProcModules",
            ]
            if (
                is_proc_field
                or "Stacktrace" in k
                or k in ["Traceback", "PythonArgs", "Title", "JournalErrors"]
            ):
                if not hasattr(self[k], "isspace"):
                    continue
                for (pattern, repl) in replacements:
                    if isinstance(self[k], bytes):
                        self[k] = pattern.sub(
                            repl, self[k].decode("UTF-8", errors="replace")
                        ).encode("UTF-8")
                    else:
                        self[k] = pattern.sub(repl, self[k])

    def gdb_command(self, sandbox, gdb_sandbox=None):
        """Build gdb command for this report.

        This builds a gdb command for processing the given report, by setting
        the file to the ExecutablePath/InterpreterPath, unpacking the core dump
        and pointing "core-file" to it (if the report has a core dump), and
        setting up the paths when calling gdb in a package sandbox.

        When available, this calls "gdb-multiarch" instead of "gdb", for
        processing crash reports from foreign architectures.

        Return argv list for gdb and any environment variables.
        """
        assert "ExecutablePath" in self
        executable = self.get("InterpreterPath", self["ExecutablePath"])

        same_arch = False
        if (
            "Architecture" in self
            and self["Architecture"] == packaging.get_system_architecture()
        ):
            same_arch = True

        gdb_sandbox_bin = (
            os.path.join(gdb_sandbox, "usr", "bin") if gdb_sandbox else None
        )
        gdb_path = _which_extrapath("gdb", gdb_sandbox_bin)
        if not gdb_path:
            return "", ""
        command = [gdb_path]
        environ = {"HOME": "/nonexistent"}

        if not same_arch:
            # check if we have gdb-multiarch
            ma = _which_extrapath("gdb-multiarch", gdb_sandbox_bin)
            if ma:
                command = [ma]
            else:
                sys.stderr.write(
                    "WARNING: Please install gdb-multiarch for processing "
                    'reports from foreign architectures. Results with "gdb" '
                    "will be very poor.\n"
                )

        if sandbox:
            native_multiarch = "x86_64-linux-gnu"
            # N.B. set solib-absolute-prefix is an alias for set sysroot
            command += [
                "--ex",
                "set debug-file-directory %s/usr/lib/debug" % sandbox,
                "--ex",
                "set solib-absolute-prefix " + sandbox,
                "--ex",
                "add-auto-load-safe-path " + sandbox,
                # needed to fix /lib64/ld-linux-x86-64.so.2 broken symlink
                "--ex",
                "set solib-search-path %s/lib/%s:%s/usr/lib/%s"
                % (sandbox, native_multiarch, sandbox, native_multiarch),
            ]
            if gdb_sandbox:
                ld_lib_path = "%s/lib:%s/lib/%s:%s/usr/lib/%s:%s/usr/lib" % (
                    gdb_sandbox,
                    gdb_sandbox,
                    native_multiarch,
                    gdb_sandbox,
                    native_multiarch,
                    gdb_sandbox,
                )
                pyhome = "%s/usr" % gdb_sandbox
                # env settings need to be modified for gdb in a sandbox
                environ |= {
                    "LD_LIBRARY_PATH": ld_lib_path,
                    "PYTHONHOME": pyhome,
                    "GCONV_PATH": "%s/usr/lib/%s/gconv"
                    % (gdb_sandbox, native_multiarch),
                }
                command.insert(
                    0,
                    "%s/lib/%s/ld-linux-x86-64.so.2"
                    % (gdb_sandbox, native_multiarch),
                )
                command += [
                    "--ex",
                    "set data-directory %s/usr/share/gdb" % gdb_sandbox,
                ]
            if not os.path.exists(sandbox + executable):
                if executable.startswith("/usr"):
                    if os.path.exists(sandbox + executable[3:]):
                        executable = executable[3:]
            executable = sandbox + executable

        command += ["--ex", 'file "%s"' % executable]

        if "CoreDump" in self:
            if hasattr(self["CoreDump"], "find"):
                (fd, core) = tempfile.mkstemp(prefix="apport_core_")
                atexit.register(os.unlink, core)
                os.write(fd, self["CoreDump"])
                os.close(fd)
            elif hasattr(self["CoreDump"], "gzipvalue"):
                (fd, core) = tempfile.mkstemp(prefix="apport_core_")
                atexit.register(os.unlink, core)
                os.close(fd)
                with open(core, "wb") as f:
                    self["CoreDump"].write(f)
            else:
                # value is a file path
                core = self["CoreDump"][0]

            command += ["--ex", "core-file " + core]

        return command, environ

    def _address_to_offset(self, addr):
        """Resolve a memory address to an ELF name and offset.

        This can be used for building duplicate signatures from non-symbolic
        stack traces. These often do not have enough symbols available to
        resolve function names, but taking the raw addresses also is not
        suitable due to ASLR. But the offsets within a library should be
        constant between crashes (assuming the same version of all libraries).

        This needs and uses the "ProcMaps" field to resolve addresses.

        Return 'path+offset' when found, or None if address is not in any
        mapped range.
        """
        self._build_proc_maps_cache()

        for (start, end, elf) in self._proc_maps_cache:
            if start <= addr <= end:
                return "%s+%x" % (elf, addr - start)

        return None

    def _build_proc_maps_cache(self):
        """Generate self._proc_maps_cache from ProcMaps field.

        This only gets done once.
        """
        if self._proc_maps_cache:
            return

        assert "ProcMaps" in self
        self._proc_maps_cache = []
        # library paths might have spaces, so we need to make some assumptions
        # about the intermediate fields. But we know that in between the
        # pre-last data field and the path there are many spaces, while between
        # the other data fields there is only one. So we take 2 or more spaces
        # as the separator of the last data field and the path.
        fmt = re.compile(r"^([0-9a-fA-F]+)-([0-9a-fA-F]+).*\s{2,}(\S.*$)")
        fmt_unknown = re.compile(r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s")

        for line in self["ProcMaps"].splitlines():
            if not line.strip():
                continue
            m = fmt.match(line)
            if not m:
                # ignore lines with unknown ELF
                if fmt_unknown.match(line):
                    continue
                # but complain otherwise, as this means we encounter an
                # architecture or new kernel version where the format changed
                assert m, "cannot parse ProcMaps line: " + line
            self._proc_maps_cache.append(
                (int(m.group(1), 16), int(m.group(2), 16), m.group(3))
            )

    @staticmethod
    def get_logind_session(pid=None, proc_pid_fd=None):
        """Get logind session path and start time.

        Return (session_id, session_start_timestamp) if process is in a logind
        session, or None otherwise.
        """
        if proc_pid_fd is not None:
            cgroup_file = os.open("cgroup", os.O_RDONLY, dir_fd=proc_pid_fd)
        else:
            cgroup_file = "/proc/%s/cgroup" % pid

        # determine cgroup
        try:
            with io.open(cgroup_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if (
                        "name=systemd:" in line
                        and line.endswith(".scope")
                        and "/session-" in line
                    ):
                        my_session = line.split("/session-", 1)[1][:-6]
                        break
                else:
                    return None
            # determine session creation time
            session_start_time = os.stat(
                "/run/systemd/sessions/" + my_session
            ).st_mtime
        except OSError:
            return None

        return (my_session, session_start_time)
