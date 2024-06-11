"""Representation of and data collection for a problem report."""

# Copyright (C) 2006 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

# pylint: disable=too-many-lines
# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import atexit
import datetime
import errno
import fnmatch
import glob
import grp
import importlib.util
import io
import logging
import os
import pathlib
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import xml.dom
import xml.dom.minidom
import xml.parsers.expat
from collections.abc import Iterable, Iterator

import apport.fileutils
import apport.logging
import problem_report
from apport.hookutils import kill_pkttyagent
from apport.packaging_impl import impl as packaging
from apport.ui import HookUI, NoninteractiveHookUI

_data_dir = os.environ.get("APPORT_DATA_DIR", "/usr/share/apport")
GENERAL_HOOK_DIR = f"{_data_dir}/general-hooks/"
PACKAGE_HOOK_DIR = f"{_data_dir}/package-hooks/"
_opt_dir = "/opt"

# path of the ignore file
_ignore_file = os.environ.get("APPORT_IGNORE_FILE", "~/.apport-ignore.xml")

# system-wide denylist/allowlist directories
_DENYLIST_DIR = "/etc/apport/report-ignore"
_ALLOWLIST_DIR = "/etc/apport/report-only"
_LEGACY_DENYLIST_DIR = "/etc/apport/blacklist.d"  # wokeignore:rule=blacklist
_LEGACY_ALLOWLIST_DIR = "/etc/apport/whitelist.d"  # wokeignore:rule=whitelist

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


def _read_list_files_in_directory(directory: str) -> Iterator[str]:
    """Read every file in the directory and return each stripped line."""
    try:
        for list_file in pathlib.Path(directory).iterdir():
            try:
                with list_file.open(encoding="utf-8") as fd:
                    for line in fd:
                        yield line.strip()
            except OSError:
                continue
    except OSError:
        pass


def _read_proc_link(
    path: str, pid: int | None = None, dir_fd: int | None = None
) -> str:
    """Use readlink() to resolve link.

    Return a string representing the path to which the symbolic link points.
    """
    if dir_fd is not None:
        return os.readlink(path, dir_fd=dir_fd)

    return os.readlink(f"/proc/{pid}/{path}")


def _read_proc_file(
    path: str, pid: int | None = None, dir_fd: int | None = None
) -> str:
    """Read file content.

    Return its content, or return a textual error if it failed.
    """
    try:
        if dir_fd is None:
            proc_file: int | str = f"/proc/{pid}/{path}"
        else:
            proc_file = os.open(path, os.O_RDONLY | os.O_CLOEXEC, dir_fd=dir_fd)

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


def _command_output(
    command: list[str], env: dict[str, str] | None = None, timeout: float = 1800
) -> str:
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
            encoding="UTF-8",
            env=env,
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        if error.stdout:
            output = f": {error.stdout.decode().rstrip()}"
        else:
            output = " with no stdout"
        raise OSError(
            f"Error: command {str(error.cmd)} timed out"
            f" after {error.timeout} seconds{output}"
        ) from error
    if sp.returncode == 0:
        return sp.stdout.rstrip()
    raise OSError(
        f"Error: command {command} failed with exit code {sp.returncode}:"
        f" {sp.stdout.rstrip()}"
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
            if c.hasChildNodes() and c.childNodes[0].nodeType == xml.dom.Node.TEXT_NODE:
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
        hookname = os.path.splitext(os.path.basename(hook))[0].replace("-", "_")
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


class _Environment(dict[str, str]):
    """Wrapper around an environment dictionary."""

    def anonymize_path(self) -> None:
        """Anonymize PATH environment variable if present."""
        path = self.get("PATH")
        if path is None:
            return
        if (
            path == "/usr/local/sbin:/usr/local/bin"
            ":/usr/sbin:/usr/bin:/sbin:/bin:/usr/games"
        ):
            del self["PATH"]
        elif "/home" in path or "/tmp" in path:
            self["PATH"] = "(custom, user)"
        else:
            self["PATH"] = "(custom, no user)"

    def anonymize_vars(self, keys: Iterable[str]) -> None:
        """Anonymize given environment variables if present."""
        for key in keys:
            if key in self:
                self[key] = "<set>"

    @classmethod
    def from_string(cls, environ):
        """Read environment variables from text representation.

        The environment variables are expected to be separated by newlines.
        """
        return cls(
            [entry.split("=", 1) for entry in environ.split("\n") if "=" in entry]
        )


#
# Report class
#


class Report(problem_report.ProblemReport):
    """A problem report specific to apport (crash or bug).

    This class wraps a standard ProblemReport and adds methods for collecting
    standard debugging data.
    """

    def __init__(self, problem_type: str = "Crash", date: str | None = None) -> None:
        """Initialize a fresh problem report.

        date is the desired date/time string; if None (default), the current
        local time is used.

        If the report is attached to a process ID, this should be set in
        self.pid, so that e. g. hooks can use it to collect additional data.
        """
        problem_report.ProblemReport.__init__(self, problem_type, date)
        self.pid: int | None = None
        self._proc_maps_cache: list[tuple[int, int, str]] | None = None

    @staticmethod
    def _customized_package_suffix(package: str) -> str:
        """Return a string suitable for appending to Package/Dependencies.

        If package has only unmodified files, return the empty string. If not,
        return ' [modified: ...]' with a list of modified files.
        """
        suffix = ""
        mod = packaging.get_modified_files(package)
        if mod:
            suffix += f" [modified: {' '.join(mod)}]"
        try:
            if not packaging.is_distro_package(package):
                origin = packaging.get_package_origin(package)
                if origin:
                    suffix += f" [origin: {origin}]"
                else:
                    suffix += " [origin: unknown]"
        except ValueError:
            # no-op for nonexisting packages
            pass

        return suffix

    def add_package(self, package: str) -> str | None:
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
        self["Package"] = (
            f"{package} {version or '(not installed)'}"
            f"{self._customized_package_suffix(package)}"
        )

        return version

    def _get_transitive_dependencies(self, package: str) -> str:
        # get set of all transitive dependencies
        dependencies_set: set[str] = set()
        _transitive_dependencies(package, dependencies_set)

        # get dependency versions
        dependencies = ""
        for dep in sorted(dependencies_set):
            try:
                v = packaging.get_version(dep)
            except ValueError:
                # can happen with uninstalled alternate dependencies
                continue

            if dependencies:
                dependencies += "\n"
            dependencies += f"{dep} {v}{self._customized_package_suffix(dep)}"
        return dependencies

    def add_package_info(self, package: str | None = None) -> None:
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
            if "ExecutablePath" not in self and self["ProblemType"] == "KernelCrash":
                package = self["Package"]
            else:
                package = apport.fileutils.find_file_package(self["ExecutablePath"])
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

        if "PackageArchitecture" not in self:
            self["PackageArchitecture"] = packaging.get_architecture(package)
        if "Dependencies" not in self:
            self["Dependencies"] = self._get_transitive_dependencies(package)

    def add_snap_info(self, snap):
        """Add info about an installed Snap.

        This adds a Snap: field, containing name, version and channel.
        It adds a SnapSource: field, if the snap has a Launchpad contact
        defined.
        """
        self["Snap"] = (
            f"{snap.get('name')} {snap.get('version')}"
            f" ({snap.get('channel', 'unknown')})"
        )
        snapname = snap.get("name")
        self["SnapChanges"] = _command_output(
            ["snap", "changes", "--abs-time", snapname]
        )
        self["SnapConnections"] = _command_output(["snap", "connections", snapname])
        self[f"SnapInfo.{snapname}"] = _command_output(
            ["snap", "info", "--abs-time", snapname]
        )
        import yaml  # pylint: disable=import-outside-toplevel

        with open(f"/snap/{snapname}/current/meta/snap.yaml", encoding="utf-8") as f:
            snap_meta = yaml.safe_load(f)
        if "base" in snap_meta:
            base = snap_meta["base"]
            self[f"SnapInfo.{base}"] = _command_output(
                ["snap", "info", "--abs-time", base]
            )
        providers = []
        if "plugs" in snap_meta:
            for plug in snap_meta["plugs"]:
                dp = snap_meta["plugs"][plug].get("default-provider")
                if dp and dp not in providers:
                    providers.append(dp)
        for provider in providers:
            self[f"SnapInfo.{provider}"] = _command_output(
                ["snap", "info", "--abs-time", provider]
            )
        # Automatically handle snaps which have a Launchpad contact defined
        if snap.get("contact"):
            self.add_snap_contact_info(snap.get("contact"))

    def add_snap_contact_info(self, snap_contact: str) -> None:
        """Load report with information about where it should be filed.

        Parse project (e.g. 'subiquity') or source package string
        (e.g. 'ubuntu/+source/gnome-calculator') from snap 'contact'.
        Additionally, extract any tag/tags defined in the contact URL.
        """
        # Launchpad
        p = (
            r"^https?:\/\/.*launchpad\.net\/(?:distros/)?"
            r"((?:[^\/]+\/\+source\/)?[^\/]+)(?:.*field\.tags?=([^&]+))?"
        )
        m = re.search(p, urllib.parse.unquote(snap_contact))
        if m and m.group(1):
            self["SnapSource"] = m.group(1)
            if m.group(2):
                self["SnapTags"] = m.group(2)

        # Github
        p = r"^https?://.*github\.com/([^/]+)/([^/]+)"
        m = re.search(p, urllib.parse.unquote(snap_contact))
        if m:
            self["SnapGitOwner"] = m.group(1)
            self["SnapGitName"] = m.group(2)
            self["CrashDB"] = "snap-github"

    def add_os_info(self) -> None:
        """Add operating system information.

        This adds:
        - DistroRelease: NAME and VERSION from /etc/os-release, or
          'lsb_release -sir' output
        - Architecture: system architecture in distro specific notation
        - Uname: uname -srm output
        """
        if "DistroRelease" not in self:
            osname, osversion = apport.packaging.get_os_version()
            self["DistroRelease"] = f"{osname} {osversion}"
        if "Uname" not in self:
            u = os.uname()
            self["Uname"] = f"{u[0]} {u[2]} {u[4]}"
        if "Architecture" not in self:
            self["Architecture"] = packaging.get_system_architecture()

    def add_user_info(self) -> None:
        """Add information about the user.

        This adds:
        - UserGroups: system groups the user is in
        """
        # Use effective uid in case privileges were dropped
        try:
            user = pwd.getpwuid(os.geteuid())[0]
        except KeyError:
            # User not found (e.g. dynamic user in container)
            return
        sys_gid_max = apport.fileutils.get_sys_gid_max()
        groups = [
            name
            for name, p, gid, memb in grp.getgrall()
            if user in memb and gid <= sys_gid_max
        ]
        groups.sort()
        if groups:
            self["UserGroups"] = " ".join(groups)
        else:
            # the docs indicate this is optional but a lot of tests expect
            # UserGroups to exist
            self["UserGroups"] = "N/A"

    def _check_interpreted(self) -> None:
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches
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
        if not any(filter(lambda i: fnmatch.fnmatch(exebasename, i), interpreters)):
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
            if name.startswith("python") and cmdargs[1] == "-m" and len(cmdargs) >= 3:
                path = self._python_module_path(cmdargs[2])
                if path:
                    self["InterpreterPath"] = self["ExecutablePath"]
                    self["ExecutablePath"] = path
                else:
                    self["UnreportableReason"] = (
                        f"Cannot determine path of python module {cmdargs[2]}"
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
                self["UnreportableReason"] = "Cannot determine twistd client program"

    def _twistd_executable(self) -> str | None:
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
    def _python_module_path(module: str) -> str | None:
        """Determine path of given Python module."""
        try:
            spec = importlib.util.find_spec(module)
        except ImportError:
            return None
        if spec is None:
            return None
        return spec.origin

    def add_proc_info(
        self,
        pid: int | str | None = None,
        proc_pid_fd: int | None = None,
        extraenv: Iterable[str] | None = None,
    ) -> None:
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches
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
        """
        if isinstance(pid, str):
            pid = int(pid)
        if not proc_pid_fd:
            if not pid:
                pid = self.pid or os.getpid()
            if not self.pid:
                self.pid = pid
            try:
                proc_pid_fd = os.open(
                    f"/proc/{pid}", os.O_RDONLY | os.O_PATH | os.O_DIRECTORY
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
        self.add_proc_environ(pid=pid, proc_pid_fd=proc_pid_fd, extraenv=extraenv)
        self["ProcStatus"] = _read_proc_file("status", pid, proc_pid_fd)
        self["ProcCmdline"] = _read_proc_file("cmdline", pid, proc_pid_fd).rstrip("\0")
        self["ProcMaps"] = _read_maps(proc_pid_fd)
        if "ExecutablePath" not in self:
            try:
                self["ExecutablePath"] = _read_proc_link("exe", pid, proc_pid_fd)
            except PermissionError as error:
                raise ValueError("not accessible") from error
            except OSError as error:
                if error.errno == errno.ENOENT:
                    raise ValueError("invalid process") from error
                raise
        for p in ("rofs", "rwfs", "squashmnt", "persistmnt"):
            if self["ExecutablePath"].startswith(f"/{p}/"):
                self["ExecutablePath"] = self["ExecutablePath"][len(f"/{p}") :]
                break
        if not os.path.exists(self["ExecutablePath"]):
            raise ValueError(f"{self['ExecutablePath']} does not exist")

        # check if we have an interpreted program
        self._check_interpreted()

        self._add_executable_timestamp()

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

    def _add_executable_timestamp(self) -> None:
        self["ExecutableTimestamp"] = str(int(os.stat(self["ExecutablePath"]).st_mtime))

    def add_proc_environ(
        self,
        pid: int | None = None,
        extraenv: Iterable[str] | None = None,
        proc_pid_fd: int | None = None,
    ) -> None:
        """Add environment information.

        If pid is not given, it defaults to the process' current pid.

        This adds the following fields:
        - ProcEnviron: A subset of the process' environment (only some standard
          variables that do not disclose potentially sensitive information,
          plus the ones mentioned in extraenv)
        - CurrentDesktop: Value of $XDG_CURRENT_DESKTOP, if present
        """
        if not proc_pid_fd:
            if not pid:
                pid = os.getpid()
            proc_pid_fd = os.open(
                f"/proc/{pid}", os.O_RDONLY | os.O_PATH | os.O_DIRECTORY
            )

        try:
            environ = _Environment(apport.fileutils.get_process_environ(proc_pid_fd))
        except OSError as error:
            self["ProcEnviron"] = f"Error: {error}"
            return
        self._add_environ(environ, extraenv)

    def _add_environ(
        self, environ: _Environment, extraenv: Iterable[str] | None = None
    ) -> None:
        anonymize_vars = {"LD_LIBRARY_PATH", "LD_PRELOAD", "XDG_RUNTIME_DIR"}
        safe_vars = anonymize_vars | {
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
            "PATH",
        }
        if extraenv:
            safe_vars |= set(extraenv)

        environ.anonymize_path()
        environ.anonymize_vars(anonymize_vars)

        if "XDG_CURRENT_DESKTOP" in environ:
            self["CurrentDesktop"] = environ["XDG_CURRENT_DESKTOP"]
        self["ProcEnviron"] = "\n".join(
            [
                f"{key}=" + value.replace("\n", "\\n")
                for key, value in sorted(environ.items())
                if key in safe_vars
            ]
        )

    def add_kernel_crash_info(self) -> bool:
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
            command = ["crash", f"/usr/lib/debug/boot/vmlinux-{kver}", core]
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

    def add_gdb_info(
        self, rootdir: str | None = None, gdb_sandbox: str | None = None
    ) -> None:
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-locals,too-many-statements
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
        environ["HOME"] = "/nonexistent"
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

        out = _command_output(gdb_cmd, env=environ)

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
                r'^\$\d+\s+=\s+0x[0-9a-fA-F]+\s+"(.*)"\s*$', self["AssertionMessage"]
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
            r"^#(\d+)\s+(?:0x(?:\w+)\s+in\s+\*?(.*)|(<signal handler called>)\s*)$"
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
                    if fn.startswith("_X") or fn in {
                        "handle_response",
                        "handle_error",
                        "XWindowEvent",
                    }:
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
            if depth < len(toptrace) and not ignore_functions_re.match(function):
                toptrace[depth] = frame
                depth += 1
        self["StacktraceTop"] = "\n".join(toptrace).strip()

    def add_hooks_info(
        self,
        ui: HookUI | None = None,
        package: str | None = None,
        srcpackage: str | None = None,
    ) -> bool:
        """Run hook script for collecting package specific data.

        A hook script needs to be in PACKAGE_HOOK_DIR/<Package>.py or in
        GENERAL_HOOK_DIR/*.py and has to contain a function 'add_info(report,
        ui)' that takes and modifies a Report, and gets an UserInterface
        reference for interactivity.

        return True if the hook requested to stop the report filing process,
        False otherwise.
        """
        if ui is None:
            ui = NoninteractiveHookUI()
        ret = self._add_hooks_info(ui, package, srcpackage)
        self.pop("_HooksRun", None)
        kill_pkttyagent()
        return ret

    def _add_hooks_info(
        self, ui: HookUI, package: str | None, srcpackage: str | None
    ) -> bool:
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches

        # determine package names, unless already given as arguments
        # avoid path traversal
        if not package:
            package = self.get("Package")
        if package:
            package = package.split()[0]
            if "/" in package:
                self["UnreportableReason"] = f"invalid Package: {package}"
                return False
        if not srcpackage:
            srcpackage = self.get("SourcePackage")
        if srcpackage:
            srcpackage = srcpackage.split()[0]
            if "/" in srcpackage:
                self["UnreportableReason"] = f"invalid SourcePackage: {srcpackage}"
                return False

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
        for hook in sorted(glob.glob(GENERAL_HOOK_DIR + "/*.py")):
            if _run_hook(self, ui, hook):
                return True

        # binary package hook
        if package:
            for hook_dir in hook_dirs:
                if _run_hook(self, ui, os.path.join(hook_dir, package + ".py")):
                    return True

        # source package hook
        if srcpackage:
            for hook_dir in hook_dirs:
                if _run_hook(
                    self, ui, os.path.join(hook_dir, f"source_{srcpackage}.py")
                ):
                    return True

        return False

    def search_bug_patterns(self, url: str | None) -> str | None:
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
            dom = xml.dom.getDOMImplementation().createDocument(None, "apport", None)
        else:
            try:
                dom = xml.dom.minidom.parseString(contents)
            except xml.parsers.expat.ExpatError as error:
                raise ValueError(
                    f"{_ignore_file} has invalid format: {str(error)}"
                ) from error

        # remove whitespace so that writing back the XML does not accumulate
        # whitespace
        dom.documentElement.normalize()
        _dom_remove_space(dom.documentElement)

        return dom

    def _get_signal_name(self) -> str:
        signal_number = int(self["Signal"])
        signal_name = self.get("SignalName")
        if signal_name:
            return signal_name
        try:
            return signal.Signals(signal_number).name
        except ValueError:
            return f"signal {signal_number}"

    def check_ignored(self) -> bool:
        """Check if current report should not be presented.

        Reports can be suppressed by per-user denylisting in
        ~/.apport-ignore.xml (in the real UID's home) and
        /etc/apport/report-ignore/. For environments where you are only
        interested in crashes of some programs, you can also create an
        allowlist in /etc/apport/report-only/, everything which does not
        match gets ignored then.

        This requires the ExecutablePath attribute. Throws a ValueError if the
        file has an invalid format.

        Privileges may need to be dropped before calling this.
        """
        assert "ExecutablePath" in self

        # check system-wide denylist
        if self["ExecutablePath"] in _read_list_files_in_directory(
            _DENYLIST_DIR
        ) or self["ExecutablePath"] in _read_list_files_in_directory(
            _LEGACY_DENYLIST_DIR
        ):
            return True

        # check system-wide allowlist
        allowlist = set(_read_list_files_in_directory(_ALLOWLIST_DIR))
        allowlist |= set(_read_list_files_in_directory(_LEGACY_ALLOWLIST_DIR))
        if allowlist and self["ExecutablePath"] not in allowlist:
            return True

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

    def mark_ignore(self) -> None:
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

    def has_useful_stacktrace(self) -> bool:
        """Check whether StackTrace can be considered 'useful'.

        The current heuristic is to consider it useless if it either is shorter
        than three lines and has any unknown function, or for longer traces, a
        minority of known functions.
        """
        if not self.get("StacktraceTop"):
            return False

        unknown_fn = [f.startswith("??") for f in self["StacktraceTop"].splitlines()]

        if len(unknown_fn) < 3:
            return unknown_fn.count(True) == 0

        return unknown_fn.count(True) <= len(unknown_fn) / 2.0

    def stacktrace_top_function(self) -> str | None:
        """Return topmost function in StacktraceTop."""
        for line in self.get("StacktraceTop", "").splitlines():
            fname = line.split("(")[0].strip()
            if fname != "??":
                return fname

        return None

    def _get_python_exception_title(self) -> str | None:
        trace = self["Traceback"].splitlines()

        if len(trace) < 1:
            return None
        if len(trace) < 3:
            return (
                f"{os.path.basename(self['ExecutablePath'])}"
                f" crashed with {trace[0]}"
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
        m = re.match(f"^{re.escape(exception)}: (.+)$", last_line)
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
            context = f"{function}()"

        title = f"{path} crashed with {exception} in {context}"

        if message:
            title += f": {message}"

        return title

    def _get_signal_crash_title(self) -> str | None:
        fn = self.stacktrace_top_function()
        if fn:
            fn = f" in {fn}()"
        else:
            fn = ""

        arch_mismatch = ""
        if (
            "Architecture" in self
            and "PackageArchitecture" in self
            and self["Architecture"] != self["PackageArchitecture"]
            and self["PackageArchitecture"] != "all"
        ):
            arch_mismatch = f" [non-native {self['PackageArchitecture']} package]"

        return (
            f"{os.path.basename(self['ExecutablePath'])}"
            f" crashed with {self._get_signal_name()}{fn}{arch_mismatch}"
        )

    # pylint: disable-next=too-many-return-statements
    def standard_title(self) -> str | None:
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
            return (
                f"{os.path.basename(self['ExecutablePath'])} assert failure:"
                f" {self['AssertionMessage']}"
            )

        if "Signal" in self and "ExecutablePath" in self and "StacktraceTop" in self:
            return self._get_signal_crash_title()

        if "Traceback" in self and "ExecutablePath" in self:
            return self._get_python_exception_title()

        # package problem
        if self.get("ProblemType") == "Package" and "Package" in self:
            title = f"package {self['Package']} failed to install/upgrade"
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

    def obsolete_packages(self) -> list[str]:
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

    def crash_signature(self) -> str | None:
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-return-statements
        # pylint: disable=too-many-statements
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
            if not self["ProblemType"] in {"KernelCrash", "KernelOops"}:
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
            sig = f"{self['ExecutablePath']}:{self['Signal']}"
            bt_fn_re = re.compile(r"^(?:([\w:~]+).*|(<signal handler called>)\s*)$")

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
                        sig += f":{f}@{m.group(2)}"

            exc_name = trace[-1].split(":")[0]
            try:
                exc_name += f"({self['_PythonExceptionQualifier']})"
            except KeyError:
                pass
            return self["ExecutablePath"] + ":" + exc_name + sig

        if self["ProblemType"] == "KernelOops" and "Failure" in self:
            if "suspend" in self["Failure"] or "resume" in self["Failure"]:
                # Suspend / resume failure
                sig = self["Failure"]
                if self.get("MachineType"):
                    sig += f":{self['MachineType']}"
                if self.get("dmi.bios.version"):
                    sig += f":{self['dmi.bios.version']}"
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
                        assert (
                            match
                        ), f"could not parse expected problem type line: {line}"
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
    def _extract_function_and_address(line: str) -> str | None:
        parsed = re.search(r"\[.*\] (.*)$", line)
        if parsed:
            match = parsed.group(1)
            assert match, f"could not parse expected call trace line: {line}"
            if match[0] != "?":
                return match
        return None

    def crash_signature_addresses(self) -> str | None:
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
        if "ProcMaps" not in self or "Stacktrace" not in self or "Signal" not in self:
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

        return f"{self['ExecutablePath']}:{self['Signal']}:{':'.join(stack)}"

    def anonymize(self) -> None:
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
                replacements.append((re.compile(rf"\b{re.escape(p[0])}\b"), "username"))
            replacements.append(
                (re.compile(rf"\b{re.escape(p[5])}\b"), "/home/username")
            )

            for s in p[4].split(","):
                s = s.strip()
                if len(s) > 2:
                    replacements.append(
                        (re.compile(rf"(\b|\s){re.escape(s)}\b"), r"\1User Name")
                    )

        hostname = os.uname()[1]
        if len(hostname) >= 2:
            replacements.append((re.compile(rf"\b{re.escape(hostname)}\b"), "hostname"))

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
                or k in {"Traceback", "PythonArgs", "Title", "JournalErrors"}
            ):
                if not hasattr(self[k], "isspace"):
                    continue
                for pattern, repl in replacements:
                    if isinstance(self[k], bytes):
                        self[k] = pattern.sub(
                            repl, self[k].decode("UTF-8", errors="replace")
                        ).encode("UTF-8")
                    else:
                        self[k] = pattern.sub(repl, self[k])

    def gdb_command(
        self, sandbox: str | None, gdb_sandbox: str | None = None
    ) -> tuple[list[str], dict[str, str]]:
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-locals
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
            raise FileNotFoundError(
                errno.ENOENT,
                os.strerror(errno.ENOENT),
                "gdb not found in retracing env",
            )

        command = [gdb_path]
        environ: dict[str, str] = {}

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
                f"set debug-file-directory {sandbox}/usr/lib/debug",
                "--ex",
                "set solib-absolute-prefix " + sandbox,
                "--ex",
                "add-auto-load-safe-path " + sandbox,
                # needed to fix /lib64/ld-linux-x86-64.so.2 broken symlink
                "--ex",
                f"set solib-search-path {sandbox}/lib/{native_multiarch}"
                f":{sandbox}/usr/lib/{native_multiarch}",
            ]
            if gdb_sandbox:
                ld_lib_path = (
                    f"{gdb_sandbox}/lib"
                    f":{gdb_sandbox}/lib/{native_multiarch}"
                    f":{gdb_sandbox}/usr/lib/{native_multiarch}"
                    f":{gdb_sandbox}/usr/lib"
                )
                pyhome = f"{gdb_sandbox}/usr"
                # env settings need to be modified for gdb in a sandbox
                environ |= {
                    "LD_LIBRARY_PATH": ld_lib_path,
                    "PATH": ld_lib_path,
                    "PYTHONHOME": pyhome,
                    "GCONV_PATH": f"{gdb_sandbox}/usr/lib/{native_multiarch}/gconv",
                }
                command[:0] = ["ld-linux-x86-64.so.2"]
                command += ["--ex", f"set data-directory {gdb_sandbox}/usr/share/gdb"]
            if not os.path.exists(sandbox + executable):
                if executable.startswith("/usr"):
                    if os.path.exists(sandbox + executable[3:]):
                        executable = executable[3:]
            executable = sandbox + executable

        command += ["--ex", f'file "{executable}"']

        if "CoreDump" in self:
            if hasattr(self["CoreDump"], "find"):
                (fd, core) = tempfile.mkstemp(prefix="apport_core_")
                atexit.register(os.unlink, core)
                os.write(fd, self["CoreDump"])
                os.close(fd)
            elif isinstance(self["CoreDump"], problem_report.CompressedValue):
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

        for start, end, elf in self._proc_maps_cache:
            if start <= addr <= end:
                return f"{elf}+{addr - start:x}"

        return None

    def _build_proc_maps_cache(self) -> None:
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

    def _add_str_from_coredump(
        self, coredump: dict[str, object], coredump_key: str, key: str
    ) -> None:
        value = coredump.get(coredump_key)
        assert isinstance(value, str)
        self[key] = value.rstrip()

    def _add_coredump_from_systemd_coredump(self, coredump: dict[str, object]) -> None:
        dump = coredump.get("COREDUMP")
        if dump:
            assert isinstance(dump, bytes)
            self["CoreDump"] = dump
            return

        filename = coredump.get("COREDUMP_FILENAME")
        if filename:
            assert isinstance(filename, str)
            try:
                self["CoreDump"] = problem_report.CompressedFile(filename)
            except FileNotFoundError:
                logging.getLogger(__name__).warning(
                    "Ignoring COREDUMP_FILENAME '%s' because it does not exist.",
                    filename,
                )

    @classmethod
    def from_systemd_coredump(cls, coredump):
        """Convert the givin systemd coredump into a problem report.

        The following keys are not used:
         * COREDUMP_CGROUP (str)
         * COREDUMP_COMM (str)
         * COREDUMP_CONTAINER_CMDLINE (str)
         * COREDUMP_GID (int)
         * COREDUMP_HOSTNAME (str)
         * COREDUMP_OPEN_FDS (str)
         * COREDUMP_OWNER_UID (str)
         * COREDUMP_PACKAGE_JSON (str)
         * COREDUMP_PACKAGE_NAME
         * COREDUMP_PACKAGE_VERSION
         * COREDUMP_PROC_AUXV (bytes)
         * COREDUMP_PROC_CGROUP (str)
         * COREDUMP_PROC_LIMITS (str)
         * COREDUMP_PROC_MOUNTINFO (str)
         * COREDUMP_RLIMIT (str)
         * COREDUMP_ROOT (str)
         * COREDUMP_SESSION
         * COREDUMP_SLICE (str)
         * COREDUMP_UID (int)
         * COREDUMP_UNIT (str)
         * COREDUMP_USER_UNIT (str)
         * MESSAGE (str)
        """
        date = coredump.get("COREDUMP_TIMESTAMP")
        assert isinstance(date, datetime.datetime)
        report = cls(date=time.asctime(date.timetuple()))

        pid = coredump.get("COREDUMP_PID")
        assert isinstance(pid, int)
        report.pid = pid

        signal_number = coredump.get("COREDUMP_SIGNAL")
        assert isinstance(signal_number, int)
        report["Signal"] = str(signal_number)

        report._add_str_from_coredump(coredump, "COREDUMP_SIGNAL_NAME", "SignalName")
        report._add_str_from_coredump(coredump, "COREDUMP_CMDLINE", "ProcCmdline")
        report._add_str_from_coredump(coredump, "COREDUMP_EXE", "ExecutablePath")
        report._add_str_from_coredump(coredump, "COREDUMP_CWD", "ProcCwd")
        report._add_str_from_coredump(coredump, "COREDUMP_PROC_MAPS", "ProcMaps")
        report._add_str_from_coredump(coredump, "COREDUMP_PROC_STATUS", "ProcStatus")

        environ = coredump.get("COREDUMP_ENVIRON")
        assert isinstance(environ, str)
        report._add_environ(_Environment.from_string(environ))

        report._add_executable_timestamp()
        if report.get("COREDUMP_TRUNCATED") != "1":
            report._add_coredump_from_systemd_coredump(coredump)

        return report
