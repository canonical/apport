"""Functions to manage apport problem report files."""

# Copyright (C) 2006 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

# TODO: Address following pylint complaints
# pylint: disable=invalid-name,missing-docstring

import configparser
import contextlib
import functools
import glob
import http.client
import io
import json
import operator
import os
import pwd
import re
import socket
import stat
import subprocess
import time

from apport.packaging_impl import impl as packaging
from problem_report import ProblemReport

report_dir = os.environ.get("APPORT_REPORT_DIR", "/var/crash")
core_dir = os.environ.get("APPORT_COREDUMP_DIR", "/var/lib/apport/coredump")
max_corefiles_per_uid = 5

_config_file = "~/.config/apport/settings"

SNAPD_SOCKET = "/run/snapd.socket"


#  UHTTPConnection is based on code from the UpdateManager package:
#  Copyright (c) 2017 Canonical
#  Author: Andrea Azzarone <andrea.azzarone@canonical.com>
class UHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        http.client.HTTPConnection.__init__(self, "localhost")
        self.path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.path)
        self.sock = sock


def allowed_to_report():
    """Check whether crash reporting is enabled."""
    if not os.access("/usr/bin/whoopsie", os.X_OK):
        return True

    try:
        cmd = ["/bin/systemctl", "-q", "is-enabled", "whoopsie.path"]
        return subprocess.call(cmd) == 0
    except OSError:
        return False


def get_dbus_socket(dbus_addr):
    """Extract the socket from a DBus address."""
    if not dbus_addr:
        return None

    # Only support unix domain sockets, and only the default Ubuntu path
    if not dbus_addr.startswith("unix:path=/run/user/"):
        return None

    # Prevent path traversal
    if "../" in dbus_addr:
        return None

    # Don't support escaped values, multiple addresses, or multiple keys
    # and values
    for search in ("%", ",", ";"):
        if search in dbus_addr:
            return None

    parts = dbus_addr.split("=")
    if len(parts) != 2:
        return None

    return parts[1]


def find_package_desktopfile(package):
    """Return a package's .desktop file.

    If given package is installed and has a single .desktop file, return the
    path to it, otherwise return None.
    """
    if package is None:
        return None

    desktopfile = None

    for line in packaging.get_files(package):
        if line.endswith(".desktop"):
            # restrict to autostart and applications, see LP#1147528
            if not line.startswith("/etc/xdg/autostart") and not line.startswith(
                "/usr/share/applications/"
            ):
                continue

            if desktopfile:
                return None  # more than one

            # only consider visible ones
            try:
                with open(line, "rb") as f:
                    if b"NoDisplay=true" not in f.read():
                        desktopfile = line
            except FileNotFoundError:
                continue

    return desktopfile


def likely_packaged(file):
    """Check whether the given file is likely to belong to a package.

    This is semi-decidable: A return value of False is definitive, a True value
    is only a guess which needs to be checked with find_file_package().
    However, this function is very fast and does not access the package
    database.
    """
    # packages only ship executables in these directories
    pkg_allowlist = [
        "/bin/",
        "/boot",
        "/etc/",
        "/initrd",
        "/lib",
        "/sbin/",
        "/opt",
        "/usr/",
        "/var",
    ]

    allowlist_match = False
    for i in pkg_allowlist:
        if file.startswith(i):
            allowlist_match = True
            break
    return (
        allowlist_match
        and not file.startswith("/usr/local/")
        and not file.startswith("/var/lib/")
    )


def find_file_package(file):
    """Return the package that ships the given file.

    Return None if no package ships it.
    """
    # resolve symlinks in directories
    (directory, name) = os.path.split(file)
    resolved_dir = os.path.realpath(directory)
    if os.path.isdir(resolved_dir):
        file = os.path.join(resolved_dir, name)

    if not likely_packaged(file):
        return None

    return packaging.get_file_package(file)


def find_snap(snap):
    """Return the data of the given snap.

    Return None if the snap is not found to be installed.
    """
    try:
        with contextlib.closing(UHTTPConnection(SNAPD_SOCKET)) as c:
            url = f"/v2/snaps/{snap}"
            c.request("GET", url)
            response = c.getresponse()
            if response.status == 200:
                return json.loads(response.read())["result"]
    except (http.client.HTTPException, json.JSONDecodeError, OSError):
        return None
    return None


def seen_report(report):
    """Check whether the report file has already been processed earlier."""
    st = os.stat(report)
    return (st.st_atime > st.st_mtime) or (st.st_size == 0)


def mark_report_upload(report):
    upload = f"{report.rsplit('.', 1)[0]}.upload"
    uploaded = f"{report.rsplit('.', 1)[0]}.uploaded"
    # if uploaded exists and is older than the report remove it and upload
    if os.path.exists(uploaded) and os.path.exists(upload):
        report_st = os.stat(report)
        upload_st = os.stat(upload)
        if upload_st.st_mtime < report_st.st_mtime:
            os.unlink(upload)
    with open(upload, "a", encoding="utf-8"):
        pass


def mark_hanging_process(report, pid):
    if "ExecutablePath" in report:
        subject = report["ExecutablePath"].replace("/", "_")
    else:
        raise ValueError("report does not have the ExecutablePath attribute")

    uid = os.geteuid()
    base = f"{subject}.{str(uid)}.{pid}.hanging"
    path = os.path.join(report_dir, base)
    with open(path, "a", encoding="utf-8"):
        pass


def mark_report_seen(report):
    """Mark given report file as seen."""
    st = os.stat(report)
    try:
        os.utime(report, (st.st_mtime, st.st_mtime - 1))
    except OSError:
        # file is probably not our's, so do it the slow and boring way
        # change the file's access time until it stat's different than the
        # mtime. This might take a while if we only have 1-second resolution.
        # Time out after 1.2 seconds.
        timeout = 12
        while timeout > 0:
            with open(report, encoding="utf-8") as report_file:
                report_file.read(1)
            try:
                st = os.stat(report)
            except OSError:
                return

            if st.st_atime > st.st_mtime:
                break
            time.sleep(0.1)
            timeout -= 1

        if timeout == 0:
            # happens on noatime mounted partitions; just give up and delete
            delete_report(report)


_LOGIN_DEFS_RE = re.compile(
    r"^\s*(?P<name>[A-Z0-9_]+)\s+(?P<quote>[\"\']?)(?P<value>.*)(?P=quote)\s*$"
)


def _parse_login_defs(lines: io.TextIOWrapper) -> dict[str, str]:
    defs = {}
    for line in lines:
        match = _LOGIN_DEFS_RE.match(line)
        if not match:
            continue
        defs[match.group("name")] = match.group("value")
    return defs


@functools.cache
def get_login_defs() -> dict[str, str]:
    """Parse /etc/login.defs and return a dictionary with its content."""
    try:
        with open("/etc/login.defs", encoding="utf-8") as login_defs_file:
            return _parse_login_defs(login_defs_file)
    except FileNotFoundError:
        return {}


def get_sys_gid_max() -> int:
    """Return maximum system group ID (SYS_GID_MAX from /etc/login.defs)."""
    try:
        return int(get_login_defs()["SYS_GID_MAX"])
    except (KeyError, ValueError):
        return 999


def get_sys_uid_max() -> int:
    """Return maximum system user ID (SYS_UID_MAX from /etc/login.defs)."""
    try:
        return int(get_login_defs()["SYS_UID_MAX"])
    except (KeyError, ValueError):
        return 999


def get_all_reports():
    """Return a list with all report files accessible to the calling user."""
    reports = []
    for r in glob.glob(os.path.join(report_dir, "*.crash")):
        try:
            if os.path.getsize(r) > 0 and os.access(r, os.R_OK | os.W_OK):
                reports.append(r)
        except OSError:
            # race condition, can happen if report disappears between glob and
            # stat
            pass
    return reports


def get_new_reports():
    """Get new reports for calling user.

    Return a list with all report files which have not yet been processed
    and are accessible to the calling user.
    """
    reports = []
    for r in get_all_reports():
        try:
            if not seen_report(r):
                reports.append(r)
        except OSError:
            # race condition, can happen if report disappears between glob and
            # stat
            pass
    return reports


def get_all_system_reports():
    """Get all system reports.

    Return a list with all report files which belong to a system user.
    The maximum system user group ID is taken from SYS_UID_MAX from
    /etc/login.defs (defaults to 999 on Debian based systems and LSB
    specifies 499 in "User ID Ranges").
    """
    reports = []
    sys_uid_max = get_sys_uid_max()
    for r in glob.glob(os.path.join(report_dir, "*.crash")):
        try:
            st = os.stat(r)
            if st.st_size > 0 and st.st_uid <= sys_uid_max:
                # filter out guest session crashes;
                # they might have a system UID
                try:
                    pw = pwd.getpwuid(st.st_uid)
                    if pw.pw_name.startswith("guest"):
                        continue
                except KeyError:
                    pass

                reports.append(r)
        except OSError:
            # race condition, can happen if report disappears between glob and
            # stat
            pass
    return reports


def get_new_system_reports():
    """Get new system reports.

    Return a list with all report files which have not yet been processed
    and belong to a system user. The maximum system user group ID is taken
    from SYS_UID_MAX from /etc/login.defs (defaults to 999 on Debian based
    systems and LSB specifies 499 in "User ID Ranges").
    """
    return [r for r in get_all_system_reports() if not seen_report(r)]


def delete_report(report):
    """Delete the given report file.

    If unlinking the file fails due to a permission error (if report_dir is not
    writable to normal users), the file will be truncated to 0 bytes instead.
    """
    try:
        os.unlink(report)
    except OSError:
        with open(report, "w", encoding="utf-8") as f:
            f.truncate(0)


def get_recent_crashes(report):
    """Return the number of recent crashes for the given report file.

    Return the number of recent crashes (currently, crashes which happened more
    than 24 hours ago are discarded).
    """
    pr = ProblemReport()
    pr.load(report, False, key_filter=["CrashCounter", "Date"])
    try:
        count = int(pr["CrashCounter"])
        report_time = time.mktime(time.strptime(pr["Date"]))
        cur_time = time.mktime(time.localtime())
        # discard reports which are older than 24 hours
        if cur_time - report_time > 24 * 3600:
            return 0
        return count
    except (ValueError, KeyError):
        return 0


def increment_crash_counter(report: ProblemReport, filename: str) -> None:
    """Increment the crash counter if report was seen."""
    if not seen_report(filename):
        return
    # Make sure the file isn't a FIFO or symlink
    fd = os.open(filename, os.O_NOFOLLOW | os.O_RDONLY | os.O_NONBLOCK)
    st = os.fstat(fd)
    if stat.S_ISREG(st.st_mode):
        with os.fdopen(fd, "rb") as f:
            crash_counter = get_recent_crashes(f) + 1
        report["CrashCounter"] = str(crash_counter)


def make_report_file(report, uid=None):
    """Construct a canonical pathname for a report and open it for writing.

    If uid is not given, it defaults to the effective uid of the current
    process. The report file must not exist already, to prevent losing
    previous reports or symlink attacks.

    Return an open file object for binary writing.
    """
    if "ExecutablePath" in report:
        subject = report["ExecutablePath"].replace("/", "_")
    elif "Package" in report:
        subject = report["Package"].split(None, 1)[0]
    else:
        raise ValueError("report has neither ExecutablePath nor Package attribute")

    if not uid:
        uid = os.geteuid()

    path = os.path.join(report_dir, f"{subject}.{str(uid)}.crash")
    return open(path, "xb")


def check_files_md5(sumfile):
    """Check file integrity against md5 sum file.

    sumfile must be md5sum(1) format (relative to /).

    Return a list of files that don't match.
    """
    assert os.path.exists(sumfile)
    md5sum = subprocess.run(
        ["/usr/bin/md5sum", "-c", sumfile],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/",
        env={},
    )

    # if md5sum succeeded, don't bother parsing the output
    if md5sum.returncode == 0:
        return []

    mismatches = []
    for line in md5sum.stdout.decode().splitlines():
        if line.endswith("FAILED"):
            mismatches.append(line.rsplit(":", 1)[0])

    return mismatches


@functools.cache
def _get_config_parser(path: str) -> configparser.ConfigParser:
    config = configparser.ConfigParser(interpolation=None)
    contents = ""
    fd = None
    f = None
    try:
        fd = os.open(path, os.O_NOFOLLOW | os.O_RDONLY)
        st = os.fstat(fd)
        if stat.S_ISREG(st.st_mode):
            f = os.fdopen(fd, "r")
            # Limit size to prevent DoS
            contents = f.read(500)
    except OSError:
        pass
    finally:
        if f is not None:
            f.close()
        elif fd is not None:
            os.close(fd)

    try:
        config.read_string(contents)
    except configparser.MissingSectionHeaderError:
        pass

    return config


def get_config(section, setting, default=None, path=None, boolean=False):
    """Return a setting from user configuration.

    This is read from ~/.config/apport/settings or path. If bool is True, the
    value is interpreted as a boolean.

    Privileges may need to be dropped before calling this.
    """
    if not path:
        # Properly handle dropped privileges
        homedir = pwd.getpwuid(os.geteuid())[5]
        path = _config_file.replace("~", homedir)

    config = _get_config_parser(path)

    try:
        if boolean:
            return config.getboolean(section, setting)
        return config.get(section, setting)
    except (configparser.NoOptionError, configparser.NoSectionError):
        return default


def get_starttime(contents: str) -> int:
    """Extract the starttime from the contents of a stat file."""
    # 22nd field in a stat file is the time the process started after
    # system boot in clock ticks. In order to prevent filename
    # manipulations including spaces or extra parentheses, skip all the way
    # to the very last closing parentheses, then start counting.
    stripped = contents[contents.rfind(")") + 2 :]
    # We've skipped over the PID and the filename, so index is now 19.
    return int(stripped.split()[19])


def get_uid_and_gid(contents):
    """Extract the uid and gid from the contents of a status file."""
    real_uid = None
    real_gid = None
    for line in contents.splitlines():
        # Iterate through the whole contents to make sure we're getting
        # the last Uid and Gid lines in the file and not a manipulated
        # process name with embedded newlines.
        if line.startswith("Uid:") and len(line.split()) > 1:
            real_uid = int(line.split()[1])
        elif line.startswith("Gid:") and len(line.split()) > 1:
            real_gid = int(line.split()[1])
    return (real_uid, real_gid)


def search_map(mapfd, uid):
    """Search for an ID in a map fd."""
    for line in mapfd:
        fields = line.split()
        if len(fields) != 3:
            continue

        host_start = int(fields[1])
        host_end = host_start + int(fields[2])

        if host_start <= uid <= host_end:
            return True

    return False


def get_boot_id():
    """Get the kernel boot id."""
    with open("/proc/sys/kernel/random/boot_id", encoding="utf-8") as f:
        boot_id = f.read().strip()
    return boot_id


def get_process_environ(proc_pid_fd: int) -> dict[str, str]:
    """Get the process environ from a proc directory file descriptor.

    Raises an OSError in case the environ file could not been read.
    """

    def opener(path: str | os.PathLike[str], flags: int) -> int:
        return os.open(path, flags, dir_fd=proc_pid_fd)

    with open(
        "environ", encoding="utf-8", errors="replace", opener=opener
    ) as environ_fd:
        environ = environ_fd.read().rstrip("\0 ")

    if not environ:
        return {}
    return dict([entry.split("=", 1) for entry in environ.split("\0") if "=" in entry])


def get_process_path(proc_pid_fd=None):
    """Get the process path from a proc directory file descriptor."""
    if proc_pid_fd is None:
        return "unknown"
    try:
        return os.readlink("exe", dir_fd=proc_pid_fd)
    except OSError:
        return "unknown"


def get_core_path(pid=None, exe=None, uid=None, timestamp=None, proc_pid_fd=None):
    """Get the path to a core file."""
    if pid is None:
        pid = "unknown"
        timestamp = "unknown"
    elif timestamp is None:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as stat_file:
            stat_contents = stat_file.read()
        timestamp = get_starttime(stat_contents)

    if exe is None:
        exe = get_process_path(proc_pid_fd)
    exe = exe.replace("/", "_").replace(".", "_")

    if uid is None:
        uid = os.getuid()

    # This is similar to systemd-coredump, but with the exe name instead
    # of the command name
    core_name = f"core.{exe}.{uid}.{get_boot_id()}.{str(pid)}.{str(timestamp)}"

    core_path = os.path.join(core_dir, core_name)

    return (core_name, core_path)


def find_core_files_by_uid(uid):
    """Search the core file directory for files that belong to a
    specified uid. Returns a list of lists containing the filename and
    the file modification time.
    """
    uid = str(uid)
    core_files = []
    uid_files = []

    if os.path.exists(core_dir):
        core_files = os.listdir(path=core_dir)

    for f in core_files:
        try:
            if f.split(".")[2] == uid:
                core_file_time = os.path.getmtime(os.path.join(core_dir, f))
                uid_files.append([f, core_file_time])
        except (IndexError, FileNotFoundError):
            continue
    return uid_files


def clean_core_directory(uid):
    """Remove old files from the core directory if there are more than
    the maximum allowed per uid.
    """
    uid_files = find_core_files_by_uid(uid)
    sorted_files = sorted(uid_files, key=operator.itemgetter(1))

    # Subtract a extra one to make room for the new core file
    if len(uid_files) > max_corefiles_per_uid - 1:
        for _ in range(len(uid_files) - max_corefiles_per_uid + 1):
            os.remove(os.path.join(core_dir, sorted_files[0][0]))
            sorted_files.remove(sorted_files[0])


def shared_libraries(path):
    """Get libraries with which the specified binary is linked.

    Return a library name -> path mapping, for example 'libc.so.6' ->
    '/lib/x86_64-linux-gnu/libc.so.6'.
    """
    libs = {}

    with subprocess.Popen(
        ["ldd", path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    ) as ldd:
        for line in ldd.stdout:
            try:
                name, rest = line.split("=>", 1)
            except ValueError:
                continue

            name = name.strip()
            # exclude linux-vdso since that is a virtual so
            if "linux-vdso" in name:
                continue
            # this is usually "path (address)"
            rest = rest.split()[0].strip()
            if rest.startswith("("):
                continue
            libs[name] = rest
        ldd.stdout.close()

    if ldd.returncode != 0:
        return {}
    return libs


def should_skip_crash(report: ProblemReport, filename: str) -> str | None:
    """Check if the crash should be skipped for flood protection.

    In case the crash should be skipped return a string with the reason.
    Otherwise return None.
    """
    try:
        crash_counter = int(report["CrashCounter"])
    except (KeyError, ValueError):
        crash_counter = 0
    if crash_counter > 1:
        return f"this executable already crashed {crash_counter} times, ignoring"
    if os.path.exists(filename) and not seen_report(filename):
        # don't clobber existing report
        return (
            f"report {filename} already exists and unseen,"
            f" skipping to avoid disk usage DoS"
        )
    return None


def links_with_shared_library(path, lib):
    """Check if the binary at path links with the library named lib.

    path should be a fully qualified path (e.g. report['ExecutablePath']),
    lib may be of the form 'lib<name>' or 'lib<name>.so.<version>'
    """
    libs = shared_libraries(path)

    if lib in libs:
        return True

    for linked_lib in libs:
        if linked_lib.startswith(f"{lib}.so."):
            return True

    return False
