"""Convenience functions for use in package hooks."""

# Copyright (C) 2008 - 2012 Canonical Ltd.
# Authors:
#   Matt Zimmerman <mdz@canonical.com>
#   Brian Murray <brian@ubuntu.com>
#   Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

# pylint: disable=too-many-lines
# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import base64
import datetime
import glob
import os
import re
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import warnings
from collections.abc import Iterable, Mapping

import apport.fileutils
from apport.packaging_impl import impl as packaging
from problem_report import ProblemReport

_invalid_key_chars_re = re.compile(r"[^0-9a-zA-Z_.-]")
_AGENT = None


def path_to_key(path):
    """Generate a valid report key name from a file path.

    This will replace invalid punctuation symbols with valid ones.
    """
    if isinstance(path, bytes):
        path = path.decode("UTF-8")
    return _invalid_key_chars_re.sub(".", path.replace(" ", "_"))


def attach_file_if_exists(report, path, key=None, overwrite=True, force_unicode=False):
    """Attach file contents if file exists.

    If key is not specified, the key name will be derived from the file
    name with path_to_key().

    If overwrite is True, an existing key will be updated. If it is False, a
    new key with '_' appended will be added instead.

    If the contents is valid UTF-8, or force_unicode is True, then the value
    will be a string, otherwise it will be bytes.
    """
    # Prevent directory traversal. Do it here too so it won't disclose if
    # a file exists or not.
    if "../" in path:
        return

    if not key:
        key = path_to_key(path)

    if os.path.exists(path):
        attach_file(report, path, key, overwrite, force_unicode)


def read_file(path, force_unicode=False):
    # TODO: Split into smaller functions/methods
    # pylint: disable=too-many-return-statements
    """Return the contents of the specified path.

    If the contents is valid UTF-8, or force_unicode is True, then the value
    will a string, otherwise it will be bytes.

    Upon error, this will deliver a text representation of the error,
    instead of failing.
    """
    try:
        # Prevent directory traversal
        if "../" in path:
            return "Error: invalid path."
        fd = os.open(path, os.O_NOFOLLOW | os.O_RDONLY | os.O_NONBLOCK)
        st = os.fstat(fd)
        # make sure there are no symlinks in the full path
        real_path = os.path.realpath(path)
        if st.st_ino != os.stat(real_path).st_ino or path != real_path:
            os.close(fd)
            return "Error: path contained symlinks."
        # make sure the file isn't a FIFO or symlink
        if stat.S_ISREG(st.st_mode):
            with os.fdopen(fd, "rb") as f:
                contents = f.read().strip()
        else:
            os.close(fd)
            return "Error: path was not a regular file."
    except OSError as error:
        return f"Error: {str(error)}"

    if force_unicode:
        return contents.decode("UTF-8", errors="replace")
    try:
        return contents.decode("UTF-8")
    except UnicodeDecodeError:
        return contents


def attach_file(report, path, key=None, overwrite=True, force_unicode=False):
    """Attach a file to the report.

    If key is not specified, the key name will be derived from the file
    name with path_to_key().

    If overwrite is True, an existing key will be updated. If it is False, a
    new key with '_' appended will be added instead.

    If the contents is valid UTF-8, or force_unicode is True, then the value
    will a string, otherwise it will be bytes.
    """
    if not key:
        key = path_to_key(path)

    # Do not clobber existing keys
    if not overwrite:
        while key in report:
            key += "_"
    report[key] = read_file(path, force_unicode=force_unicode)


def attach_conffiles(report, package, conffiles=None, ui=None):
    """Attach information about any modified or deleted conffiles.

    If conffiles is given, only this subset will be attached. If ui is given,
    ask whether the contents of the file may be added to the report; if this is
    denied, or there is no UI, just mark it as "modified" in the report.
    """
    modified = packaging.get_modified_conffiles(package)

    for path, contents in modified.items():
        if conffiles and path not in conffiles:
            continue

        key = f"modified.conffile.{path_to_key(path)}"
        if isinstance(contents, str) and (
            contents == "[deleted]" or contents.startswith("[inaccessible")
        ):
            report[key] = contents
            continue

        if ui:
            response = ui.yesno(
                f'It seems you have modified the contents of "{path}".  '
                f"Would you like to add the contents of it to your bug report?"
            )
            if response:
                report[key] = contents
            else:
                report[key] = "[modified]"
        else:
            report[key] = "[modified]"

        mtime = datetime.datetime.fromtimestamp(os.stat(path).st_mtime)
        report[f"mtime.conffile.{path_to_key(path)}"] = mtime.isoformat()


# pylint: disable-next=unused-argument
def attach_upstart_overrides(report, package):
    """Attach information about any Upstart override files."""
    warnings.warn(
        "apport.hookutils.attach_upstart_overrides() is obsolete."
        " Upstart is dead. Please drop this call.",
        PendingDeprecationWarning,
        stacklevel=2,
    )


# pylint: disable-next=unused-argument
def attach_upstart_logs(report, package):
    """Attach information about a package's session upstart logs."""
    warnings.warn(
        "apport.hookutils.attach_upstart_logs() is obsolete."
        " Upstart is dead. Please drop this call.",
        PendingDeprecationWarning,
        stacklevel=2,
    )


def attach_dmesg(report):
    """Attach information from the kernel ring buffer (dmesg).

    This will not overwrite already existing information.
    """
    if not report.get("CurrentDmesg", "").strip():
        report["CurrentDmesg"] = root_command_output(["dmesg"])


def attach_dmi(report):
    """Attach Desktop Management Interface (DMI) information to the report."""
    dmi_dir = "/sys/class/dmi/id"
    if os.path.isdir(dmi_dir):
        for f in os.listdir(dmi_dir):
            if f in {"subsystem", "uevent"}:
                continue
            p = os.path.realpath(f"{dmi_dir}/{f}")
            st = os.stat(p)
            # ignore the root-only ones, since they have serial numbers
            if not stat.S_ISREG(st.st_mode) or (st.st_mode & 4 == 0):
                continue

            try:
                value = read_file(p)
            except OSError:
                continue
            if value:
                report[f"dmi.{f.replace('_', '.')}"] = value

    # Use the hardware information to create a machine type.
    if "dmi.sys.vendor" in report and "dmi.product.name" in report:
        report["MachineType"] = (
            f"{report['dmi.sys.vendor']} {report['dmi.product.name']}"
        )


def attach_hardware(report):
    """Attach a standard set of hardware-related data to the report, including:

    - kernel dmesg (boot and current)
    - /proc/interrupts
    - /proc/cpuinfo
    - /proc/cmdline
    - /proc/modules
    - lspci -vvnn
    - lscpi -vt
    - lsusb
    - lsusb -v
    - lsusb -t
    - devices from udev
    - DMI information from /sys
    - prtconf (sparc)
    - pccardctl status/ident
    """
    attach_dmesg(report)

    attach_file(report, "/proc/interrupts", "ProcInterrupts")
    attach_file(report, "/proc/cpuinfo", "ProcCpuinfo")
    attach_file(report, "/proc/cmdline", "ProcKernelCmdLine")

    if os.path.exists("/sys/bus/pci"):
        report["Lspci"] = command_output(["lspci", "-vvnn"])
        report["Lspci-vt"] = command_output(["lspci", "-vt"])
    report["Lsusb"] = command_output(["lsusb"])
    report["Lsusb-v"] = command_output(["lsusb", "-v"])
    report["Lsusb-t"] = command_output(["lsusb", "-t"])
    report["ProcModules"] = command_output(["sort", "/proc/modules"])
    report["UdevDb"] = command_output(["udevadm", "info", "--export-db"])
    report["acpidump"] = root_command_output(["/usr/share/apport/dump_acpi_tables.py"])

    # anonymize partition labels
    labels = report["UdevDb"]
    labels = re.sub("ID_FS_LABEL=(.*)", "ID_FS_LABEL=<hidden>", labels)
    labels = re.sub("ID_FS_LABEL_ENC=(.*)", "ID_FS_LABEL_ENC=<hidden>", labels)
    labels = re.sub("by-label/(.*)", "by-label/<hidden>", labels)
    labels = re.sub("ID_FS_LABEL=(.*)", "ID_FS_LABEL=<hidden>", labels)
    labels = re.sub("ID_FS_LABEL_ENC=(.*)", "ID_FS_LABEL_ENC=<hidden>", labels)
    labels = re.sub("by-label/(.*)", "by-label/<hidden>", labels)
    report["UdevDb"] = labels

    attach_dmi(report)

    if command_available("prtconf"):
        report["Prtconf"] = command_output(["prtconf"])

    if command_available("pccardctl"):
        out = command_output(["pccardctl", "status"]).strip()
        if out:
            report["PccardctlStatus"] = out
        out = command_output(["pccardctl", "ident"]).strip()
        if out:
            report["PccardctlIdent"] = out


def attach_alsa_old(report):
    """(loosely based on http://www.alsa-project.org/alsa-info.sh)
    for systems where alsa-info is not installed
    (i e, *buntu 12.04 and earlier)
    """
    attach_file_if_exists(report, os.path.expanduser("~/.asoundrc"), "UserAsoundrc")
    attach_file_if_exists(
        report, os.path.expanduser("~/.asoundrc.asoundconf"), "UserAsoundrcAsoundconf"
    )
    attach_file_if_exists(report, "/etc/asound.conf")
    attach_file_if_exists(report, "/proc/asound/version", "AlsaVersion")
    attach_file(report, "/proc/cpuinfo", "ProcCpuinfo")

    report["AlsaDevices"] = command_output(["ls", "-l", "/dev/snd/"])
    report["AplayDevices"] = command_output(["aplay", "-l"])
    report["ArecordDevices"] = command_output(["arecord", "-l"])

    report["PciMultimedia"] = pci_devices(PCI_MULTIMEDIA)

    cards = []
    if os.path.exists("/proc/asound/cards"):
        with open("/proc/asound/cards", encoding="utf-8") as fd:
            for line in fd:
                if "]:" in line:
                    fields = line.lstrip().split()
                    cards.append(int(fields[0]))

    for card in cards:
        key = f"Card{card}.Amixer.info"
        report[key] = command_output(["amixer", "-c", str(card), "info"])
        key = f"Card{card}.Amixer.values"
        report[key] = command_output(["amixer", "-c", str(card)])

        for codecpath in glob.glob(f"/proc/asound/card{card}/codec*"):
            if os.path.isfile(codecpath):
                codec = os.path.basename(codecpath)
                key = f"Card{card}.Codecs.{path_to_key(codec)}"
                attach_file(report, codecpath, key=key)
            elif os.path.isdir(codecpath):
                codec = os.path.basename(codecpath)
                for name in os.listdir(codecpath):
                    path = os.path.join(codecpath, name)
                    key = (
                        f"Card{card}.Codecs"
                        f".{path_to_key(codec)}.{path_to_key(name)}"
                    )
                    attach_file(report, path, key)


def attach_alsa(report):
    """Attach ALSA subsystem information to the report."""
    if os.path.exists("/usr/sbin/alsa-info"):
        report["AlsaInfo"] = command_output(
            ["/usr/sbin/alsa-info", "--stdout", "--no-upload"]
        )
    elif os.path.exists("/usr/share/alsa-base/alsa-info.sh"):
        report["AlsaInfo"] = command_output(
            ["/usr/share/alsa-base/alsa-info.sh", "--stdout", "--no-upload"]
        )
    else:
        attach_alsa_old(report)

    report["AudioDevicesInUse"] = command_output(
        ["fuser", "-v"]
        + glob.glob("/dev/dsp*")
        + glob.glob("/dev/snd/*")
        + glob.glob("/dev/seq*")
    )

    if os.path.exists("/usr/bin/pacmd"):
        report["PulseList"] = command_output(["pacmd", "list"])

    if os.path.exists("/usr/bin/pa-info"):
        report["PaInfo"] = command_output(["/usr/bin/pa-info"])

    attach_dmi(report)
    attach_dmesg(report)


def command_available(command):
    """Is given command on the executable search path?"""
    if "PATH" not in os.environ:
        return False
    path = os.environ["PATH"]
    for element in path.split(os.pathsep):
        if not element:
            continue
        filename = os.path.join(element, command)
        if os.path.isfile(filename) and os.access(filename, os.X_OK):
            return True
    return False


def command_output(
    command,
    input=None,  # pylint: disable=redefined-builtin
    stderr=subprocess.STDOUT,
    keep_locale=False,
    decode_utf8=True,
):
    """Try to execute given command (list) and return its stdout.

    In case of failure, a textual error gets returned. This function forces
    LC_MESSAGES to C, to avoid translated output in bug reports.

    If decode_utf8 is True (default), the output will be converted to a string,
    otherwise left as bytes.
    """
    env = os.environ.copy()
    if not keep_locale:
        env["LC_MESSAGES"] = "C"
    try:
        sp = subprocess.run(
            command,
            check=False,
            input=input,
            stdout=subprocess.PIPE,
            stderr=stderr,
            env=env,
        )
    except OSError as error:
        return f"Error: {str(error)}"

    if sp.returncode == 0:
        res = sp.stdout.strip()
    else:
        res = (
            b"Error: command "
            + str(command).encode()
            + b" failed with exit code "
            + str(sp.returncode).encode()
            + b": "
            + sp.stdout
        )

    if decode_utf8:
        res = res.decode("UTF-8", errors="replace")
    return res


def _spawn_pkttyagent():
    global _AGENT  # pylint: disable=global-statement

    if _AGENT is not None:
        return
    if os.geteuid() == 0:
        return
    if not sys.stdin.isatty():
        return
    if not os.path.exists("/usr/bin/pkttyagent"):
        return

    try:
        (r, w) = os.pipe2(0)
    except OSError:
        return

    # closed by kill_pkttyagent(), pylint: disable=consider-using-with
    _AGENT = subprocess.Popen(
        ["pkttyagent", "--notify-fd", str(w), "--fallback"],
        close_fds=False,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    os.close(w)

    with select.epoll() as epoll:
        while True:
            epoll.register(r, select.EPOLLIN)
            events = epoll.poll()
            for _, event_type in events:
                if event_type & select.EPOLLHUP:
                    os.close(r)
                    return


def kill_pkttyagent():
    """Kill pkttyagent (from PolicyKit) if it was started by Apport."""
    global _AGENT  # pylint: disable=global-statement

    if _AGENT is None:
        return

    _AGENT.terminate()
    _AGENT.wait()
    _AGENT = None


def _root_command_prefix():
    if os.getuid() == 0:
        return []
    if os.path.exists("/usr/bin/pkexec"):
        _spawn_pkttyagent()
        return ["pkexec"]
    # the package hook won't have everything it wanted but that's okay
    return []


def root_command_output(  # pylint: disable=redefined-builtin
    command, input=None, stderr=subprocess.STDOUT, decode_utf8=True
):
    """Try to execute given command (list) as root and return its stdout.

    This passes the command through pkexec, unless the caller is already root.

    In case of failure, a textual error gets returned.

    If decode_utf8 is True (default), the output will be converted to a string,
    otherwise left as bytes.
    """
    assert isinstance(command, list), "command must be a list"
    output = command_output(
        _root_command_prefix() + command,
        input,
        stderr,
        keep_locale=True,
        decode_utf8=decode_utf8,
    )
    return output


def execute_multiple_root_commands(
    command_map: Mapping[str, str],
) -> dict[str, str | bytes]:
    """Execute multiple commands as root and return their respective outputs.

    command_map is a keyname -> 'shell command' dictionary with the commands to
    run. They are all run through /bin/sh, so you need to take care of shell
    escaping yourself. To include stderr output of a command, end it with
    "2>&1".

    Just like root_command_output, this passes the command through pkexec,
    unless the caller is already root.

    This is preferable to using root_command_output() multiple times, as that
    will ask for the password every time.
    """
    if not command_map:
        return {}

    output: dict[str, bytes | str] = {}
    wrapper_path = os.path.join(
        os.path.abspath(os.environ.get("APPORT_DATA_DIR", "/usr/share/apport")),
        "root_info_wrapper",
    )
    workdir = tempfile.mkdtemp()
    try:
        # create a shell script with all the commands
        script_path = os.path.join(workdir, ":script:")
        with open(script_path, "w", encoding="utf-8") as script:
            for keyname, command in command_map.items():
                assert hasattr(
                    command, "strip"
                ), "command must be a string (shell command)"
                # use "| cat" here, so that we can end commands with 2>&1
                # (otherwise it would have the wrong redirection order)
                script.write(f"{command} | cat > {os.path.join(workdir, keyname)}\n")

        # run script
        subprocess.run(
            _root_command_prefix() + [wrapper_path, script_path], check=False
        )

        # now read back the individual outputs
        for keyname in command_map:
            try:
                with open(os.path.join(workdir, keyname), "rb") as f:
                    buf = f.read().strip()
            except OSError:
                # this can happen if the user dismisses authorization in
                # _root_command_prefix
                continue
            # opportunistically convert to strings, like command_output()
            if buf:
                try:
                    output[keyname] = buf.decode("UTF-8")
                except UnicodeDecodeError:
                    output[keyname] = buf
        return output
    finally:
        shutil.rmtree(workdir)


def attach_root_command_outputs(
    report: ProblemReport, command_map: Mapping[str, str]
) -> None:
    """Execute multiple commands as root and put their outputs into report.

    command_map is a keyname -> 'shell command' dictionary with the commands to
    run. They are all run through /bin/sh, so you need to take care of shell
    escaping yourself. To include stderr output of a command, end it with
    "2>&1".

    Just like root_command_output, this passes the command through pkexec,
    unless the caller is already root.

    This is preferable to using root_command_output() multiple times, as that
    will ask for the password every time.
    """
    for k, v in execute_multiple_root_commands(command_map).items():
        report[k] = v


def __filter_re_process(pattern, process):
    lines = ""
    # Get stdout while waiting for process to complete
    while process.poll() is None:
        for line in process.stdout:
            line = line.decode("UTF-8", errors="replace")
            if pattern.search(line):
                lines += line
    # Ensure all stdout is read after process completion
    for line in process.stdout:
        line = line.decode("UTF-8", errors="replace")
        if pattern.search(line):
            lines += line
    process.stdout.close()
    process.wait()
    if process.returncode == 0:
        return lines
    return ""


def recent_syslog(pattern, path=None, *, journald_only_system=True):
    """Extract recent system messages which match a regex.

    pattern should be a "re" object. By default, messages are read from
    the systemd journal, or /var/log/syslog; but when giving "path", messages
    are read from there instead.
    The journald_only_system parameter controls the scope of messages that are
    extracted when reading from the systemd journal. If set to True (the
    default), only messages from the system services are extracted. If set to
    False, all messages that the current user can see are extracted.
    """
    if path:
        command = ["tail", "-n", "10000", path]
    elif os.path.exists("/run/systemd/system"):
        command = ["journalctl", "--quiet", "-b", "-a"]
        if journald_only_system:
            command.append("--system")
    elif os.access("/var/log/syslog", os.R_OK):
        command = ["tail", "-n", "10000", "/var/log/syslog"]
    else:
        return ""
    with subprocess.Popen(command, stdout=subprocess.PIPE) as process:
        return __filter_re_process(pattern, process)


def xsession_errors(pattern=None):
    """Extract messages from ~/.xsession-errors.

    By default this parses out glib-style warnings, errors, criticals etc. and
    X window errors.  You can specify a "re" object as pattern to customize the
    filtering.

    Please note that you should avoid attaching the whole file to reports, as
    it can, and often does, contain sensitive and private data.
    """
    path = os.path.expanduser("~/.xsession-errors")
    if not os.path.exists(path) or not os.access(path, os.R_OK):
        return ""

    if not pattern:
        pattern = re.compile(
            r"^(\(.*:\d+\): \w+-(WARNING|CRITICAL|ERROR))"
            r"|(Error: .*No Symbols named)"
            r"|([^ ]+\[\d+\]: ([A-Z]+):)"
            r"|([^ ]-[A-Z]+ \*\*:)"
            r"|(received an X Window System error)"
            r"|(^The error was \')"
            r"|(^  \(Details: serial \d+ error_code)"
        )

    lines = ""
    with open(path, "rb") as f:
        for line in f:
            line = line.decode("UTF-8", errors="replace")
            if pattern.search(line):
                lines += line
    return lines


PCI_MASS_STORAGE = 0x01
PCI_NETWORK = 0x02
PCI_DISPLAY = 0x03
PCI_MULTIMEDIA = 0x04
PCI_MEMORY = 0x05
PCI_BRIDGE = 0x06
PCI_SIMPLE_COMMUNICATIONS = 0x07
PCI_BASE_SYSTEM_PERIPHERALS = 0x08
PCI_INPUT_DEVICES = 0x09
PCI_DOCKING_STATIONS = 0x0A
PCI_PROCESSORS = 0x0B
PCI_SERIAL_BUS = 0x0C


def pci_devices(*pci_classes):
    """Return a text dump of PCI devices attached to the system."""
    if not pci_classes:
        return command_output(["lspci", "-vvnn"])

    result = ""
    output = command_output(["lspci", "-vvmmnn"])
    for paragraph in output.split("\n\n"):
        pci_class = None
        slot = None

        for line in paragraph.split("\n"):
            try:
                key, value = line.split(":", 1)
            except ValueError:
                continue
            value = value.strip()
            key = key.strip()
            if key == "Class":
                n = int(value[-5:-1], 16)
                pci_class = (n & 0xFF00) >> 8
            elif key == "Slot":
                slot = value

        if pci_class and slot and pci_class in pci_classes:
            if result:
                result += "\n\n"
            result += command_output(["lspci", "-vvnns", slot]).strip()

    return result


def usb_devices():
    """Return a text dump of USB devices attached to the system."""
    # TODO: would be nice to be able to filter by interface class
    return command_output(["lsusb", "-v"])


def files_in_package(package, globpat=None):
    """Retrieve a list of files owned by package, optionally matching
    globpat."""
    files = packaging.get_files(package)
    if globpat:
        result = [f for f in files if glob.fnmatch.fnmatch(f, globpat)]
    else:
        result = files
    return result


def attach_gconf(report, package):  # pylint: disable=unused-argument
    """Obsolete."""
    # keeping a no-op function for some time to not break hooks


def attach_gsettings_schema(report, schema):
    """Attach user-modified gsettings keys of a schema."""
    cur_value = report.get("GsettingsChanges", "")

    defaults = {}  # schema -> key ->  value
    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = "/nonexisting"
    with subprocess.Popen(
        ["gsettings", "list-recursively", schema], env=env, stdout=subprocess.PIPE
    ) as gsettings:
        for line in gsettings.stdout:
            try:
                (schema_name, key, value) = line.split(None, 2)
                value = value.rstrip()
            except ValueError:
                continue  # invalid line
            defaults.setdefault(schema_name, {})[key] = value

    with subprocess.Popen(
        ["gsettings", "list-recursively", schema], stdout=subprocess.PIPE
    ) as gsettings:
        for line in gsettings.stdout:
            try:
                (schema_name, key, value) = line.split(None, 2)
                value = value.rstrip()
            except ValueError:
                continue  # invalid line

            if value != defaults.get(schema_name, {}).get(key, ""):
                if schema_name == b"org.gnome.shell" and key in {
                    b"command-history",
                    b"favorite-apps",
                }:
                    value = "redacted by apport"
                cur_value += f"{schema_name} {key} {value}\n"

    report["GsettingsChanges"] = cur_value


def attach_gsettings_package(report, package):
    """Attach user-modified gsettings keys of all schemas in a package."""
    for schema_file in files_in_package(
        package, "/usr/share/glib-2.0/schemas/*.gschema.xml"
    ):
        schema = os.path.basename(schema_file)[:-12]
        attach_gsettings_schema(report, schema)


def attach_journal_errors(report: ProblemReport, time_window: int = 10) -> None:
    """Attach journal warnings and errors.

    If the report contains a date, get the journal logs around that
    date (plus/minus the time_window in seconds). Otherwise attach the
    latest 1000 journal logs since the last boot.
    """
    if not os.path.exists("/run/systemd/system"):
        return

    crash_timestamp = report.get_timestamp()
    if crash_timestamp:
        before_crash = crash_timestamp - time_window
        after_crash = crash_timestamp + time_window
        args = [f"--since=@{before_crash}", f"--until=@{after_crash}"]
    else:
        args = ["-b", "--lines=1000"]
    report["JournalErrors"] = command_output(
        ["journalctl", "--priority=warning"] + args
    )


def attach_network(report):
    """Attach generic network-related information to report."""
    report["IpRoute"] = command_output(["ip", "route"])
    report["IpAddr"] = command_output(["ip", "addr"])
    report["PciNetwork"] = pci_devices(PCI_NETWORK)
    attach_file_if_exists(report, "/etc/network/interfaces", key="IfupdownConfig")

    for var in ("http_proxy", "ftp_proxy", "no_proxy"):
        if var in os.environ:
            report[var] = os.environ[var]


def _get_wireless_devices() -> list[str]:
    """Return list of wireless devices on the system."""
    return [p.split("/")[4] for p in glob.glob("/sys/class/net/*/wireless")]


def attach_wifi(report):
    """Attach wireless (WiFi) network information to report."""
    report["WifiSyslog"] = recent_syslog(
        re.compile(
            r"(NetworkManager|modem-manager|dhclient|kernel|wpa_supplicant)"
            r"(\[\d+\])?:"
        )
    )
    report["RfKill"] = command_output(["rfkill", "list"])
    if os.path.exists("/sbin/iw"):
        for wireless_device in _get_wireless_devices():
            report[f"IwDev{wireless_device.capitalize()}Link"] = re.sub(
                "([0-9a-f]{2}:){5}[0-9a-f]{2}",
                "<hidden-mac>",
                re.sub(
                    "SSID: (.*)",
                    "SSID: <hidden>",
                    command_output(["iw", "dev", wireless_device, "link"]),
                ),
            )
        iw_output = command_output(["iw", "reg", "get"])
    else:
        iw_output = "N/A"
    report["CRDA"] = iw_output

    attach_file_if_exists(report, "/var/log/wpa_supplicant.log", key="WpaSupplicantLog")


def attach_printing(report):
    """Attach printing information to the report.

    Based on http://wiki.ubuntu.com/PrintingBugInfoScript.
    """
    attach_file_if_exists(report, "/etc/papersize", "Papersize")
    attach_file_if_exists(report, "/var/log/cups/error_log", "CupsErrorLog")
    report["Locale"] = command_output(["locale"])
    report["Lpstat"] = command_output(["lpstat", "-v"])

    ppds = glob.glob("/etc/cups/ppd/*.ppd")
    if ppds:
        nicknames = command_output(["fgrep", "-H", "*NickName"] + ppds)
        report["PpdFiles"] = re.sub(
            r'/etc/cups/ppd/(.*).ppd:\*NickName: *"(.*)"', r"\g<1>: \g<2>", nicknames
        )

    report["PrintingPackages"] = package_versions(
        "foo2zjs",
        "foomatic-db",
        "foomatic-db-engine",
        "foomatic-db-gutenprint",
        "foomatic-db-hpijs",
        "foomatic-filters",
        "foomatic-gui",
        "hpijs",
        "hplip",
        "m2300w",
        "min12xxw",
        "c2050",
        "hpoj",
        "pxljr",
        "pnm2ppa",
        "splix",
        "hp-ppd",
        "hpijs-ppds",
        "linuxprinting.org-ppds",
        "openprinting-ppds",
        "openprinting-ppds-extra",
        "ghostscript",
        "cups",
        "cups-driver-gutenprint",
        "foomatic-db-gutenprint",
        "ijsgutenprint",
        "cupsys-driver-gutenprint",
        "gimp-gutenprint",
        "gutenprint-doc",
        "gutenprint-locales",
        "system-config-printer-common",
        "kdeprint",
    )


def attach_mac_events(
    report: ProblemReport, profiles: Iterable[str] | str | None = None
) -> None:
    """Attach MAC information and events to the report."""
    # Allow specifying a string, or a list of strings
    if isinstance(profiles, str):
        profiles = [profiles]

    mac_regex = r"(?:audit\(|apparmor|selinux|security).*"
    mac_re = re.compile(mac_regex, re.IGNORECASE)
    aa_regex = 'apparmor="DENIED".+?profile=([^ ]+?)[ ]'
    aa_re = re.compile(aa_regex, re.IGNORECASE)

    privileged_commands = {}
    if "KernLog" not in report:
        privileged_commands["dmesg"] = "dmesg"

    if "AuditLog" not in report and os.path.exists("/var/run/auditd.pid"):
        privileged_commands["AuditLog"] = (
            f'egrep "{mac_regex}" /var/log/audit/audit.log'
        )

    privileged_outputs = execute_multiple_root_commands(privileged_commands)

    if "dmesg" in privileged_outputs:
        output = privileged_outputs["dmesg"]
        assert isinstance(output, str)
        report["KernLog"] = "\n".join(re.findall(mac_re, output))
    if "AuditLog" in privileged_outputs:
        report["AuditLog"] = privileged_outputs["AuditLog"]

    attach_file_if_exists(report, "/proc/version_signature", "ProcVersionSignature")
    attach_file(report, "/proc/cmdline", "ProcCmdline")

    for match in re.findall(
        aa_re, "\n".join((report.get("KernLog", ""), report.get("AuditLog", "")))
    ):
        if not profiles:
            report.add_tags(["apparmor"])
            break

        try:
            if match[0] == '"':
                profile = match[1:-1]
            else:
                profile = bytes.fromhex(match).decode("UTF-8", errors="replace")
        except (IndexError, ValueError):
            continue

        for search_profile in profiles:
            if re.match(f"^{search_profile}$", profile):
                report.add_tags(["apparmor"])
                break


def attach_related_packages(report, packages):
    """Attach version information for related packages.

    In the future, this might also run their hooks.
    """
    report["RelatedPackageVersions"] = package_versions(*packages)


def package_versions(*packages):
    """Return a text listing of package names and versions.

    Arguments may be package names or globs, e. g. "foo*"
    """
    if not packages:
        return ""
    versions = []
    for package_pattern in packages:
        if not package_pattern:
            continue

        matching_packages = packaging.package_name_glob(package_pattern)

        if not matching_packages:
            versions.append((package_pattern, "N/A"))

        for package in sorted(matching_packages):
            try:
                version = packaging.get_version(package)
            except ValueError:
                version = "N/A"
            if version is None:
                version = "N/A"
            versions.append((package, version))

    package_width = max(len(version[0]) for version in versions)
    return "\n".join([f"{p:<{package_width}s} {v}" for (p, v) in versions])


def _get_module_license(module):
    """Return the license for a given kernel module."""
    try:
        modinfo = subprocess.run(
            ["/sbin/modinfo", module],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if modinfo.returncode != 0:
            return "invalid"
    except OSError:
        return None
    for line in modinfo.stdout.decode("UTF-8").splitlines():
        fields = line.split(":", 1)
        if len(fields) < 2:
            continue
        if fields[0] == "license":
            return fields[1].strip()

    return None


def nonfree_kernel_modules(module_list="/proc/modules"):
    """Check loaded modules and return a list of those which are not free."""
    try:
        with open(module_list, encoding="utf-8") as f:
            mods = [line.split()[0] for line in f]
    except OSError:
        return []

    nonfree = []
    for m in mods:
        s = _get_module_license(m)
        if s and not ("GPL" in s or "BSD" in s or "MPL" in s or "MIT" in s):
            nonfree.append(m)

    return nonfree


def __drm_con_info(con):
    info = ""
    for f in os.listdir(con):
        path = os.path.join(con, f)
        if f == "uevent" or not os.path.isfile(path):
            continue
        with open(path, "rb") as con_info_file:
            val = con_info_file.read().strip()
        # format some well-known attributes specially
        if f == "modes":
            val = val.replace(b"\n", b" ")
        if f == "edid":
            val = base64.b64encode(val)
            f += "-base64"
        info += f"{f}: {val.decode('UTF-8', errors='replace')}\n"
    return info


def attach_drm_info(report):
    """Add information about DRM hardware.

    Collect information from /sys/class/drm/.
    """
    drm_dir = "/sys/class/drm"
    if not os.path.isdir(drm_dir):
        return
    for f in os.listdir(drm_dir):
        con = os.path.join(drm_dir, f)
        if os.path.exists(os.path.join(con, "enabled")):
            # DRM can set an arbitrary string for its connector paths.
            report[f"DRM.{path_to_key(f)}"] = __drm_con_info(con)


def in_session_of_problem(report):
    """Check if the problem happened in the currently running XDG session.

    This can be used to determine if e. g. ~/.xsession-errors is relevant and
    should be attached.

    Return None if this cannot be determined.
    """
    session_id = os.environ.get("XDG_SESSION_ID")
    if not session_id:
        # fall back to reading cgroup
        with open("/proc/self/cgroup", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if (
                    "name=systemd:" in line
                    and line.endswith(".scope")
                    and "/session-" in line
                ):
                    session_id = line.split("/session-", 1)[1][:-6]
                    break
            else:
                return None

    try:
        report_time = report.get_timestamp()
    except AttributeError:
        return None
    if report_time is None:
        return None

    # determine session creation time
    try:
        session_start_time = os.stat(f"/run/systemd/sessions/{session_id}").st_mtime
    except OSError:
        return None

    return session_start_time <= report_time


def attach_default_grub(report, key=None):
    """Attach /etc/default/grub after filtering out password lines."""
    path = "/etc/default/grub"
    if not key:
        key = path_to_key(path)

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            filtered = [
                (
                    line
                    if not line.startswith("password")
                    else "### PASSWORD LINE REMOVED ###"
                )
                for line in f.readlines()
            ]
            report[key] = "".join(filtered)


# backwards compatible API
shared_libraries = apport.fileutils.shared_libraries
links_with_shared_library = apport.fileutils.links_with_shared_library
