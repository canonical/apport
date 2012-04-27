'''Convenience functions for use in package hooks.'''

# Copyright (C) 2008 - 2011 Canonical Ltd.
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

import subprocess
import os
import sys
import time
import calendar
import datetime
import glob
import re
import stat
import base64
import tempfile
import shutil
import locale

from gi.repository import Gio, GLib

from apport.packaging_impl import impl as packaging

import apport

try:
    _path_key_trans = ''.maketrans('#/-_+ ', '....._')
except AttributeError:
    # Python 2 variant
    import string
    _path_key_trans = string.maketrans('#/-_+ ', '....._')


def path_to_key(path):
    '''Generate a valid report key name from a file path.

    This will replace invalid punctuation symbols with valid ones.
    '''
    if sys.version[0] >= '3':
        if type(path) == type(b''):
            path = path.decode('UTF-8')
    else:
        if type(path) != type(b''):
            path = path.encode('UTF-8')
    return path.translate(_path_key_trans)


def attach_file_if_exists(report, path, key=None, overwrite=True):
    '''Attach file contents if file exists.

    If key is not specified, the key name will be derived from the file
    name with path_to_key().

    If overwrite is True, an existing key will be updated. If it is False, a
    new key with '_' appended will be added instead.
    '''
    if not key:
        key = path_to_key(path)

    if os.path.exists(path):
        attach_file(report, path, key, overwrite)


def read_file(path):
    '''Return the contents of the specified path.

    Upon error, this will deliver a text representation of the error,
    instead of failing.
    '''
    try:
        with open(path, 'rb') as f:
            return f.read().strip()
    except Exception as e:
        return 'Error: ' + str(e)


def attach_file(report, path, key=None, overwrite=True):
    '''Attach a file to the report.

    If key is not specified, the key name will be derived from the file
    name with path_to_key().

    If overwrite is True, an existing key will be updated. If it is False, a
    new key with '_' appended will be added instead.
    '''
    if not key:
        key = path_to_key(path)

    # Do not clobber existing keys
    if not overwrite:
        while key in report:
            key += '_'
    report[key] = read_file(path)


def attach_conffiles(report, package, conffiles=None, ui=None):
    '''Attach information about any modified or deleted conffiles.

    If conffiles is given, only this subset will be attached. If ui is given,
    ask whether the contents of the file may be added to the report; if this is
    denied, or there is no UI, just mark it as "modified" in the report.
    '''
    modified = packaging.get_modified_conffiles(package)

    for path, contents in modified.items():
        if conffiles and path not in conffiles:
            continue

        key = 'modified.conffile.' + path_to_key(path)
        if contents == '[deleted]':
            report[key] = contents
            continue

        if ui:
            response = ui.yesno('It seems you have modified the contents of "%s".  Would you like to add the contents of it to your bug report?' % path)
            if response:
                report[key] = contents
            else:
                report[key] = '[modified]'
        else:
            report[key] = '[modified]'

        mtime = datetime.datetime.fromtimestamp(os.stat(path).st_mtime)
        report['mtime.conffile.' + path_to_key(path)] = mtime.isoformat()


def attach_upstart_overrides(report, package):
    '''Attach information about any Upstart override files'''

    try:
        files = apport.packaging.get_files(package)
    except ValueError:
        return

    for file in files:
        if os.path.exists(file) and file.startswith('/etc/init/'):
            override = file.replace('.conf', '.override')
            key = 'upstart.' + override.replace('/etc/init/', '')
            attach_file_if_exists(report, override, key)


def attach_dmesg(report):
    '''Attach information from the kernel ring buffer (dmesg).

    This will not overwrite already existing information.
    '''
    try:
        if not report.get('BootDmesg', '').strip():
            with open('/var/log/dmesg') as f:
                report['BootDmesg'] = f.read()
    except IOError:
        pass
    if not report.get('CurrentDmesg', '').strip():
        dmesg = command_output(['sh', '-c', 'dmesg | comm -13 --nocheck-order /var/log/dmesg -'])
        # if an initial message was truncated by the ring buffer, skip over it
        first_newline = dmesg.find(b'\n[')
        if first_newline != -1:
            dmesg = dmesg[first_newline + 1:]
        report['CurrentDmesg'] = dmesg


def attach_dmi(report):
    dmi_dir = '/sys/class/dmi/id'
    if os.path.isdir(dmi_dir):
        for f in os.listdir(dmi_dir):
            p = '%s/%s' % (dmi_dir, f)
            st = os.stat(p)
            # ignore the root-only ones, since they have serial numbers
            if not stat.S_ISREG(st.st_mode) or (st.st_mode & 4 == 0):
                continue
            if f in ('subsystem', 'uevent'):
                continue

            try:
                with open(p) as fd:
                    value = fd.read().strip()
            except (OSError, IOError):
                continue
            if value:
                report['dmi.' + f.replace('_', '.')] = value


def attach_hardware(report):
    '''Attach a standard set of hardware-related data to the report, including:

    - kernel dmesg (boot and current)
    - /proc/interrupts
    - /proc/cpuinfo
    - /proc/cmdline
    - /proc/modules
    - lspci -vvnn
    - lsusb
    - devices from udev
    - DMI information from /sys
    - prtconf (sparc)
    - pccardctl status/ident
    '''
    attach_dmesg(report)

    attach_file(report, '/proc/interrupts', 'ProcInterrupts')
    attach_file(report, '/proc/cpuinfo', 'ProcCpuinfo')
    attach_file(report, '/proc/cmdline', 'ProcKernelCmdLine')
    attach_file(report, '/var/log/udev', 'UdevLog')

    if os.path.exists('/sys/bus/pci'):
        report['Lspci'] = command_output(['lspci', '-vvnn'])
    report['Lsusb'] = command_output(['lsusb'])
    report['ProcModules'] = command_output(['sort', '/proc/modules'])
    report['UdevDb'] = command_output(['udevadm', 'info', '--export-db'])

    # anonymize partition labels
    l = report['UdevLog'].decode('UTF-8', errors='replace')
    l = re.sub('ID_FS_LABEL=(.*)', 'ID_FS_LABEL=<hidden>', l)
    l = re.sub('ID_FS_LABEL_ENC=(.*)', 'ID_FS_LABEL_ENC=<hidden>', l)
    l = re.sub('by-label/(.*)', 'by-label/<hidden>', l)
    l = re.sub('ID_FS_LABEL=(.*)', 'ID_FS_LABEL=<hidden>', l)
    l = re.sub('ID_FS_LABEL_ENC=(.*)', 'ID_FS_LABEL_ENC=<hidden>', l)
    l = re.sub('by-label/(.*)', 'by-label/<hidden>', l)
    report['UdevLog'] = l.encode('UTF-8')

    attach_dmi(report)

    # Use the hardware information to create a machine type.
    if 'dmi.sys.vendor' in report and 'dmi.product.name' in report:
        report['MachineType'] = '%s %s' % (report['dmi.sys.vendor'],
                report['dmi.product.name'])

    if command_available('prtconf'):
        report['Prtconf'] = command_output(['prtconf'])

    if command_available('pccardctl'):
        out = command_output(['pccardctl', 'status']).strip()
        if out:
            report['PccardctlStatus'] = out
        out = command_output(['pccardctl', 'ident']).strip()
        if out:
            report['PccardctlIdent'] = out


def attach_alsa(report):
    '''Attach ALSA subsystem information to the report.

    (loosely based on http://www.alsa-project.org/alsa-info.sh)
    '''
    attach_file_if_exists(report, os.path.expanduser('~/.asoundrc'),
                          'UserAsoundrc')
    attach_file_if_exists(report, os.path.expanduser('~/.asoundrc.asoundconf'),
                          'UserAsoundrcAsoundconf')
    attach_file_if_exists(report, '/etc/asound.conf')
    attach_file_if_exists(report, '/proc/asound/version', 'AlsaVersion')
    attach_file(report, '/proc/cpuinfo', 'ProcCpuinfo')

    report['AlsaDevices'] = command_output(['ls', '-l', '/dev/snd/'])
    report['AplayDevices'] = command_output(['aplay', '-l'])
    report['ArecordDevices'] = command_output(['arecord', '-l'])

    report['PciMultimedia'] = pci_devices(PCI_MULTIMEDIA)

    cards = []
    if os.path.exists('/proc/asound/cards'):
        with open('/proc/asound/cards') as fd:
            for line in fd:
                if ']:' in line:
                    fields = line.lstrip().split()
                    cards.append(int(fields[0]))

    for card in cards:
        key = 'Card%d.Amixer.info' % card
        report[key] = command_output(['amixer', '-c', str(card), 'info'])
        key = 'Card%d.Amixer.values' % card
        report[key] = command_output(['amixer', '-c', str(card)])

        for codecpath in glob.glob('/proc/asound/card%d/codec*' % card):
            if os.path.isfile(codecpath):
                codec = os.path.basename(codecpath)
                key = 'Card%d.Codecs.%s' % (card, path_to_key(codec))
                attach_file(report, codecpath, key=key)
            elif os.path.isdir(codecpath):
                codec = os.path.basename(codecpath)
                for name in os.listdir(codecpath):
                    path = os.path.join(codecpath, name)
                    key = 'Card%d.Codecs.%s.%s' % (card, path_to_key(codec), path_to_key(name))
                    attach_file(report, path, key)

    report['AudioDevicesInUse'] = command_output(
        ['fuser', '-v'] + glob.glob('/dev/dsp*')
            + glob.glob('/dev/snd/*')
            + glob.glob('/dev/seq*'))

    if os.path.exists('/usr/bin/pacmd'):
        report['PulseList'] = command_output(['pacmd', 'list'])

    attach_dmi(report)
    attach_dmesg(report)

    # This seems redundant with the amixer info, do we need it?
    #report['AlsactlStore'] = command-output(['alsactl', '-f', '-', 'store'])


def command_available(command):
    '''Is given command on the executable search path?'''
    if 'PATH' not in os.environ:
        return False
    path = os.environ['PATH']
    for element in path.split(os.pathsep):
        if not element:
            continue
        filename = os.path.join(element, command)
        if os.path.isfile(filename) and os.access(filename, os.X_OK):
            return True
    return False


def command_output(command, input=None, stderr=subprocess.STDOUT, keep_locale=False):
    '''Try to execute given command (array) and return its stdout.

    In case of failure, a textual error gets returned. This function forces
    LC_MESSAGES to C, to avoid translated output in bug reports.
    '''
    env = os.environ.copy()
    if not keep_locale:
        env['LC_MESSAGES'] = 'C'
    try:
        sp = subprocess.Popen(command, stdout=subprocess.PIPE,
                              stderr=stderr,
                              stdin=(input and subprocess.PIPE or None),
                              close_fds=True, env=env)
    except OSError as e:
        return 'Error: ' + str(e)

    out = sp.communicate(input)[0]
    if sp.returncode == 0:
        return out.strip()
    else:
        return 'Error: command %s failed with exit code %i: %s' % (
                str(command), sp.returncode, out)


def _root_command_prefix():
    if os.getuid() == 0:
        prefix = []
    elif os.getenv('DISPLAY') and \
            subprocess.call(['which', 'kdesudo'], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE) == 0 and \
            subprocess.call(['pgrep', '-x', '-u', str(os.getuid()), 'ksmserver'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
        prefix = ['kdesudo', '--desktop', '/usr/share/applications/apport-kde-mime.desktop',
                  '--', 'env', '-u', 'LANGUAGE', 'LC_MESSAGES=C']
    elif os.getenv('DISPLAY') and \
            subprocess.call(['which', 'gksu'], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE) == 0 and \
            subprocess.call(['pgrep', '-x', '-u', str(os.getuid()), 'gnome-panel|gconfd-2'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
        prefix = ['gksu', '-D', 'Apport', '--', 'env', '-u', 'LANGUAGE', 'LC_MESSAGES=C']
    else:
        prefix = ['sudo', 'LC_MESSAGES=C', 'LANGUAGE=']

    return prefix


def root_command_output(command, input=None, stderr=subprocess.STDOUT):
    '''Try to execute given command (array) as root and return its stdout.

    This passes the command through gksu, kdesudo, or sudo, depending on the
    running desktop environment.

    In case of failure, a textual error gets returned.
    '''
    assert type(command) == type([]), 'command must be a list'
    return command_output(_root_command_prefix() + command, input, stderr,
            keep_locale=True)


def attach_root_command_outputs(report, command_map):
    '''Execute multiple commands as root and put their outputs into report.

    command_map is a keyname -> 'shell command' dictionary with the commands to
    run. They are all run through /bin/sh, so you need to take care of shell
    escaping yourself. To include stderr output of a command, end it with
    "2>&1".

    Just like root_command_output() this will use gksu, kdesudo, or sudo for
    gaining root privileges, depending on the running desktop environment.

    This is preferrable to using root_command_output() multiple times, as that
    will ask for the password every time.
    '''
    workdir = tempfile.mkdtemp()
    try:
        # create a shell script with all the commands
        script_path = os.path.join(workdir, ':script:')
        script = open(script_path, 'w')
        for keyname, command in command_map.items():
            assert hasattr(command, 'strip'), 'command must be a string (shell command)'
            # use "| cat" here, so that we can end commands with 2>&1
            # (otherwise it would have the wrong redirection order)
            script.write('%s | cat > %s\n' % (command, os.path.join(workdir, keyname)))
        script.close()

        # run script
        sp = subprocess.Popen(_root_command_prefix() + ['/bin/sh', script_path],
            close_fds=True)
        sp.wait()

        # now read back the individual outputs
        for keyname in command_map:
            f = open(os.path.join(workdir, keyname))
            buf = f.read().strip()
            if buf:
                report[keyname] = buf
            f.close()
    finally:
        shutil.rmtree(workdir)


def recent_syslog(pattern):
    '''Extract recent messages from syslog which match a regex.

    pattern should be a "re" object.
    '''
    return recent_logfile('/var/log/syslog', pattern)


def recent_logfile(logfile, pattern, maxlines=10000):
    '''Extract recent messages from a logfile which match a regex.

    pattern should be a "re" object. By default this catches at most the last
    1000 lines, but this can be modified with a different maxlines argument.
    '''
    lines = ''
    try:
        tail = subprocess.Popen(['tail', '-n', str(maxlines), logfile],
                stdout=subprocess.PIPE)
        while tail.poll() is None:
            for line in tail.stdout:
                line = line.decode('UTF-8', errors='replace')
                if pattern.search(line):
                    lines += line
        tail.wait()
    except IOError:
        return ''
    return lines


def xsession_errors(pattern=None):
    '''Extract messages from ~/.xsession-errors.

    By default this parses out glib-style warnings, errors, criticals etc. and
    X window errors.  You can specify a "re" object as pattern to customize the
    filtering.

    Please note that you should avoid attaching the whole file to reports, as
    it can, and often does, contain sensitive and private data.
    '''
    path = os.path.expanduser('~/.xsession-errors')
    if not os.path.exists(path):
        return ''

    if not pattern:
        pattern = re.compile('^(\(.*:\d+\): \w+-(WARNING|CRITICAL|ERROR))|(Error: .*No Symbols named)|([^ ]+\[\d+\]: ([A-Z]+):)|([^ ]-[A-Z]+ \*\*:)|(received an X Window System error)|(^The error was \')|(^  \(Details: serial \d+ error_code)')

    lines = ''
    with open(path) as f:
        for line in f:
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
PCI_DOCKING_STATIONS = 0x0a
PCI_PROCESSORS = 0x0b
PCI_SERIAL_BUS = 0x0c


def pci_devices(*pci_classes):
    '''Return a text dump of PCI devices attached to the system.'''

    if not pci_classes:
        return command_output(['lspci', '-vvnn'])

    result = ''
    output = command_output(['lspci', '-vvmmnn'])
    for paragraph in output.split(b'\n\n'):
        pci_class = None
        slot = None

        for line in paragraph.split(b'\n'):
            try:
                key, value = line.split(b':', 1)
            except ValueError:
                continue
            value = value.strip()
            key = key.strip()
            if key == 'Class':
                n = int(value[-5:-1], 16)
                pci_class = (n & 0xff00) >> 8
            elif key == 'Slot':
                slot = value

        if pci_class and slot and pci_class in pci_classes:
            if result:
                result += '\n\n'
            result += command_output(['lspci', '-vvnns', slot]).strip()

    return result


def usb_devices():
    '''Return a text dump of USB devices attached to the system.'''

    # TODO: would be nice to be able to filter by interface class
    return command_output(['lsusb', '-v'])


def files_in_package(package, globpat=None):
    '''Retrieve a list of files owned by package, optionally matching globpat'''

    files = packaging.get_files(package)
    if globpat:
        result = [f for f in files if glob.fnmatch.fnmatch(f, globpat)]
    else:
        result = files
    return result


def attach_gconf(report, package):
    '''Obsolete'''

    # keeping a no-op function for some time to not break hooks
    pass


def attach_gsettings_schema(report, schema):
    '''Attach user-modified gsttings keys of a schema.'''

    cur_value = report.get('GsettingsChanges', '')

    defaults = {}  # schema -> key ->  value
    env = os.environ.copy()
    env['XDG_CONFIG_HOME'] = '/nonexisting'
    gsettings = subprocess.Popen(['gsettings', 'list-recursively', schema],
            env=env, stdout=subprocess.PIPE)
    for l in gsettings.stdout:
        try:
            (schema, key, value) = l.split(None, 2)
            value = value.rstrip()
        except ValueError:
            continue  # invalid line
        defaults.setdefault(schema, {})[key] = value

    gsettings = subprocess.Popen(['gsettings', 'list-recursively', schema],
            stdout=subprocess.PIPE)
    for l in gsettings.stdout:
        try:
            (schema, key, value) = l.split(None, 2)
            value = value.rstrip()
        except ValueError:
            continue  # invalid line

        if value != defaults.get(schema, {}).get(key, ''):
            cur_value += '%s %s %s\n' % (schema, key, value)

    report['GsettingsChanges'] = cur_value


def attach_gsettings_package(report, package):
    '''Attach user-modified gsettings keys of all schemas in a package.'''

    for schema_file in files_in_package(package,
            '/usr/share/glib-2.0/schemas/*.gschema.xml'):
        schema = os.path.basename(schema_file)[:-12]
        attach_gsettings_schema(report, schema)


def attach_network(report):
    '''Attach generic network-related information to report.'''

    report['IpRoute'] = command_output(['ip', 'route'])
    report['IpAddr'] = command_output(['ip', 'addr'])
    report['PciNetwork'] = pci_devices(PCI_NETWORK)
    attach_file_if_exists(report, '/etc/network/interfaces', key='IfupdownConfig')

    for var in ('http_proxy', 'ftp_proxy', 'no_proxy'):
        if var in os.environ:
            report[var] = os.environ[var]


def attach_wifi(report):
    '''Attach wireless (WiFi) network information to report.'''

    report['WifiSyslog'] = recent_syslog(re.compile(r'(NetworkManager|modem-manager|dhclient|kernel|wpa_supplicant)(\[\d+\])?:'))
    report['IwConfig'] = re.sub('ESSID:(.*)', 'ESSID:<hidden>',
        re.sub('Encryption key:(.*)', 'Encryption key: <hidden>',
        re.sub('Access Point: (.*)', 'Access Point: <hidden>',
            command_output(['iwconfig']).decode('UTF-8', errors='ignore'))))
    report['RfKill'] = command_output(['rfkill', 'list'])
    report['CRDA'] = command_output(['iw', 'reg', 'get'])

    attach_file_if_exists(report, '/var/log/wpa_supplicant.log', key='WpaSupplicantLog')


def attach_printing(report):
    '''Attach printing information to the report.

    Based on http://wiki.ubuntu.com/PrintingBugInfoScript.
    '''
    attach_file_if_exists(report, '/etc/papersize', 'Papersize')
    attach_file_if_exists(report, '/var/log/cups/error_log', 'CupsErrorLog')
    report['Locale'] = command_output(['locale'])
    report['Lpstat'] = command_output(['lpstat', '-v'])

    ppds = glob.glob('/etc/cups/ppd/*.ppd')
    if ppds:
        nicknames = command_output(['fgrep', '-H', '*NickName'] + ppds)
        report['PpdFiles'] = re.sub('/etc/cups/ppd/(.*).ppd:\*NickName: *"(.*)"', '\g<1>: \g<2>', nicknames)

    report['PrintingPackages'] = package_versions(
        'foo2zjs', 'foomatic-db', 'foomatic-db-engine',
        'foomatic-db-gutenprint', 'foomatic-db-hpijs', 'foomatic-filters',
        'foomatic-gui', 'hpijs', 'hplip', 'm2300w', 'min12xxw', 'c2050',
        'hpoj', 'pxljr', 'pnm2ppa', 'splix', 'hp-ppd', 'hpijs-ppds',
        'linuxprinting.org-ppds', 'openprinting-ppds',
        'openprinting-ppds-extra', 'ghostscript', 'cups',
        'cups-driver-gutenprint', 'foomatic-db-gutenprint', 'ijsgutenprint',
        'cupsys-driver-gutenprint', 'gimp-gutenprint', 'gutenprint-doc',
        'gutenprint-locales', 'system-config-printer-common', 'kdeprint')


def attach_mac_events(report):
    '''Attach MAC information and events to the report.'''

    mac_regex = 'audit\(|apparmor|selinux|security'
    mac_re = re.compile(mac_regex, re.IGNORECASE)
    aa_denied_regex = 'apparmor="DENIED"'
    aa_denied_re = re.compile(aa_denied_regex, re.IGNORECASE)

    if os.path.exists('/var/log/kern.log'):
        report['KernLog'] = recent_logfile('/var/log/kern.log', mac_re)
    elif os.path.exists('/var/log/messages'):
        report['KernLog'] = recent_logfile('/var/log/messages', mac_re)

    if os.path.exists('/var/run/auditd.pid'):
        attach_root_command_outputs(report, {'AuditLog': 'egrep "' + mac_regex + '" /var/log/audit/audit.log'})

    attach_file(report, '/proc/version_signature', 'ProcVersionSignature')
    attach_file(report, '/proc/cmdline', 'ProcCmdline')

    if re.search(aa_denied_re, report.get('KernLog', '')) or re.search(aa_denied_re, report.get('AuditLog', '')):
        tags = report.get('Tags', '')
        if tags:
            tags += ' '
        report['Tags'] = tags + 'apparmor'


def attach_related_packages(report, packages):
    '''Attach version information for related packages

    In the future, this might also run their hooks.
    '''
    report['RelatedPackageVersions'] = package_versions(*packages)


def package_versions(*packages):
    '''Return a text listing of package names and versions.

    Arguments may be package names or globs, e. g. "foo*"
    '''
    versions = []
    for package_pattern in packages:
        if not package_pattern:
            continue

        matching_packages = packaging.package_name_glob(package_pattern)

        if not matching_packages:
            versions.append((package_pattern, 'N/A'))

        for package in sorted(matching_packages):
            try:
                version = packaging.get_version(package)
            except ValueError:
                version = 'N/A'
            if version is None:
                version = 'N/A'
            versions.append((package, version))

    package_width, version_width = \
        map(max, [map(len, t) for t in zip(*versions)])

    fmt = '%%-%ds %%s' % package_width
    return '\n'.join([fmt % v for v in versions])


def shared_libraries(path):
    '''Returns a list of strings containing the sonames of shared libraries
    with which the specified binary is linked.'''

    libs = set()

    for line in command_output(['ldd', path]).split('\n'):
        try:
            lib, rest = line.split('=>', 1)
        except ValueError:
            continue

        lib = lib.strip()
        libs.add(lib)

    return libs


def links_with_shared_library(path, lib):
    '''Returns True if the binary at path links with the library named lib.

    path should be a fully qualified path (e.g. report['ExecutablePath'])
    lib may be of the form 'lib<name>' or 'lib<name>.so.<version>'
    '''

    libs = shared_libraries(path)

    if lib in libs:
        return True

    for linked_lib in libs:
        if linked_lib.startswith(lib + '.so.'):
            return True

    return False


def _get_module_license(module):
    '''Return the license for a given kernel module.'''

    try:
        modinfo = subprocess.Popen(['/sbin/modinfo', module],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = modinfo.communicate()[0].decode('UTF-8')
        if modinfo.returncode != 0:
            return 'invalid'
    except OSError:
        return None
    for l in out.splitlines():
        fields = l.split(':', 1)
        if len(fields) < 2:
            continue
        if fields[0] == 'license':
            return fields[1].strip()

    return None


def nonfree_kernel_modules(module_list='/proc/modules'):
    '''Check loaded modules and return a list of those which are not free.'''

    try:
        with open(module_list) as f:
            mods = [l.split()[0] for l in f]
    except IOError:
        return []

    nonfree = []
    for m in mods:
        l = _get_module_license(m)
        if l and not ('GPL' in l or 'BSD' in l or 'MPL' in l or 'MIT' in l):
            nonfree.append(m)

    return nonfree


def __drm_con_info(con):
    info = ''
    for f in os.listdir(con):
        path = os.path.join(con, f)
        if f == 'uevent' or not os.path.isfile(path):
            continue
        val = open(path).read().strip()
        # format some well-known attributes specially
        if f == 'modes':
            val = val.replace('\n', ' ')
        if f == 'edid':
            val = base64.b64encode(val)
            f += '-base64'
        info += '%s: %s\n' % (f, val)
    return info


def attach_drm_info(report):
    '''Add information about DRM hardware.

    Collect information from /sys/class/drm/.
    '''
    drm_dir = '/sys/class/drm'
    if not os.path.isdir(drm_dir):
        return
    for f in os.listdir(drm_dir):
        con = os.path.join(drm_dir, f)
        if os.path.exists(os.path.join(con, 'enabled')):
            # DRM can set an arbitrary string for its connector paths.
            report['DRM.' + path_to_key(f)] = __drm_con_info(con)


def in_session_of_problem(report):
    '''Check if the problem happened in the currently running XDG session.

    This can be used to determine if e. g. ~/.xsession-errors is relevant and
    should be attached.

    Return None if this cannot be determined due to not being able to talk to
    ConsoleKit.
    '''
    # report time is in local TZ
    orig_ctime = locale.getlocale(locale.LC_TIME)
    try:
        locale.setlocale(locale.LC_TIME, 'C')
        report_time = time.mktime(time.strptime(report['Date']))
    except KeyError:
        return None
    finally:
        locale.setlocale(locale.LC_TIME, orig_ctime)

    try:
        bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        ck_manager = Gio.DBusProxy.new_sync(bus, Gio.DBusProxyFlags.NONE, None,
            'org.freedesktop.ConsoleKit', '/org/freedesktop/ConsoleKit/Manager',
            'org.freedesktop.ConsoleKit.Manager', None)

        cur_session = ck_manager.GetCurrentSession()

        ck_session = Gio.DBusProxy.new_sync(bus, Gio.DBusProxyFlags.NONE, None,
            'org.freedesktop.ConsoleKit', cur_session,
            'org.freedesktop.ConsoleKit.Session', None)

        session_start_time = ck_session.GetCreationTime()
    except GLib.GError as e:
        sys.stderr.write('Error connecting to ConsoleKit: %s\n' % str(e))
        return None

    m = re.match('(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+Z)$',
            session_start_time)
    if m:
        # CK gives UTC time
        session_start_time = calendar.timegm(time.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S'))
    else:
        sys.stderr.write('cannot parse time returned by CK: %s\n' % session_start_time)
        return None

    return session_start_time <= report_time
