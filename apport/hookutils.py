'''Convenience functions for use in package hooks.

Copyright (C) 2008-2009 Canonical Ltd.
Author: Matt Zimmerman <mdz@canonical.com>
Contributor: Brian Murray <brian@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import subprocess
import hashlib
import os
import datetime
import glob
import re

import xml.dom, xml.dom.minidom

from packaging_impl import impl as packaging

def path_to_key(path):
    '''Generate a valid report key name from a file path.
        
    This will meet apport's restrictions on the characters used in keys.
    '''
    return path.replace('/', '.')

def attach_file_if_exists(report, path, key=None):
    '''Attach file contents if file exists.'''

    if not key:
        key = path_to_key(path)

    if os.path.exists(path):
        attach_file(report, path, key)

def read_file(path):
    '''Return the contents of the specified path. 
        
    Upon error, this will deliver a a text representation of the error,
    instead of failing.
    '''
    try:
        return open(path).read().strip()
    except Exception, e:
        return 'Error: ' + str(e)

def attach_file(report, path, key=None):
    '''Attach a file to the report.

    If key is not specified, the key name will be derived from the file
    name with path_to_key().
    '''
    if not key:
        key = path_to_key(path)

    report[key] = read_file(path)

def attach_conffiles(report, package, conffiles=None):
    '''Attach information about any modified or deleted conffiles'''

    output = command_output(['dpkg-query','-W','--showformat=${Conffiles}',
                             package])
    for line in output.split('\n'):
        path, default_md5sum = line.strip().split()

        if conffiles and path not in conffiles: continue

        key = 'modified.conffile.' + path_to_key(path)

        if os.path.exists(path):
            contents = open(path).read()
            m = hashlib.md5()
            m.update(contents)
            calculated_md5sum = m.hexdigest()

            if calculated_md5sum != default_md5sum:
                report[key] = contents
                statinfo = os.stat(path)
                mtime = datetime.datetime.fromtimestamp(statinfo.st_mtime)
                mtime_key = 'mtime.conffile.' + path_to_key(path)
                report[mtime_key] = mtime.isoformat()
        else:
            report[key] = '[deleted]'

def attach_dmesg(report):
    '''Attach information from the kernel ring buffer (dmesg).'''

    report['BootDmesg'] = open('/var/log/dmesg').read()
    report['CurrentDmesg'] = command_output(['sh', '-c', 'dmesg | comm -13 /var/log/dmesg -'])

def attach_machinetype(report):
    '''Calculate and attach a specific machine type if possible.'''

    if 'HalComputerInfo' in report:
        system = ''
        vendor = re.compile(r"system.hardware.vendor\s*=\s*'(.*)'\s*\(string\)")
        match = vendor.search(report['HalComputerInfo'])
        if match:
            system += match.group(1).rstrip() + ' '
        product = re.compile(r"system.hardware.product\s*=\s*'(.*)'\s*\(string\)")
        match = product.search(report['HalComputerInfo'])
        if match:
            system += match.group(1).rstrip() + ' '

        if system != '':
            report['MachineType'] = system.rstrip()

def attach_hardware(report):
    attach_dmesg(report)

    attach_file(report, '/proc/interrupts', 'ProcInterrupts')
    attach_file(report, '/proc/version_signature', 'ProcVersionSignature')
    attach_file(report, '/proc/cpuinfo', 'ProcCpuinfo')
    attach_file(report, '/proc/cmdline', 'ProcCmdLine')
    attach_file(report, '/proc/modules', 'ProcModules')

    report['Lspci'] = command_output(['lspci','-vvnn'])
    report['Lsusb'] = command_output(['lsusb'])
    report['HalComputerInfo'] = hal_dump_udi('/org/freedesktop/Hal/devices/computer')

    if 'Uname' in report:
        # already covered in ProcVersionSignature
        del report['Uname']

    # Use the hardware information to create a machine type.
    attach_machinetype(report)

def attach_alsa(report):
    '''Attach ALSA subsystem information to the report.

    (loosely based on http://www.alsa-project.org/alsa-info.sh)
        '''
    attach_file_if_exists(report, os.path.expanduser('~/.asoundrc'),
                          'UserAsoundrc')
    attach_file_if_exists(report, os.path.expanduser('~/.asoundrc.asoundconf'),
                          'UserAsoundrcAsoundconf')
    attach_file_if_exists(report, '/etc/asound.conf')

    report['AlsaDevices'] = command_output(['ls','-l','/dev/snd/'])
    report['AplayDevices'] = command_output(['aplay','-l'])
    report['ArecordDevices'] = command_output(['arecord','-l'])

    report['PciMultimedia'] = pci_devices(PCI_MULTIMEDIA)

    cards = []
    for line in open('/proc/asound/cards'):
        if ']:' in line:
            fields = line.lstrip().split()
            cards.append(fields[0])

    for card in cards:
        key = 'Amixer.%s.info' % card
        report[key] = command_output(['amixer', '-c', card, 'info'])
        key = 'Amixer.%s.values' % card
        report[key] = command_output(['amixer', '-c', card])

    # This seems redundant with the amixer info, do we need it?
    #report['AlsactlStore'] = command-output(['alsactl', '-f', '-', 'store'])

def command_output(command, input = None, stderr = subprocess.STDOUT):
    '''Try to execute given command (array) and return its stdout. 
    
    In case of failure, a textual error gets returned.
    '''
    try:
       sp = subprocess.Popen(command, stdout=subprocess.PIPE,
                             stderr=stderr, close_fds=True)
    except OSError, e:
       return 'Error: ' + str(e)

    out = sp.communicate(input)[0]
    if sp.returncode == 0:
       return out.strip()
    else:
       return 'Error: command %s failed with exit code %i: %s' % (
           str(command), sp.returncode, out)

def recent_syslog(pattern):
    '''Extract recent messages from syslog which match a regex.
        
    pattern should be a "re" object.
    '''
    lines = ''
    for line in open('/var/log/syslog'):
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

    slots = []
    output = command_output(['lspci','-vvmmnn'])
    for paragraph in output.split('\n\n'):
        pci_class = None
        pci_subclass = None
        slot = None

        for line in paragraph.split('\n'):
            key, value = line.split(':',1)
            value = value.strip()
            key = key.strip()
            if key == 'Class':
                n = int(value[-5:-1],16)
                pci_class = (n & 0xff00) >> 8
                pci_subclass = (n & 0x00ff)
            elif key == 'Slot':
                slot = value

        if pci_class and slot and pci_class in pci_classes:
            slots.append(slot)

    cmd = ['lspci','-vvnn']
    for slot in slots:
        cmd.extend(['-s',slot])

    return command_output(cmd)

def usb_devices():
    '''Return a text dump of USB devices attached to the system.'''

    # TODO: would be nice to be able to filter by interface class
    return command_output(['lsusb','-v'])

def hal_find_by_capability(capability):
    '''Retrieve a list of UDIs for hal objects having the specified capability.'''

    output = command_output(['hal-find-by-capability',
                             '--capability',capability])
    return output.split('\n')

def hal_dump_udi(udi):
    '''Dump the properties of a HAL object, specified by its UDI.'''

    out = command_output(['lshal','-u',udi])

    # filter out serial numbers
    result = ''
    for l in out.splitlines():
        if '.serial =' in l:
            continue
        result += l + '\n'

    return result

def files_in_package(package, globpat=None):
    '''Retrieve a list of files owned by package, optionally matching globpat'''

    files = packaging.get_files(package)
    if globpat:
        result = [f for f in files if glob.fnmatch.fnmatch(f, globpat)]
    else:
        result = files
    return result

def attach_gconf(report, package):
    '''Attach information about gconf keys set to non-default values.'''

    import gconf
    import glib

    client = gconf.client_get_default()

    non_defaults = {}
    for schema_file in files_in_package(package,
                                    '/usr/share/gconf/schemas/*.schemas'):

        for key, default_value in _parse_gconf_schema(schema_file).items():
            try:
                value = client.get(key).to_string()
                if value != default_value:
                    non_defaults[key] = value
            except glib.GError:
                # Fall back to gconftool-2 and string comparison
                value = command_output(['gconftool-2','-g',key])

                if value != default_value:
                    non_defaults[key] = value

    if non_defaults:
        s = ''
        keys = non_defaults.keys()
        keys.sort()
        for key in keys:
            value = non_defaults[key]
            s += '%s=%s\n' % (key, value)

        report['GConfNonDefault'] = s

def attach_network(report):
    '''Attach network-related information to report.'''

    report['IpRoute'] = command_output(['ip','route'])
    report['IpAddr'] = command_output(['ip','addr'])
    report['PciNetwork'] = pci_devices(PCI_NETWORK)

    for var in ('http_proxy', 'ftp_proxy', 'no_proxy'):
        if var in os.environ:
            report[var] = os.environ[var]

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

def attach_related_packages(report, packages):
    '''Attach version information for related packages

       In the future, this might also run their hooks.'''
    report['RelatedPackageVersions'] = package_versions(*packages)

def package_versions(*packages):
    versions = ''
    for package in packages:
        try:
            version = packaging.get_version(package)
        except ValueError:
            version = 'N/A'
        if version is None:
            version = 'N/A'
        versions += '%s %s\n' % (package, version)

    return versions

def _parse_gconf_schema(schema_file):
    ret = {}

    dom = xml.dom.minidom.parse(schema_file)
    for gconfschemafile in dom.getElementsByTagName('gconfschemafile'):
        for schemalist in gconfschemafile.getElementsByTagName('schemalist'):
            for schema in schemalist.getElementsByTagName('schema'):
                key = schema.getElementsByTagName('applyto')[0].childNodes[0].data
                type = schema.getElementsByTagName('type')[0].childNodes[0].data
                default = schema.getElementsByTagName('default')[0].childNodes[0].data
                if type == 'bool':
                    if default:
                        ret[key] = 'true'
                    else:
                        ret[key] = 'false'
                else:
                    ret[key] = default

    return ret
