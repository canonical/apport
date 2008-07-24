'''Apport package hook for the Linux kernel.

(c) 2008 Canonical Ltd.
Contributors:
Matt Zimmerman <mdz@canonical.com>
Martin Pitt <martin.pitt@canonical.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import os
import subprocess

attach_files = { 'BootDmesg' : '/var/log/dmesg',
                 'ProcInterrupts' : '/proc/interrupts',
                 'ProcVersion' : '/proc/version',
                 'ProcVersionSignature' : '/proc/version_signature',
                 'ProcCpuInfo' : '/proc/cpuinfo',
                 'ProcCmdLine' : '/proc/cmdline',
                 'ProcModules' : '/proc/modules' }
                 
attach_commands = { 'Lspci' : ['lspci', '-vvnn'],
                    'LsUsb' : ['lsusb'],
                    'HalComputerInfo' : ['lshal', '-u', '/org/freedesktop/Hal/devices/computer'],
                    'CurrentDmesg' : ['sh', '-c', 'dmesg | comm -13 /var/log/dmesg -']
                    }

def _command_output(command, input = None, stderr = subprocess.STDOUT):
    '''Try to execute given command (array) and return its stdout, or return
    a textual error if it failed.'''

    try:
       sp = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr,
close_fds=True)
    except OSError, e:
       return 'Error: ' + str(e)

    out = sp.communicate(input)[0]
    if sp.returncode == 0:
       return out.strip()
    else:
       return 'Error: command %s failed with exit code %i: %s' % (
           str(command), sp.returncode, out)

def _read_file(file):
    try:
        return open(file).read().strip()
    except Exception, e:
        return 'Error: ' + str(e)

def add_info(report):
    for name, path in attach_files.items():
        if os.path.exists(path):
            report[name] = _read_file(path)

    for name, command in attach_commands.items():
        output = _command_output(command)
        report[name] = output

    version_signature = report.get('ProcVersionSignature','')
    if version_signature.startswith('Ubuntu '):
        package_version = version_signature.split(' ', 1)[1]
        report['RunningKernelVersion'] = package_version
    else:
        report['UnreportableReason'] = _('The running kernel is not an Ubuntu kernel')

if __name__ == '__main__':
    report = {}
    add_info(report)
    for key in report:
        print '%s: %s' % (key, report[key].split('\n', 1)[0])
