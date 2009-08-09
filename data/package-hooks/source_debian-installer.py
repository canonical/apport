'''Apport package hook for the Debian installer.

Copyright (C) 2009 Canonical Ltd.
Author: Colin Watson <cjwatson@ubuntu.com>'''

from apport.hookutils import attach_hardware, command_available, command_output

def add_info(report):
    attach_hardware(report)

    report['DiskUsage'] = command_output(['df'])
    report['MemoryUsage'] = command_output(['free'])

    if command_available('dmraid'):
        report['DmraidSets'] = command_output(['dmraid', '-s'])
        report['DmraidDevices'] = command_output(['dmraid', '-r'])
        if command_available('dmsetup'):
            report['DeviceMapperTables'] = command_output(['dmsetup', 'table'])

    try:
        installer_version = open('/var/log/installer/version')
        for line in installer_version:
            if line.startswith('ubiquity '):
                report['UnreportableReason'] = 'System installed using ubiquity, not debian-installer'
                break
        installer_version.close()
    except IOError:
        pass

if __name__ == '__main__':
    report = {}
    add_info(report)
    for key in report:
        print '%s: %s' % (key, report[key].split('\n', 1)[0])
