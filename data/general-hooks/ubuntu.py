'''Attach generally useful information, not specific to any package.

Copyright (C) 2009 Canonical Ltd.
Author: Matt Zimmerman <mdz@canonical.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import apport.packaging
import re
from urlparse import urljoin
from urllib2 import urlopen
from apport.hookutils import *

def add_info(report):
    add_tags = []

    # crash reports from live system installer often expose target mount
    for f in ('ExecutablePath', 'InterpreterPath'):
        if f in report and report[f].startswith('/target/'):
            report[f] = report[f][7:]

    # if we are running from a live system, add the build timestamp
    attach_file_if_exists(report, '/cdrom/.disk/info', 'LiveMediaBuild')

    # This includes the Ubuntu packaged kernel version
    attach_file_if_exists(report, '/proc/version_signature', 'ProcVersionSignature')

    # https://wiki.ubuntu.com/FoundationsTeam/Specs/OemTrackingId
    attach_file_if_exists(report, '/var/lib/ubuntu_dist_channel', 
        'DistributionChannelDescriptor')

    # There are enough of these now that it is probably worth refactoring...
    # -mdz
    if report['ProblemType'] == 'Package':
        if report['Package'] not in ['grub', 'grub2']:
            # linux-image postinst emits this when update-grub fails
            # https://wiki.ubuntu.com/KernelTeam/DebuggingUpdateErrors
            if 'DpkgTerminalLog' in report and re.search(r'^User postinst hook script \[.*update-grub\] exited with value', report['DpkgTerminalLog'], re.MULTILINE):
                # File these reports on the grub package instead
                grub_package = apport.packaging.get_file_package('/usr/sbin/update-grub')
                if grub_package is None or grub_package == 'grub':
                    report['SourcePackage'] = 'grub'
                else:
                    report['SourcePackage'] = 'grub2'

        if report['Package'] != 'initramfs-tools':
            # update-initramfs emits this when it fails, usually invoked from the linux-image postinst
            # https://wiki.ubuntu.com/KernelTeam/DebuggingUpdateErrors
            if 'DpkgTerminalLog' in report and re.search(r'^update-initramfs: failed for ', report['DpkgTerminalLog'], re.MULTILINE):
                # File these reports on the initramfs-tools package instead
                report['SourcePackage'] = 'initramfs-tools'

        if report['Package'].startswith('linux-image-') and 'DpkgTerminalLog' in report:
            # /etc/kernel/*.d failures from kernel package postinst
            m = re.search(r'^run-parts: (/etc/kernel/\S+\.d/\S+) exited with return code \d+', report['DpkgTerminalLog'], re.MULTILINE)
            if m:
                path = m.group(1)
                package = apport.packaging.get_file_package(path)
                if package:
                    report['SourcePackage'] = package
                    report['ErrorMessage'] = m.group(0)
                else:
                    report['UnreportableReason'] = 'This failure was caused by a program which did not originate from Ubuntu'

    if 'Package' in report:
        package = report['Package'].split()[0]
        if package and 'attach_conffiles' in dir():
            attach_conffiles(report, package)

        # do not file bugs against "upgrade-system" if it is not installed (LP#404727)
        if package == 'upgrade-system' and 'not installed' in report['Package']:
            report['UnreportableReason'] = 'You do not have the upgrade-system package installed. Please report package upgrade failures against the package that failed to install, or against upgrade-manager.'

    # EC2 and Ubuntu Enterprise Cloud instances
    if apport.packaging.get_version('ec2-init') is not None:
        metadata_url = 'http://169.254.169.254/latest/meta-data/'
        ami_id_url = urljoin(metadata_url, 'ami-id')

        try:
            ami = urlopen(ami_id_url).read()
        except:
            ami = None

        if ami is None:
            cloud = None
        elif ami.startswith('ami'):
            cloud = 'ec2'
            add_tags.append('ec2-images')

            # It would be great to translate these into meaningful Ubuntu versions -mdz
            report['Ec2AMI'] = ami
            report['Ec2AMIManifest'] = urlopen(urljoin(metadata_url, 'ami-manifest-path')).read()
            report['Ec2Kernel'] = urlopen(urljoin(metadata_url, 'kernel-id')).read()
            report['Ec2Ramdisk'] = urlopen(urljoin(metadata_url, 'ramdisk-id')).read()
            report['Ec2InstanceType'] = urlopen(urljoin(metadata_url, 'instance-type')).read()
            report['Ec2AvailabilityZone.'] = urlopen(urljoin(metadata_url, 'placement/availability-zone')).read()
        else:
            cloud = 'uec'
            add_tags.append('uec-images')

    if add_tags:
        if 'Tags' in report:
            report['Tags'] += ' ' + ' '.join(add_tags)
        else:
            report['Tags'] = ' '.join(add_tags)
