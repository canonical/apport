'''Convenience functions for use in package hooks.

Copyright (C) 2008 Canonical Ltd.
Author: Matt Zimmerman <mdz@canonical.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import subprocess
import md5
import os
import datetime

def path_to_key(path):
	return path.replace('/', '.')

def attach_file_if_exists(report, path, key=None):
	if not key:
		key = path_to_key(path)

	if os.path.exists(path):
		attach_file(report, path, key)

def attach_file(report, path, key=None):
	if not key:
		key = path_to_key(path)

	report[key] = open(path).read()

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
			m = md5.new()
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

def command_output(command, input = None, stderr = subprocess.STDOUT):
    '''Try to execute given command (array) and return its stdout, or return
    a textual error if it failed.'''

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
	'''Extract recent messages from syslog which match pattern
    (eg. re object)'''

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
	# TODO: would be nice to be able to filter by interface class
	return command_output(['lsusb','-v'])

def hal_find_by_capability(capability):
    output = command_output(['hal-find-by-capability',
                             '--capability',capability])
    return output.split('\n')

def hal_dump_udi(udi):
	return command_output(['lshal','-u',udi])
