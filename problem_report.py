'''Store, load, and handle problem reports.

Copyright (C) 2006 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import bz2, zlib, base64, time, UserDict, sys

class ProblemReport(UserDict.IterableUserDict):
    def __init__(self, type = 'Crash', date = None):
	'''Initialize a fresh problem report.
	
	type can be 'Crash', 'Packaging', or 'Kernel'. date is the desired
	date/time string; if None (default), the current local time is used. '''

	if date == None:
	    date = time.asctime()
	self.data = {'ProblemType': type, 'Date': date}

    def	load(self, file, binary=True):
	'''Initialize problem report from a file-like object, using Debian
	control file format.
	
	if binary is False, binary data is not loaded; the dictionary key is
	created, but its value will be an empty string.'''

	self.data.clear()
	key = None
	value = None
	b64_block = False
	bd = None
	for line in file:
	    # continuation line
	    if line.startswith(' '):
		if b64_block and not binary:
		    continue
		assert (key != None and value != None)
		if b64_block:
		    l = base64.b64decode(line)
		    if bd:
			value += bd.decompress(l)
		    else:
			# lazy initialization of bd; fall back to bzip2 if gzip
			# fails
			bd = zlib.decompressobj()
			try:
			    value += bd.decompress(l)
			except zlib.error:
			    bd = bz2.BZ2Decompressor()
			    value += bd.decompress(l)
		else:
		    if len(value) > 0:
			value += '\n'
		    value += line[1:-1]
	    else:
		if b64_block:
		    try:
			value += bd.flush()
		    except AttributeError:
			pass # bz2 decompressor has no flush()
		    b64_block = False
		    bd = None
		if key:
		    assert value != None
		    self.data[key] = value
		(key, value) = line.split(':', 1)
		value = value.strip()
		if value == 'base64':
		    value = ''
		    b64_block = True

	if key != None:
	    self.data[key] = value

    def has_removed_fields(self):
	'''Check whether the report has any keys which were not loaded in load()
	due to being compressed binary.'''

	return ('' in self.itervalues())

    def _is_binary(self, string):
	'''Check if the given strings contains binary data.'''

	for c in string:
	    if c < ' ' and not c.isspace():
		return True
	return False

    def write(self, file):
	'''Write information into the given file-like object, using Debian
	control file format.

	If a value is a string, it is written directly. Otherwise it must be a
	tuple containing a string, and an optional boolean value (in that
	order); the first argument is interpreted as a file name, which will be
	read and its content will become the value of this key.

	The second argument specifies whether the contents will be
	bzip2'ed and base64-encoded (this defaults to True).
	'''

	# sort keys into ASCII non-ASCII/binary attachment ones, so that
	# the base64 ones appear last in the report
	asckeys = []
	binkeys = []
	for k in self.data.keys():
	    v = self.data[k]
	    if hasattr(v, 'find'):
		if self._is_binary(v):
		    binkeys.append(k)
		else:
		    asckeys.append(k)
	    else:
		if len(v) >= 2 and not v[1]: # force uncompressed
		    asckeys.append(k)
		else:
		    binkeys.append(k)

	asckeys.remove('ProblemType')
	asckeys.sort()
	asckeys.insert(0, 'ProblemType')
	binkeys.sort()

	# write the ASCII keys first
	for k in asckeys:
	    v = self.data[k]

	    # if it's a tuple, we have a file reference; read the contents
	    if not hasattr(v, 'find'):
		v = open(v[0]).read()

	    if v.find('\n') >= 0:
		# multiline value
		assert v.find('\n\n') < 0
		print >> file, k + ':'
		print >> file, '', v.replace('\n', '\n ')
	    else:
		# single line value
		print >> file, k + ':', v

	# now write the binary keys with bzip2 compression and base64 encoding
	for k in binkeys:
	    v = self.data[k]

	    file.write (k + ': base64\n ')
	    bc = zlib.compressobj()
	    # direct value
	    if hasattr(v, 'find'):
		outblock = bc.compress(v)
		if outblock:
		    file.write(base64.b64encode(outblock))
		    file.write('\n ')
	    # file reference
	    else:
		f = open(v[0])
		while True:
		    block = f.read(1048576)
		    if block:
			outblock = bc.compress(block)
			if outblock:
			    file.write(base64.b64encode(outblock))
			    file.write('\n ')
		    else:
			break

	    # flush compressor and write the rest
	    file.write(base64.b64encode(bc.flush()))
	    file.write('\n')

    def __setitem__(self, k, v):
	assert hasattr(k, 'isalnum')
	assert k.isalnum()
	# value must be a string or a file reference (tuple (string [, bool]))
	assert (hasattr(v, 'isalnum') or 
	    (hasattr(v, '__getitem__') and (
	    len(v) == 1 or (len(v) == 2 and v[1] in (True, False)))
	    and hasattr(v[0], 'isalnum')))

	return self.data.__setitem__(k, v)


#
# Unit test
#

import unittest, StringIO, tempfile, os

class _ProblemReportTest(unittest.TestCase):
    def test_basic_operations(self):
	'''Test basic creation and operation.'''

	pr = ProblemReport()
	pr['foo'] = 'bar'
	pr['bar'] = ' foo   bar\nbaz\n   blip  '
	self.assertEqual(pr['foo'], 'bar')
	self.assertEqual(pr['bar'], ' foo   bar\nbaz\n   blip  ')
	self.assertEqual(pr['ProblemType'], 'Crash')
	self.assert_(time.strptime(pr['Date']))

    def test_ctor_arguments(self):
	'''Test non-default constructor arguments.'''

	pr = ProblemReport('Kernel')
	self.assertEqual(pr['ProblemType'], 'Kernel')
	pr = ProblemReport(date = '19801224 12:34')
	self.assertEqual(pr['Date'], '19801224 12:34')

    def test_sanity_checks(self):
	'''Test various error conditions.'''

	pr = ProblemReport()
	self.assertRaises(AssertionError, pr.__setitem__, 'a b', '1')
	self.assertRaises(AssertionError, pr.__setitem__, 'a', 1)
	self.assertRaises(AssertionError, pr.__setitem__, 'a', 1)
	self.assertRaises(AssertionError, pr.__setitem__, 'a', (1,))
	self.assertRaises(AssertionError, pr.__setitem__, 'a', ('/tmp/nonexistant', ''))
	self.assertRaises(KeyError, pr.__getitem__, 'Nonexistant')

    def test_write(self):
	'''Test write() and proper formatting.'''

	pr = ProblemReport(date = 'now!')
	pr['Simple'] = 'bar'
	pr['WhiteSpace'] = ' foo   bar\nbaz\n  blip  '
	io = StringIO.StringIO()
	pr.write(io)
	self.assertEqual(io.getvalue(), 
'''ProblemType: Crash
Date: now!
Simple: bar
WhiteSpace:
  foo   bar
 baz
   blip  
''')

    def test_load(self):
	'''Test load() with various formatting.'''
	pr = ProblemReport()
	pr.load(StringIO.StringIO(
'''ProblemType: Crash
Date: now!
Simple: bar
WhiteSpace:
  foo   bar
 baz
   blip  
'''))
	self.assertEqual(pr['ProblemType'], 'Crash')
	self.assertEqual(pr['Date'], 'now!')
	self.assertEqual(pr['Simple'], 'bar')
	self.assertEqual(pr['WhiteSpace'], ' foo   bar\nbaz\n  blip  ')

	# test last field a bit more
	pr.load(StringIO.StringIO(
'''ProblemType: Crash
Date: now!
Simple: bar
WhiteSpace:
  foo   bar
 baz
   blip  
 
'''))
	self.assertEqual(pr['ProblemType'], 'Crash')
	self.assertEqual(pr['Date'], 'now!')
	self.assertEqual(pr['Simple'], 'bar')
	self.assertEqual(pr['WhiteSpace'], ' foo   bar\nbaz\n  blip  \n')
	pr = ProblemReport()
	pr.load(StringIO.StringIO(
'''ProblemType: Crash
WhiteSpace:
  foo   bar
 baz
   blip  
Last: foo
'''))
	self.assertEqual(pr['WhiteSpace'], ' foo   bar\nbaz\n  blip  ')
	self.assertEqual(pr['Last'], 'foo')

	pr.load(StringIO.StringIO(
'''ProblemType: Crash
WhiteSpace:
  foo   bar
 baz
   blip  
Last: foo
 
'''))
	self.assertEqual(pr['WhiteSpace'], ' foo   bar\nbaz\n  blip  ')
	self.assertEqual(pr['Last'], 'foo\n')

	# test that load() cleans up properly
	pr.load(StringIO.StringIO('ProblemType: Crash'))
	self.assertEqual(pr.keys(), ['ProblemType'])

    def test_write_file(self):
	'''Test writing a report with binary file data.'''

	temp = tempfile.NamedTemporaryFile()
	temp.write('AB' * 10 + '\0' * 10 + 'Z')
	temp.flush()

	pr = ProblemReport(date = 'now!')
	pr['File'] = (temp.name,)
	pr['Afile'] = (temp.name,)
	io = StringIO.StringIO()
	pr.write(io)
	temp.close()

	self.assertEqual(io.getvalue(), 
'''ProblemType: Crash
Date: now!
Afile: base64
 eJw=
 c3RyxIAMcBAFAG55BXk=
File: base64
 eJw=
 c3RyxIAMcBAFAG55BXk=
''')

	# force compression/encoding bool
	temp = tempfile.NamedTemporaryFile()
	temp.write('foo\0bar')
	temp.flush()
	pr = ProblemReport(date = 'now!')
	pr['File'] = (temp.name, False)
	io = StringIO.StringIO()
	pr.write(io)

	self.assertEqual(io.getvalue(), 
'''ProblemType: Crash
Date: now!
File: foo\0bar
''')

	pr['File'] = (temp.name, True)
	io = StringIO.StringIO()
	pr.write(io)

	self.assertEqual(io.getvalue(), 
'''ProblemType: Crash
Date: now!
File: base64
 eJw=
 S8vPZ0hKLAIACfACeg==
''')
	temp.close()

    def test_read_file(self):
	'''Test reading a report with binary data.'''

	bin_report = '''ProblemType: Crash
Date: now!
File: base64
 eJw=
 c3RyxIAMcBAFAG55BXk=
Foo: Bar
'''

	# test with reading everything
	pr = ProblemReport()
	pr.load(StringIO.StringIO(bin_report))
	self.assertEqual(pr['File'], 'AB' * 10 + '\0' * 10 + 'Z')
	self.assertEqual(pr.has_removed_fields(), False)

	# test with skipping binary data
	pr.load(StringIO.StringIO(bin_report), binary=False)
	self.assertEqual(pr['File'], '')
	self.assertEqual(pr.has_removed_fields(), True)

    def test_read_file_bzip2(self):
	'''Test reading a report with binary data (legacy bzip2 compression).'''

	bin_report = '''ProblemType: Crash
Date: now!
File: base64
 QlpoOTFBWSZTWc5ays4AAAdGAEEAMAAAECAAMM0AkR6fQsBSDhdyRThQkM5ays4=
Foo: Bar
'''

	# test with reading everything
	pr = ProblemReport()
	pr.load(StringIO.StringIO(bin_report))
	self.assertEqual(pr['File'], 'AB' * 10 + '\0' * 10 + 'Z')
	self.assertEqual(pr.has_removed_fields(), False)

	# test with skipping binary data
	pr.load(StringIO.StringIO(bin_report), binary=False)
	self.assertEqual(pr['File'], '')
	self.assertEqual(pr.has_removed_fields(), True)

    def test_big_file(self):
	'''Test writing and re-decoding a big random file.'''

	# create 1 MB random file
	temp = tempfile.NamedTemporaryFile()
	data = os.urandom(1048576)
	temp.write(data)
	temp.flush()

	# write it into problem report
	pr = ProblemReport()
	pr['File'] = (temp.name,)
	pr['Before'] = 'xtestx'
	pr['ZAfter'] = 'ytesty'
	io = StringIO.StringIO()
	pr.write(io)
	temp.close()

	# read it again
	io.seek(0)
	pr = ProblemReport()
	pr.load(io)

	self.assert_(pr['File'] == data)
	self.assertEqual(pr['Before'], 'xtestx')
	self.assertEqual(pr['ZAfter'], 'ytesty')

	# write it again
	io2 = StringIO.StringIO()
	pr.write(io2)
	self.assert_(io.getvalue() == io2.getvalue())

    def test_iter(self):
	'''Test ProblemReport iteration.'''

	pr = ProblemReport()
	pr['foo'] = 'bar'

	keys = []
	for k in pr:
	    keys.append(k)
	keys.sort()
	self.assertEqual(' '.join(keys), 'Date ProblemType foo')

	self.assertEqual(len([k for k in pr if k != 'foo']), 2)

    def test_modify(self):
	'''Test reading, modifying fields, and writing back.'''

	report = '''ProblemType: Crash
Date: now!
Long:
 xxx
 .
 yyy
Short: Bar
File: base64
 eJw=
 c3RyxIAMcBAFAG55BXk=
'''

	pr = ProblemReport()
	pr.load(StringIO.StringIO(report))

	self.assertEqual(pr['Long'], 'xxx\n.\nyyy')

	# write back unmodified
	io = StringIO.StringIO()
	pr.write(io)
	self.assertEqual(io.getvalue(), report)

	pr['Short'] = 'aaa\nbbb'
	pr['Long'] = '123'
	io = StringIO.StringIO()
	pr.write(io)
	self.assertEqual(io.getvalue(), 
'''ProblemType: Crash
Date: now!
Long: 123
Short:
 aaa
 bbb
File: base64
 eJw=
 c3RyxIAMcBAFAG55BXk=
''')

if __name__ == '__main__':
    unittest.main()
