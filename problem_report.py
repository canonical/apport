# vim: set fileencoding=UTF-8 :

'''Store, load, and handle problem reports.

Copyright (C) 2006 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import bz2, zlib, base64, time, UserDict, sys, gzip
from cStringIO import StringIO
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText

class ProblemReport(UserDict.IterableUserDict):
    def __init__(self, type = 'Crash', date = None):
        '''Initialize a fresh problem report.
        
        type can be 'Crash', 'Packaging', or 'Kernel'. date is the desired
        date/time string; if None (default), the current local time is used. '''

        if date == None:
            date = time.asctime()
        self.data = {'ProblemType': type, 'Date': date}

    def load(self, file, binary=True):
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
        tuple containing the source file and an optional boolean value (in that
        order); the first argument can be a file name or a file-like object,
        which will be read and its content will become the value of this key.
        The second argument specifies whether the contents will be
        zlib compressed and base64-encoded (this defaults to True).
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

        asckeys.sort()
        if 'ProblemType' in asckeys:
            asckeys.remove('ProblemType')
            asckeys.insert(0, 'ProblemType')
        binkeys.sort()

        # write the ASCII keys first
        for k in asckeys:
            v = self.data[k]

            # if it's a tuple, we have a file reference; read the contents
            if not hasattr(v, 'find'):
                if hasattr(v[0], 'read'):
                    v = v[0].read() # file-like object
                else:
                    v = open(v[0]).read() # file name

            if '\n' in v:
                # multiline value
                print >> file, k + ':'
                print >> file, '', v.replace('\n', '\n ')
            else:
                # single line value
                print >> file, k + ':', v

        # now write the binary keys with zlib compression and base64 encoding
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
                if hasattr(v[0], 'read'):
                    f = v[0] # file-like object
                else:
                    f = open(v[0]) # file name
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

    def add_to_existing(self, reportfile, keep_times=False):
        '''Add the fields of this report to an already existing report
        file.
        
        The file will be temporarily chmod'ed to 000 to prevent frontends
        from picking up a hal-updated report file. If keep_times
        is True, then the file's atime and mtime restored after updating.'''

        st = os.stat(reportfile)
        try:
            f = open(reportfile, 'a')
            os.chmod(reportfile, 0)
            self.write(f)
            f.close()
        finally:
            if keep_times:
                os.utime(reportfile, (st.st_atime, st.st_mtime))
            os.chmod(reportfile, st.st_mode)

    def write_mime(self, file, attach_treshold = 5):
        '''Write information into the given file-like object, using
        MIME/Multipart RFC 2822 format (i. e. an email with attachments).

        If a value is a string, it is written directly. Otherwise it must be a
        tuple containing the source file and an optional boolean value (in that
        order); the first argument can be a file name or a file-like object,
        which will be read and its content will become the value of this key.
        The file will be gzip compressed.

        attach_treshold specifies the maximum number of lines for a value to be
        included into the first inline text part. All bigger values (as well as
        all non-ASCII ones) will become an attachment.
        '''

        keys = self.data.keys()
        keys.sort()

        text = ''
        attachments = []

        if 'ProblemType' in keys:
            keys.remove('ProblemType')
            keys.insert(0, 'ProblemType')

        for k in keys:
            v = self.data[k]
            attach_value = None

            # if it's a tuple, we have a file reference; read the contents
            # and gzip it
            if not hasattr(v, 'find'):
                attach_value = ''
                if hasattr(v[0], 'read'):
                    f = v[0] # file-like object
                else:
                    f = open(v[0]) # file name
                attach_value = StringIO()
                gf = gzip.GzipFile(k, mode='wb', fileobj=attach_value)
                while True:
                    block = f.read(1048576)
                    if block:
                        gf.write(block)
                    else:
                        gf.close()
                        break

            # binary value
            elif self._is_binary(v):
                attach_value = StringIO()
                gf = gzip.GzipFile(k, mode='wb', fileobj=attach_value)
                gf.write(v)
                gf.close()

            # if we have an attachment value, create an attachment
            if attach_value:
                att = MIMEBase('application', 'x-gzip')
                att.add_header('Content-Disposition', 'attachment', filename=k+'.gz')
                att.set_payload(attach_value.getvalue())
                attachments.append(att)
            else:
                # plain text value
                lines = len(v.splitlines())
                if lines == 1:
                    text += '%s: %s\n' % (k, v)
                elif lines <= attach_treshold:
                    text += '%s:\n ' % k
                    if not v.endswith('\n'):
                        v += '\n'
                    text += v.strip().replace('\n', '\n ') + '\n'
                else:
                    # too large, separate attachment
                    att = MIMEText(v, _charset='UTF-8')
                    att.add_header('Content-Disposition', 'attachment', filename=k+'.txt')
                    attachments.append(att)

        # create initial text attachment
        att = MIMEText(text, _charset='UTF-8')
        att.add_header('Content-Disposition', 'inline')
        attachments.insert(0, att)

        msg = MIMEMultipart()
        for a in attachments:
            msg.attach(a)

        print >> file, msg.as_string()

    def __setitem__(self, k, v):
        assert hasattr(k, 'isalnum')
        assert k.isalnum()
        # value must be a string or a file reference (tuple (string|file [, bool]))
        assert (hasattr(v, 'isalnum') or 
            (hasattr(v, '__getitem__') and (
            len(v) == 1 or (len(v) == 2 and v[1] in (True, False)))
            and (hasattr(v[0], 'isalnum') or hasattr(v[0], 'read'))))

        return self.data.__setitem__(k, v)


#
# Unit test
#

import unittest, tempfile, os, email

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
        pr['WhiteSpace'] = ' foo   bar\nbaz\n  blip  \n\nafteremptyline'
        io = StringIO()
        pr.write(io)
        self.assertEqual(io.getvalue(), 
'''ProblemType: Crash
Date: now!
Simple: bar
WhiteSpace:
  foo   bar
 baz
   blip  
 
 afteremptyline
''')

    def test_write_append(self):
        '''Test write() with appending to an existing file.'''

        pr = ProblemReport(date = 'now!')
        pr['Simple'] = 'bar'
        pr['WhiteSpace'] = ' foo   bar\nbaz\n  blip  '
        io = StringIO()
        pr.write(io)

        pr.clear()
        pr['Extra'] = 'appended'
        pr.write(io)

        self.assertEqual(io.getvalue(), 
'''ProblemType: Crash
Date: now!
Simple: bar
WhiteSpace:
  foo   bar
 baz
   blip  
Extra: appended
''')

        temp = tempfile.NamedTemporaryFile()
        temp.write('AB' * 10 + '\0' * 10 + 'Z')
        temp.flush()

        pr = ProblemReport(date = 'now!')
        pr['File'] = (temp.name,)
        io = StringIO()
        pr.write(io)
        temp.close()

        pr.clear()
        pr['Extra'] = 'appended'
        pr.write(io)

        self.assertEqual(io.getvalue(), 
'''ProblemType: Crash
Date: now!
File: base64
 eJw=
 c3RyxIAMcBAFAG55BXk=
Extra: appended
''')

    def test_load(self):
        '''Test load() with various formatting.'''
        pr = ProblemReport()
        pr.load(StringIO(
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
        pr.load(StringIO(
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
        pr.load(StringIO(
'''ProblemType: Crash
WhiteSpace:
  foo   bar
 baz
 
   blip  
Last: foo
'''))
        self.assertEqual(pr['WhiteSpace'], ' foo   bar\nbaz\n\n  blip  ')
        self.assertEqual(pr['Last'], 'foo')

        pr.load(StringIO(
'''ProblemType: Crash
WhiteSpace:
  foo   bar
 baz
   blip  
Last: foo
 
'''))
        self.assertEqual(pr['WhiteSpace'], ' foo   bar\nbaz\n  blip  ')
        self.assertEqual(pr['Last'], 'foo\n')

        # empty lines in values must have a leading space in coding
        invalid_spacing = StringIO('''WhiteSpace:
 first

 second
''')
        pr = ProblemReport()
        self.assertRaises(ValueError, pr.load, invalid_spacing)

        # test that load() cleans up properly
        pr.load(StringIO('ProblemType: Crash'))
        self.assertEqual(pr.keys(), ['ProblemType'])

    def test_write_file(self):
        '''Test writing a report with binary file data.'''

        temp = tempfile.NamedTemporaryFile()
        temp.write('AB' * 10 + '\0' * 10 + 'Z')
        temp.flush()

        pr = ProblemReport(date = 'now!')
        pr['File'] = (temp.name,)
        pr['Afile'] = (temp.name,)
        io = StringIO()
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
        io = StringIO()
        pr.write(io)

        self.assertEqual(io.getvalue(), 
'''ProblemType: Crash
Date: now!
File: foo\0bar
''')

        pr['File'] = (temp.name, True)
        io = StringIO()
        pr.write(io)

        self.assertEqual(io.getvalue(), 
'''ProblemType: Crash
Date: now!
File: base64
 eJw=
 S8vPZ0hKLAIACfACeg==
''')
        temp.close()

    def test_write_fileobj(self):
        '''Test writing a report with a pointer to a file-like object.'''

        tempbin = StringIO('AB' * 10 + '\0' * 10 + 'Z')
        tempasc = StringIO('Hello World')

        pr = ProblemReport(date = 'now!')
        pr['BinFile'] = (tempbin,)
        pr['AscFile'] = (tempasc, False)
        io = StringIO()
        pr.write(io)

        self.assertEqual(io.getvalue(), 
'''ProblemType: Crash
AscFile: Hello World
Date: now!
BinFile: base64
 eJw=
 c3RyxIAMcBAFAG55BXk=
''')

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
        pr.load(StringIO(bin_report))
        self.assertEqual(pr['File'], 'AB' * 10 + '\0' * 10 + 'Z')
        self.assertEqual(pr.has_removed_fields(), False)

        # test with skipping binary data
        pr.load(StringIO(bin_report), binary=False)
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
        pr.load(StringIO(bin_report))
        self.assertEqual(pr['File'], 'AB' * 10 + '\0' * 10 + 'Z')
        self.assertEqual(pr.has_removed_fields(), False)

        # test with skipping binary data
        pr.load(StringIO(bin_report), binary=False)
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
        io = StringIO()
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
        io2 = StringIO()
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
        pr.load(StringIO(report))

        self.assertEqual(pr['Long'], 'xxx\n.\nyyy')

        # write back unmodified
        io = StringIO()
        pr.write(io)
        self.assertEqual(io.getvalue(), report)

        pr['Short'] = 'aaa\nbbb'
        pr['Long'] = '123'
        io = StringIO()
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

    def test_add_to_existing(self):
        '''Test adding information to an existing report.'''

        # original report
        pr = ProblemReport()
        pr['old1'] = '11'
        pr['old2'] = '22'

        (fd, rep) = tempfile.mkstemp()
        os.close(fd)
        pr.write(open(rep, 'w'))

        origstat = os.stat(rep)

        # create a new one and add it
        pr = ProblemReport()
        pr.clear()
        pr['new1'] = '33'

        pr.add_to_existing(rep, keep_times=True)

        # check keep_times
        newstat = os.stat(rep)
        self.assertEqual(origstat.st_mode, newstat.st_mode)
        self.assertAlmostEqual(origstat.st_atime, newstat.st_atime, 1)
        self.assertAlmostEqual(origstat.st_mtime, newstat.st_mtime, 1)

        # check report contents
        newpr = ProblemReport()
        newpr.load(open(rep))
        self.assertEqual(newpr['old1'], '11')
        self.assertEqual(newpr['old2'], '22')
        self.assertEqual(newpr['new1'], '33')

        # create a another new one and add it, but make sure mtime must be
        # different
        time.sleep(1)
        open(rep).read() # bump atime
        time.sleep(1)

        pr = ProblemReport()
        pr.clear()
        pr['new2'] = '44'

        pr.add_to_existing(rep)

        # check that timestamps have been updates
        newstat = os.stat(rep)
        self.assertEqual(origstat.st_mode, newstat.st_mode)
        self.assertNotEqual(origstat.st_mtime, newstat.st_mtime)
        self.assertNotEqual(origstat.st_atime, newstat.st_atime)

        # check report contents
        newpr = ProblemReport()
        newpr.load(open(rep))
        self.assertEqual(newpr['old1'], '11')
        self.assertEqual(newpr['old2'], '22')
        self.assertEqual(newpr['new1'], '33')
        self.assertEqual(newpr['new2'], '44')

        os.unlink(rep)

    def test_write_mime_text(self):
        '''Test write_mime() for text values.'''

        pr = ProblemReport(date = 'now!')
        pr['Simple'] = 'bar'
        pr['TwoLine'] = 'first\nsecond\n'
        pr['InlineMargin'] = 'first\nsecond\nthird\nfourth\nfifth\n'
        pr['Multiline'] = ' foo   bar\nbaz\n  blip  \nline4\nline♥5!!\nłıµ€ ⅝\n'
        io = StringIO()
        pr.write_mime(io)
        io.seek(0)

        msg = email.message_from_file(io)
        msg_iter = msg.walk()

        # first part is the multipart container
        part = msg_iter.next()
        self.assert_(part.is_multipart())

        # second part should be an inline text/plain attachments with all short
        # fields
        part = msg_iter.next()
        self.assert_(not part.is_multipart())
        self.assertEqual(part.get_content_type(), 'text/plain')
        self.assertEqual(part.get_content_charset(), 'utf-8')
        self.assertEqual(part.get_filename(), None)
        self.assertEqual(part.get_payload(decode=True), '''ProblemType: Crash
Date: now!
InlineMargin:
 first
 second
 third
 fourth
 fifth
Simple: bar
TwoLine:
 first
 second
''')

        # third part should be the Multiline: field as attachment
        part = msg_iter.next()
        self.assert_(not part.is_multipart())
        self.assertEqual(part.get_content_type(), 'text/plain')
        self.assertEqual(part.get_content_charset(), 'utf-8')
        self.assertEqual(part.get_filename(), 'Multiline.txt')
        self.assertEqual(part.get_payload(decode=True), ''' foo   bar
baz
  blip  
line4
line♥5!!
łıµ€ ⅝
''')

        # no more parts
        self.assertRaises(StopIteration, msg_iter.next)
        
    def test_write_mime_binary(self):
        '''Test write_mime() for binary values and file references.'''

        bin_value = 'AB' * 10 + '\0' * 10 + 'Z'

        temp = tempfile.NamedTemporaryFile()
        temp.write(bin_value)
        temp.flush()

        pr = ProblemReport(date = 'now!')
        pr['Context'] = 'Test suite'
        pr['File1'] = (temp.name,)
        pr['Value1'] = bin_value
        io = StringIO()
        pr.write_mime(io)
        io.seek(0)

        msg = email.message_from_file(io)
        msg_iter = msg.walk()

        # first part is the multipart container
        part = msg_iter.next()
        self.assert_(part.is_multipart())

        # second part should be an inline text/plain attachments with all short
        # fields
        part = msg_iter.next()
        self.assert_(not part.is_multipart())
        self.assertEqual(part.get_content_type(), 'text/plain')
        self.assertEqual(part.get_content_charset(), 'utf-8')
        self.assertEqual(part.get_filename(), None)
        self.assertEqual(part.get_payload(decode=True), 
            'ProblemType: Crash\nContext: Test suite\nDate: now!\n')

        # third part should be the File1: file contents as gzip'ed attachment
        part = msg_iter.next()
        self.assert_(not part.is_multipart())
        self.assertEqual(part.get_content_type(), 'application/x-gzip')
        self.assertEqual(part.get_filename(), 'File1.gz')
        f = tempfile.TemporaryFile()
        f.write(part.get_payload(decode=True))
        f.seek(0)
        self.assertEqual(gzip.GzipFile(mode='rb', fileobj=f).read(), bin_value)

        # fourth part should be the Value1: value as gzip'ed attachment
        part = msg_iter.next()
        self.assert_(not part.is_multipart())
        self.assertEqual(part.get_content_type(), 'application/x-gzip')
        self.assertEqual(part.get_filename(), 'Value1.gz')
        f = tempfile.TemporaryFile()
        f.write(part.get_payload(decode=True))
        f.seek(0)
        self.assertEqual(gzip.GzipFile(mode='rb', fileobj=f).read(), bin_value)

        # no more parts
        self.assertRaises(StopIteration, msg_iter.next)
        
if __name__ == '__main__':
    unittest.main()
