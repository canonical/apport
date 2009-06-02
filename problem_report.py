# vim: set encoding=UTF-8 fileencoding=UTF-8 :

'''Store, load, and handle problem reports.

Copyright (C) 2006 Canonical Ltd.
Author: Martin Pitt <martin.pitt@ubuntu.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

import zlib, base64, time, UserDict, sys, gzip, struct
from cStringIO import StringIO
from email.Encoders import encode_base64
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText

class CompressedValue:
    '''Represent a ProblemReport value which is gzip compressed.'''

    def __init__(self, value=None, name=None):
        '''Initialize an empty CompressedValue object with an optional name.'''
        
        self.gzipvalue = None
        self.name = name
        # By default, compressed values are in gzip format. Earlier versions of
        # problem_report used zlib format (without gzip header). If you have such
        # a case, set legacy_zlib to True.
        self.legacy_zlib = False

        if value:
            self.set_value(value)

    def set_value(self, value):
        '''Set uncompressed value.'''

        out = StringIO()
        gzip.GzipFile(self.name, mode='wb', fileobj=out).write(value)
        self.gzipvalue = out.getvalue()
        self.legacy_zlib = False

    def get_value(self):
        '''Return uncompressed value.'''

        if not self.gzipvalue:
            return None

        if self.legacy_zlib:
            return zlib.decompress(self.gzipvalue)
        return gzip.GzipFile(fileobj=StringIO(self.gzipvalue)).read()

    def write(self, file):
        '''Write uncompressed value into given file-like object.'''

        assert self.gzipvalue

        if self.legacy_zlib:
            file.write(zlib.decompress(self.gzipvalue))
            return

        gz = gzip.GzipFile(fileobj=StringIO(self.gzipvalue))
        while True:
            block = gz.read(1048576)
            if not block:
                break
            file.write(block)

    def __len__(self):
        '''Return length of uncompressed value.'''

        assert self.gzipvalue
        if self.legacy_zlib:
            return len(self.get_value())
        return int(struct.unpack("<L", self.gzipvalue[-4:])[0])

    def splitlines(self):
        '''Behaves like splitlines() for a normal string.'''

        return self.get_value().splitlines()

class ProblemReport(UserDict.IterableUserDict):
    def __init__(self, type = 'Crash', date = None):
        '''Initialize a fresh problem report.

        type can be 'Crash', 'Packaging', 'KernelCrash' or 'KernelOops'.
        date is the desired date/time string; if None (default), the
        current local time is used. '''

        if date == None:
            date = time.asctime()
        self.data = {'ProblemType': type, 'Date': date}

        # keeps track of keys which were added since the last ctor or load()
        self.old_keys = set()

    def load(self, file, binary=True):
        '''Initialize problem report from a file-like object.
        
        If binary is False, binary data is not loaded; the dictionary key is
        created, but its value will be an empty string. If it is true, it is
        transparently uncompressed and available as dictionary string values.
        If binary is 'compressed', the compressed value is retained, and the
        dictionary value will be a CompressedValue object. This is useful if
        the compressed value is still useful (to avoid recompression if the
        file needs to be written back).

        Files are in RFC822 format.
        '''
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
                        if binary == 'compressed':
                            # check gzip header; if absent, we have legacy zlib
                            # data
                            if value.gzipvalue == '' and not l.startswith('\037\213\010'): 
                                value.legacy_zlib = True
                            value.gzipvalue += l
                        else:
                            # lazy initialization of bd
                            # skip gzip header, if present
                            if l.startswith('\037\213\010'): 
                                bd = zlib.decompressobj(-zlib.MAX_WBITS)
                                value = bd.decompress(self._strip_gzip_header(l))
                            else:
                                # legacy zlib-only format used default block
                                # size
                                bd = zlib.decompressobj()
                                value += bd.decompress(l)
                else:
                    if len(value) > 0:
                        value += '\n'
                    value += line[1:-1]
            else:
                if b64_block:
                    if bd:
                        value += bd.flush()
                    b64_block = False
                    bd = None
                if key:
                    assert value != None
                    self.data[key] = value
                (key, value) = line.split(':', 1)
                value = value.strip()
                if value == 'base64':
                    if binary == 'compressed':
                        value = CompressedValue(key)
                        value.gzipvalue = ''
                    else:
                        value = ''
                    b64_block = True

        if key != None:
            self.data[key] = value

        self.old_keys = set(self.data.keys())

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

    def write(self, file, only_new = False):
        '''Write information into the given file-like object.

        If only_new is True, only keys which have been added since the last
        load() are written (i. e. those returned by new_keys()).

        If a value is a string, it is written directly. Otherwise it must be a
        tuple of the form (file, encode=True, limit=None, fail_on_empty=False).
        The first argument can be a file name or a file-like object,
        which will be read and its content will become the value of this key.
        'encode' specifies whether the contents will be
        gzip compressed and base64-encoded (this defaults to True). If limit is
        set to a positive integer, the entire key will be removed. If
        fail_on_empty is True, reading zero bytes will cause an IOError.

        Files are written in RFC822 format.
        '''
        # sort keys into ASCII non-ASCII/binary attachment ones, so that
        # the base64 ones appear last in the report
        asckeys = []
        binkeys = []
        for k in self.data.keys():
            if only_new and k in self.old_keys:
                continue
            v = self.data[k]
            if hasattr(v, 'find'):
                if self._is_binary(v):
                    binkeys.append(k)
                else:
                    asckeys.append(k)
            else:
                if not isinstance(v, CompressedValue) and len(v) >= 2 and not v[1]: # force uncompressed
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
                if len(v) >= 3 and v[2] != None:
                    limit = v[2]
                else:
                    limit = None

                fail_on_empty = len(v) >= 4 and v[3]

                if hasattr(v[0], 'read'):
                    v = v[0].read() # file-like object
                else:
                    v = open(v[0]).read() # file name

                if fail_on_empty and len(v) == 0:
                    raise IOError, 'did not get any data for field ' + k

                if limit != None and len(v) > limit:
                    del self.data[k]
                    continue

            if type(v) == type(u''):
                # unicode → str
                v = v.encode('UTF-8')

            if '\n' in v:
                # multiline value
                print >> file, k + ':'
                print >> file, '', v.replace('\n', '\n ')
            else:
                # single line value
                print >> file, k + ':', v

        # now write the binary keys with gzip compression and base64 encoding
        for k in binkeys:
            v = self.data[k]
            limit = None
            size = 0

            curr_pos = file.tell()
            file.write (k + ': base64\n ')

            # CompressedValue
            if isinstance(v, CompressedValue):
                file.write(base64.b64encode(v.gzipvalue))
                file.write('\n')
                continue

            # write gzip header
            gzip_header = '\037\213\010\010\000\000\000\000\002\377' + k + '\000'
            file.write(base64.b64encode(gzip_header))
            file.write('\n ')
            crc = zlib.crc32('')

            bc = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS,
                zlib.DEF_MEM_LEVEL, 0)
            # direct value
            if hasattr(v, 'find'):
                size += len(v)
                crc = zlib.crc32(v, crc)
                outblock = bc.compress(v)
                if outblock:
                    file.write(base64.b64encode(outblock))
                    file.write('\n ')
            # file reference
            else:
                if len(v) >= 3 and v[2] != None:
                    limit = v[2]

                if hasattr(v[0], 'read'):
                    f = v[0] # file-like object
                else:
                    f = open(v[0]) # file name
                while True:
                    block = f.read(1048576)
                    size += len(block)
                    crc = zlib.crc32(block, crc)
                    if limit != None:
                        if size > limit:
                            # roll back
                            file.seek(curr_pos)
                            file.truncate(curr_pos)
                            del self.data[k]
                            crc = None
                            break
                    if block:
                        outblock = bc.compress(block)
                        if outblock:
                            file.write(base64.b64encode(outblock))
                            file.write('\n ')
                    else:
                        break

                if len(v) >= 4 and v[3]:
                    if size == 0:
                        raise IOError, 'did not get any data for field %s from %s' % (k, str(v[0]))

            # flush compressor and write the rest
            if not limit or size <= limit:
                block = bc.flush()
                # append gzip trailer: crc (32 bit) and size (32 bit)
                if crc:
                    block += struct.pack("<L", crc & 0xFFFFFFFFL)
                    block += struct.pack("<L", size & 0xFFFFFFFFL)

                file.write(base64.b64encode(block))
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

    def write_mime(self, file, attach_treshold = 5, extra_headers={},
        skip_keys=None):
        '''Write information into the given file-like object, using
        MIME/Multipart RFC 2822 format (i. e. an email with attachments).

        If a value is a string or a CompressedValue, it is written directly.
        Otherwise it must be a tuple containing the source file and an optional
        boolean value (in that order); the first argument can be a file name or
        a file-like object, which will be read and its content will become the
        value of this key.  The file will be gzip compressed, unless the key
        already ends in .gz.

        attach_treshold specifies the maximum number of lines for a value to be
        included into the first inline text part. All bigger values (as well as
        all non-ASCII ones) will become an attachment.

        Extra MIME preamble headers can be specified, too, as a dictionary.

        skip_keys is a set/list specifying keys which are filtered out and not
        written to the destination file.
        '''

        keys = self.data.keys()
        keys.sort()

        text = ''
        attachments = []

        if 'ProblemType' in keys:
            keys.remove('ProblemType')
            keys.insert(0, 'ProblemType')

        for k in keys:
            if skip_keys and k in skip_keys:
                continue
            v = self.data[k]
            attach_value = None

            # compressed values are ready for attaching in gzip form
            if isinstance(v, CompressedValue):
                attach_value = v.gzipvalue

            # if it's a tuple, we have a file reference; read the contents
            # and gzip it
            elif not hasattr(v, 'find'):
                attach_value = ''
                if hasattr(v[0], 'read'):
                    f = v[0] # file-like object
                else:
                    f = open(v[0]) # file name
                if k.endswith('.gz'):
                    attach_value = f.read()
                else:
                    io = StringIO()
                    gf = gzip.GzipFile(k, mode='wb', fileobj=io)
                    while True:
                        block = f.read(1048576)
                        if block:
                            gf.write(block)
                        else:
                            gf.close()
                            break
                    attach_value = io.getvalue()
                f.close()

            # binary value
            elif self._is_binary(v):
                if k.endswith('.gz'):
                    attach_value = v
                else:
                    attach_value = CompressedValue(v, k).gzipvalue

            # if we have an attachment value, create an attachment
            if attach_value:
                att = MIMEBase('application', 'x-gzip')
                if k.endswith('.gz'):
                    att.add_header('Content-Disposition', 'attachment', filename=k)
                else:
                    att.add_header('Content-Disposition', 'attachment', filename=k+'.gz')
                att.set_payload(attach_value)
                encode_base64(att)
                attachments.append(att)
            else:
                # plain text value
                if type(v) == type(u''):
                    # convert unicode to UTF-8 str
                    v = v.encode('UTF-8')

                lines = len(v.splitlines())
                if lines == 1:
                    v = v.rstrip()
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
        for k, v in extra_headers.iteritems():
            msg.add_header(k, v)
        for a in attachments:
            msg.attach(a)

        print >> file, msg.as_string()

    def __setitem__(self, k, v):
        assert hasattr(k, 'isalnum')
        assert k.replace('.', '').replace('-', '').replace('_', '').isalnum()
        # value must be a string or a CompressedValue or a file reference
        # (tuple (string|file [, bool]))
        assert (isinstance(v, CompressedValue) or hasattr(v, 'isalnum') or
            (hasattr(v, '__getitem__') and (
            len(v) == 1 or (len(v) >= 2 and v[1] in (True, False)))
            and (hasattr(v[0], 'isalnum') or hasattr(v[0], 'read'))))

        return self.data.__setitem__(k, v)

    def new_keys(self):
        '''Return the set of keys which have been added to the report since it
        was constructed or loaded.'''

        return set(self.data.keys()) - self.old_keys

    @classmethod
    def _strip_gzip_header(klass, line):
        '''Strip gzip header from line and return the rest.'''

        flags = ord(line[3])
        offset = 10
        if flags & 4: # FLG.FEXTRA
            offset += line[offset] + 1
        if flags & 8: # FLG.FNAME
            while ord(line[offset]) != 0:
                offset += 1
            offset += 1
        if flags & 16: # FLG.FCOMMENT
            while ord(line[offset]) != 0:
                offset += 1
            offset += 1
        if flags & 2: # FLG.FHCRC
            offset += 2

        return line[offset:]

#
# Unit test
#

import unittest, tempfile, os, email

class _ProblemReportTest(unittest.TestCase):
    def test_basic_operations(self):
        '''basic creation and operation.'''

        pr = ProblemReport()
        pr['foo'] = 'bar'
        pr['bar'] = ' foo   bar\nbaz\n   blip  '
        pr['dash-key'] = '1'
        pr['dot.key'] = '1'
        pr['underscore_key'] = '1'
        self.assertEqual(pr['foo'], 'bar')
        self.assertEqual(pr['bar'], ' foo   bar\nbaz\n   blip  ')
        self.assertEqual(pr['ProblemType'], 'Crash')
        self.assert_(time.strptime(pr['Date']))
        self.assertEqual(pr['dash-key'], '1')
        self.assertEqual(pr['dot.key'], '1')
        self.assertEqual(pr['underscore_key'], '1')

    def test_ctor_arguments(self):
        '''non-default constructor arguments.'''

        pr = ProblemReport('KernelCrash')
        self.assertEqual(pr['ProblemType'], 'KernelCrash')
        pr = ProblemReport(date = '19801224 12:34')
        self.assertEqual(pr['Date'], '19801224 12:34')

    def test_sanity_checks(self):
        '''various error conditions.'''

        pr = ProblemReport()
        self.assertRaises(AssertionError, pr.__setitem__, 'a b', '1')
        self.assertRaises(AssertionError, pr.__setitem__, 'a', 1)
        self.assertRaises(AssertionError, pr.__setitem__, 'a', 1)
        self.assertRaises(AssertionError, pr.__setitem__, 'a', (1,))
        self.assertRaises(AssertionError, pr.__setitem__, 'a', ('/tmp/nonexistant', ''))
        self.assertRaises(KeyError, pr.__getitem__, 'Nonexistant')

    def test_compressed_values(self):
        '''handling of CompressedValue values.'''

        large_val = 'A' * 5000000

        pr = ProblemReport()
        pr['Foo'] = CompressedValue('FooFoo!')
        pr['Bin'] = CompressedValue()
        pr['Bin'].set_value('AB' * 10 + '\0' * 10 + 'Z')
        pr['Large'] = CompressedValue(large_val)

        self.assert_(isinstance(pr['Foo'], CompressedValue))
        self.assert_(isinstance(pr['Bin'], CompressedValue))
        self.assertEqual(pr['Foo'].get_value(), 'FooFoo!')
        self.assertEqual(pr['Bin'].get_value(), 'AB' * 10 + '\0' * 10 + 'Z')
        self.assertEqual(pr['Large'].get_value(), large_val)
        self.assertEqual(len(pr['Foo']), 7)
        self.assertEqual(len(pr['Bin']), 31)
        self.assertEqual(len(pr['Large']), len(large_val))

        io = StringIO()
        pr['Bin'].write(io)
        self.assertEqual(io.getvalue(), 'AB' * 10 + '\0' * 10 + 'Z')
        io = StringIO()
        pr['Large'].write(io)
        self.assertEqual(io.getvalue(), large_val)

        pr['Multiline'] = CompressedValue('\1\1\1\n\2\2\n\3\3\3')
        self.assertEqual(pr['Multiline'].splitlines(), 
            ['\1\1\1', '\2\2', '\3\3\3'])

        # test writing of reports with CompressedValues
        io = StringIO()
        pr.write(io)
        io.seek(0)
        pr = ProblemReport()
        pr.load(io)
        self.assertEqual(pr['Foo'], 'FooFoo!')
        self.assertEqual(pr['Bin'], 'AB' * 10 + '\0' * 10 + 'Z')
        self.assertEqual(pr['Large'], large_val)

    def test_write(self):
        '''write() and proper formatting.'''

        pr = ProblemReport(date = 'now!')
        pr['Simple'] = 'bar'
        pr['SimpleUTF8'] = '1äö2Φ3'
        pr['SimpleUnicode'] = u'1äö2Φ3'
        pr['TwoLineUTF8'] = 'pi-π\nnu-η'
        pr['TwoLineUnicode'] = u'pi-π\nnu-η'
        pr['WhiteSpace'] = ' foo   bar\nbaz\n  blip  \n\nafteremptyline'
        io = StringIO()
        pr.write(io)
        self.assertEqual(io.getvalue(), 
'''ProblemType: Crash
Date: now!
Simple: bar
SimpleUTF8: 1äö2Φ3
SimpleUnicode: 1äö2Φ3
TwoLineUTF8:
 pi-π
 nu-η
TwoLineUnicode:
 pi-π
 nu-η
WhiteSpace:
  foo   bar
 baz
   blip  
 
 afteremptyline
''')

    def test_write_append(self):
        '''write() with appending to an existing file.'''

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

        io.seek(0)
        pr = ProblemReport()
        pr.load(io)

        self.assertEqual(pr['Date'], 'now!')
        self.assertEqual(pr['File'], 'AB' * 10 + '\0' * 10 + 'Z')
        self.assertEqual(pr['Extra'], 'appended')

    def test_load(self):
        '''load() with various formatting.'''
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
        '''writing a report with binary file data.'''

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
 H4sICAAAAAAC/0FmaWxlAA==
 c3RyxIAMcBAFAK/2p9MfAAAA
File: base64
 H4sICAAAAAAC/0ZpbGUA
 c3RyxIAMcBAFAK/2p9MfAAAA
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
 H4sICAAAAAAC/0ZpbGUA
 S8vPZ0hKLAIACq50HgcAAAA=
''')
        temp.close()

    def test_write_fileobj(self):
        '''writing a report with a pointer to a file-like object.'''

        tempbin = StringIO('AB' * 10 + '\0' * 10 + 'Z')
        tempasc = StringIO('Hello World')

        pr = ProblemReport(date = 'now!')
        pr['BinFile'] = (tempbin,)
        pr['AscFile'] = (tempasc, False)
        io = StringIO()
        pr.write(io)
        io.seek(0)

        pr = ProblemReport()
        pr.load(io)
        self.assertEqual(pr['BinFile'], tempbin.getvalue())
        self.assertEqual(pr['AscFile'], tempasc.getvalue())

    def test_write_empty_fileobj(self):
        '''writing a report with a pointer to a file-like object with enforcing non-emptyness.'''

        tempbin = StringIO('')
        tempasc = StringIO('')

        pr = ProblemReport(date = 'now!')
        pr['BinFile'] = (tempbin, True, None, True)
        io = StringIO()
        self.assertRaises(IOError, pr.write, io)

        pr = ProblemReport(date = 'now!')
        pr['AscFile'] = (tempasc, False, None, True)
        io = StringIO()
        self.assertRaises(IOError, pr.write, io)

    def test_write_delayed_fileobj(self):
        '''writing a report with file pointers and delayed data.'''

        (fout, fin) = os.pipe()

        if os.fork() == 0:
            os.close(fout)
            time.sleep(0.3)
            os.write(fin, 'ab' * 512*1024)
            time.sleep(0.3)
            os.write(fin, 'hello')
            time.sleep(0.3)
            os.write(fin, ' world')
            os.close(fin)
            os._exit(0)

        os.close(fin)

        pr = ProblemReport(date = 'now!')
        pr['BinFile'] = (os.fdopen(fout),)
        io = StringIO()
        pr.write(io)
        assert os.wait()[1] == 0

        io.seek(0)

        pr2 = ProblemReport()
        pr2.load(io)
        self.assert_(pr2['BinFile'].endswith('abhello world'))
        self.assertEqual(len(pr2['BinFile']), 1048576 + len('hello world'))

    def test_read_file(self):
        '''reading a report with binary data.'''

        bin_report = '''ProblemType: Crash
Date: now!
File: base64
 H4sICAAAAAAC/0ZpbGUA
 c3RyxIAMcBAFAK/2p9MfAAAA
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

        # test with keeping compressed binary data
        pr.load(StringIO(bin_report), binary='compressed')
        self.assertEqual(pr['Foo'], 'Bar')
        self.assertEqual(pr.has_removed_fields(), False)
        self.assert_(isinstance(pr['File'], CompressedValue))

        self.assertEqual(pr['File'].get_value(), 'AB' * 10 + '\0' * 10 + 'Z')

    def test_read_file_legacy(self):
        '''reading a report with binary data in legacy format without gzip
        header.'''

        bin_report = '''ProblemType: Crash
Date: now!
File: base64
 eJw=
 c3RyxIAMcBAFAG55BXk=
Foo: Bar
'''

        data = 'AB' * 10 + '\0' * 10 + 'Z'

        # test with reading everything
        pr = ProblemReport()
        pr.load(StringIO(bin_report))
        self.assertEqual(pr['File'], data)
        self.assertEqual(pr.has_removed_fields(), False)

        # test with skipping binary data
        pr.load(StringIO(bin_report), binary=False)
        self.assertEqual(pr['File'], '')
        self.assertEqual(pr.has_removed_fields(), True)

        # test with keeping CompressedValues
        pr.load(StringIO(bin_report), binary='compressed')
        self.assertEqual(pr.has_removed_fields(), False)
        self.assertEqual(len(pr['File']), len(data))
        self.assertEqual(pr['File'].get_value(), data)
        io = StringIO()
        pr['File'].write(io)
        io.seek(0)
        self.assertEqual(io.read(), data)

    def test_big_file(self):
        '''writing and re-decoding a big random file.'''

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

        # check gzip compatibility
        io.seek(0)
        pr = ProblemReport()
        pr.load(io, binary='compressed')
        self.assertEqual(pr['File'].get_value(), data)

    def test_size_limit(self):
        '''writing and a big random file with a size limit key.'''

        # create 1 MB random file
        temp = tempfile.NamedTemporaryFile()
        data = os.urandom(1048576)
        temp.write(data)
        temp.flush()

        # write it into problem report
        pr = ProblemReport()
        pr['FileSmallLimit'] = (temp.name, True, 100)
        pr['FileLimitMinus1'] = (temp.name, True, 1048575)
        pr['FileExactLimit'] = (temp.name, True, 1048576)
        pr['FileLimitPlus1'] = (temp.name, True, 1048577)
        pr['FileLimitNone'] = (temp.name, True, None)
        pr['Before'] = 'xtestx'
        pr['ZAfter'] = 'ytesty'
        io = StringIO()
        pr.write(io)
        temp.close()

        # read it again
        io.seek(0)
        pr = ProblemReport()
        pr.load(io)

        self.failIf(pr.has_key('FileSmallLimit'))
        self.failIf(pr.has_key('FileLimitMinus1'))
        self.assert_(pr['FileExactLimit'] == data)
        self.assert_(pr['FileLimitPlus1'] == data)
        self.assert_(pr['FileLimitNone'] == data)
        self.assertEqual(pr['Before'], 'xtestx')
        self.assertEqual(pr['ZAfter'], 'ytesty')

    def test_iter(self):
        '''ProblemReport iteration.'''

        pr = ProblemReport()
        pr['foo'] = 'bar'

        keys = []
        for k in pr:
            keys.append(k)
        keys.sort()
        self.assertEqual(' '.join(keys), 'Date ProblemType foo')

        self.assertEqual(len([k for k in pr if k != 'foo']), 2)

    def test_modify(self):
        '''reading, modifying fields, and writing back.'''

        report = '''ProblemType: Crash
Date: now!
Long:
 xxx
 .
 yyy
Short: Bar
File: base64
 H4sICAAAAAAC/0ZpbGUA
 c3RyxIAMcBAFAK/2p9MfAAAA
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
 H4sICAAAAAAC/0ZpbGUA
 c3RyxIAMcBAFAK/2p9MfAAAA
''')

    def test_add_to_existing(self):
        '''adding information to an existing report.'''

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
        # skip atime check if filesystem is mounted noatime
        skip_atime = False
        dir = rep
        while len(dir)>1:
            dir, filename = os.path.split(dir)
            if os.path.ismount(dir):
                for line in open('/proc/mounts'):
                    mount, fs, options = line.split(' ')[1:4]
                    if mount == dir and 'noatime' in options.split(','):
                        skip_atime = True
                        break
                break
        if not skip_atime:
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
        '''write_mime() for text values.'''

        pr = ProblemReport(date = 'now!')
        pr['Simple'] = 'bar'
        pr['SimpleUTF8'] = '1äö2Φ3'
        pr['SimpleUnicode'] = u'1äö2Φ3'
        pr['SimpleLineEnd'] = 'bar\n'
        pr['TwoLine'] = 'first\nsecond\n'
        pr['TwoLineUTF8'] = 'pi-π\nnu-η\n'
        pr['TwoLineUnicode'] = u'pi-π\nnu-η\n'
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
SimpleLineEnd: bar
SimpleUTF8: 1äö2Φ3
SimpleUnicode: 1äö2Φ3
TwoLine:
 first
 second
TwoLineUTF8:
 pi-π
 nu-η
TwoLineUnicode:
 pi-π
 nu-η
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
        '''write_mime() for binary values and file references.'''

        bin_value = 'AB' * 10 + '\0' * 10 + 'Z'

        temp = tempfile.NamedTemporaryFile()
        temp.write(bin_value)
        temp.flush()

        tempgz = tempfile.NamedTemporaryFile()
        gz = gzip.GzipFile('File1', 'w', fileobj=tempgz)
        gz.write(bin_value)
        gz.close()
        tempgz.flush()

        pr = ProblemReport(date = 'now!')
        pr['Context'] = 'Test suite'
        pr['File1'] = (temp.name,)
        pr['File1.gz'] = (tempgz.name,)
        pr['Value1'] = bin_value
        pr['Value1.gz'] = open(tempgz.name).read()
        pr['ZValue'] = CompressedValue(bin_value)
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

        # fourth part should be the File1.gz: file contents as gzip'ed
        # attachment; write_mime() should not compress it again
        part = msg_iter.next()
        self.assert_(not part.is_multipart())
        self.assertEqual(part.get_content_type(), 'application/x-gzip')
        self.assertEqual(part.get_filename(), 'File1.gz')
        f = tempfile.TemporaryFile()
        f.write(part.get_payload(decode=True))
        f.seek(0)
        self.assertEqual(gzip.GzipFile(mode='rb', fileobj=f).read(), bin_value)

        # fifth part should be the Value1: value as gzip'ed attachment
        part = msg_iter.next()
        self.assert_(not part.is_multipart())
        self.assertEqual(part.get_content_type(), 'application/x-gzip')
        self.assertEqual(part.get_filename(), 'Value1.gz')
        f = tempfile.TemporaryFile()
        f.write(part.get_payload(decode=True))
        f.seek(0)
        self.assertEqual(gzip.GzipFile(mode='rb', fileobj=f).read(), bin_value)

        # sixth part should be the Value1: value as gzip'ed attachment;
        # write_mime should not compress it again
        part = msg_iter.next()
        self.assert_(not part.is_multipart())
        self.assertEqual(part.get_content_type(), 'application/x-gzip')
        self.assertEqual(part.get_filename(), 'Value1.gz')
        f = tempfile.TemporaryFile()
        f.write(part.get_payload(decode=True))
        f.seek(0)
        self.assertEqual(gzip.GzipFile(mode='rb', fileobj=f).read(), bin_value)

        # seventh part should be the ZValue: value as gzip'ed attachment;
        # write_mime should not compress it again
        part = msg_iter.next()
        self.assert_(not part.is_multipart())
        self.assertEqual(part.get_content_type(), 'application/x-gzip')
        self.assertEqual(part.get_filename(), 'ZValue.gz')
        f = tempfile.TemporaryFile()
        f.write(part.get_payload(decode=True))
        f.seek(0)
        self.assertEqual(gzip.GzipFile(mode='rb', fileobj=f).read(), bin_value)

        # no more parts
        self.assertRaises(StopIteration, msg_iter.next)

    def test_write_mime_extra_headers(self):
        '''write_mime() with extra headers.'''

        pr = ProblemReport(date = 'now!')
        pr['Simple'] = 'bar'
        pr['TwoLine'] = 'first\nsecond\n'
        io = StringIO()
        pr.write_mime(io, extra_headers={'Greeting': 'hello world', 
            'Foo': 'Bar'})
        io.seek(0)

        msg = email.message_from_file(io)
        self.assertEqual(msg['Greeting'], 'hello world')
        self.assertEqual(msg['Foo'], 'Bar')
        msg_iter = msg.walk()

        # first part is the multipart container
        part = msg_iter.next()
        self.assert_(part.is_multipart())

        # second part should be an inline text/plain attachments with all short
        # fields
        part = msg_iter.next()
        self.assert_(not part.is_multipart())
        self.assertEqual(part.get_content_type(), 'text/plain')
        self.assert_('Simple: bar' in part.get_payload(decode=True))

        # no more parts
        self.assertRaises(StopIteration, msg_iter.next)

    def test_write_mime_filter(self):
        '''write_mime() with key filters.'''

        bin_value = 'AB' * 10 + '\0' * 10 + 'Z'

        pr = ProblemReport(date = 'now!')
        pr['GoodText'] = 'Hi'
        pr['BadText'] = 'YouDontSeeMe'
        pr['GoodBin'] = bin_value
        pr['BadBin'] = 'Y' + '\x05' * 10 + '-'
        io = StringIO()
        pr.write_mime(io, skip_keys=['BadText', 'BadBin'])
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
GoodText: Hi
''')

        # third part should be the GoodBin: field as attachment
        part = msg_iter.next()
        self.assert_(not part.is_multipart())
        f = tempfile.TemporaryFile()
        f.write(part.get_payload(decode=True))
        f.seek(0)
        self.assertEqual(gzip.GzipFile(mode='rb', fileobj=f).read(), bin_value)

        # no more parts
        self.assertRaises(StopIteration, msg_iter.next)

    def test_updating(self):
        '''new_keys() and write() with only_new=True.'''

        pr = ProblemReport()
        self.assertEqual(pr.new_keys(), set(['ProblemType', 'Date']))
        pr.load(StringIO(
'''ProblemType: Crash
Date: now!
Foo: bar
Baz: blob
'''))

        self.assertEqual(pr.new_keys(), set())

        pr['Foo'] = 'changed'
        pr['NewKey'] = 'new new'
        self.assertEqual(pr.new_keys(), set(['NewKey']))

        out = StringIO()
        pr.write(out, only_new=True)
        self.assertEqual(out.getvalue(), 'NewKey: new new\n')

    def test_import_dict(self):
        '''importing a dictionary with update().'''

        pr = ProblemReport()
        pr['oldtext'] = 'Hello world'
        pr['oldbin'] = 'AB' * 10 + '\0' * 10 + 'Z'
        pr['overwrite'] = 'I am crap'

        d = {}
        d['newtext'] = 'Goodbye world'
        d['newbin'] = '11\000\001\002\xFFZZ'
        d['overwrite'] = 'I am good' 

        pr.update(d)
        self.assertEqual(pr['oldtext'], 'Hello world')
        self.assertEqual(pr['oldbin'], 'AB' * 10 + '\0' * 10 + 'Z')
        self.assertEqual(pr['newtext'], 'Goodbye world')
        self.assertEqual(pr['newbin'], '11\000\001\002\xFFZZ')
        self.assertEqual(pr['overwrite'], 'I am good')

if __name__ == '__main__':
    unittest.main()
