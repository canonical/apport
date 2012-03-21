# vim: set encoding=UTF-8 fileencoding=UTF-8 :

'''Store, load, and handle problem reports.'''

# Copyright (C) 2006 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import zlib, base64, time, sys, gzip, struct, os
from email.encoders import encode_base64
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

try:
    from collections import UserDict
except ImportError:
    # Python 2
    from UserDict import IterableUserDict as UserDict

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

class ProblemReport(UserDict):
    def __init__(self, type = 'Crash', date = None):
        '''Initialize a fresh problem report.

        type can be 'Crash', 'Packaging', 'KernelCrash' or 'KernelOops'.
        date is the desired date/time string; if None (default), the
        current local time is used.
        '''
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
                    if line.endswith('\n'):
                        value += line[1:-1]
                    else:
                        value += line[1:]
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
        '''Check if the report has any keys which were not loaded.

        This could happen when using binary=False in load().
        '''
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
        set to a positive integer, the file is not attached if it's larger
        than the given limit, and the entire key will be removed. If
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
                    raise IOError('did not get any data for field ' + k)

                if limit != None and len(v) > limit:
                    del self.data[k]
                    continue

            if sys.version.startswith('2'):
                if isinstance(v, unicode):
                    # unicode → str
                    v = v.encode('UTF-8')

            if '\n' in v:
                # multiline value
                file.write('%s:\n' % k)
                file.write(' %s\n' % v.replace('\n', '\n '))
            else:
                # single line value
                file.write('%s: %s\n' % (k, v))

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
                        raise IOError('did not get any data for field %s from %s' % (k, str(v[0])))

            # flush compressor and write the rest
            if not limit or size <= limit:
                block = bc.flush()
                # append gzip trailer: crc (32 bit) and size (32 bit)
                if crc:
                    block += struct.pack("<L", crc & 0xFFFFFFFF)
                    block += struct.pack("<L", size & 0xFFFFFFFF)

                file.write(base64.b64encode(block))
                file.write('\n')

    def add_to_existing(self, reportfile, keep_times=False):
        '''Add this report's data to an already existing report file.

        The file will be temporarily chmod'ed to 000 to prevent frontends
        from picking up a hal-updated report file. If keep_times
        is True, then the file's atime and mtime restored after updating.
        '''
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
        skip_keys=None, priority_fields=None):
        '''Write MIME/Multipart RFC 2822 formatted data into file.

        file must be a file-like object, not a path.

        If a value is a string or a CompressedValue, it is written directly.
        Otherwise it must be a tuple containing the source file and an optional
        boolean value (in that order); the first argument can be a file name or
        a file-like object, which will be read and its content will become the
        value of this key.  The file will be gzip compressed, unless the key
        already ends in .gz.

        attach_treshold specifies the maximum number of lines for a value to be
        included into the first inline text part. All bigger values (as well as
        all non-ASCII ones) will become an attachment, as well as text
        values bigger than 1 kB.

        Extra MIME preamble headers can be specified, too, as a dictionary.

        skip_keys is a set/list specifying keys which are filtered out and not
        written to the destination file.

        priority_fields is a set/list specifying the order in which keys should
        appear in the destination file.
        '''
        keys = sorted(self.data.keys())

        text = ''
        attachments = []

        if 'ProblemType' in keys:
            keys.remove('ProblemType')
            keys.insert(0, 'ProblemType')

        if priority_fields:
            counter = 0
            for priority_field in priority_fields:
                if priority_field in keys:
                    keys.remove(priority_field)
                    keys.insert(counter, priority_field)
                    counter += 1

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
                size = len(v)

                # ensure that byte arrays are valid UTF-8
                if type(v) == type(''):
                    v = v.decode('UTF-8', 'replace')
                # convert unicode to UTF-8 str
                assert isinstance(v, unicode)
                v = v.encode('UTF-8')

                lines = len(v.splitlines())
                if size <= 1000 and lines == 1:
                    v = v.rstrip()
                    text += '%s: %s\n' % (k, v)
                elif size <= 100 and lines <= attach_treshold:
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
        for k, v in extra_headers.items():
            msg.add_header(k, v)
        for a in attachments:
            msg.attach(a)

        file.write(msg.as_string())
        file.write('\n')

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
        '''Return newly added keys.

        Return the set of keys which have been added to the report since it
        was constructed or loaded.
        '''
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
