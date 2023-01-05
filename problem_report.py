"""Store, load, and handle problem reports."""

# Copyright (C) 2006 - 2012 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import base64
import binascii
import collections
import email.encoders
import email.mime.base
import email.mime.multipart
import email.mime.text
import gzip
import io
import locale
import os
import struct
import time
import typing
import zlib

# magic number (0x1F 0x8B) and compression method (0x08 for DEFLATE)
GZIP_HEADER_START = b"\037\213\010"


class MalformedProblemReport(ValueError):
    """Raised when a problem report violates the crash report format.

    This exception might be raised when the keys of the report are not ASCII.
    """


class CompressedValue:
    """Represent a ProblemReport value which is gzip compressed."""

    def __init__(self, value=None, name=None):
        """Initialize an empty CompressedValue object with an optional name."""
        self.gzipvalue = None
        self.name = name
        # By default, compressed values are in gzip format. Earlier versions of
        # problem_report used zlib format (without gzip header). If you have
        # such a case, set legacy_zlib to True.
        self.legacy_zlib = False

        if value:
            self.set_value(value)

    def set_value(self, value):
        """Set uncompressed value."""
        out = io.BytesIO()
        gzip.GzipFile(self.name, mode="wb", fileobj=out, mtime=0).write(value)
        self.gzipvalue = out.getvalue()
        self.legacy_zlib = False

    def get_value(self):
        """Return uncompressed value."""
        if not self.gzipvalue:
            return None

        if self.legacy_zlib:
            return zlib.decompress(self.gzipvalue)
        return gzip.GzipFile(fileobj=io.BytesIO(self.gzipvalue)).read()

    def write(self, file):
        """Write uncompressed value into given file-like object."""
        assert self.gzipvalue

        if self.legacy_zlib:
            file.write(zlib.decompress(self.gzipvalue))
            return

        gz = gzip.GzipFile(fileobj=io.BytesIO(self.gzipvalue))
        while True:
            block = gz.read(1048576)
            if not block:
                break
            file.write(block)

    def __len__(self):
        """Return length of uncompressed value."""
        assert self.gzipvalue
        if self.legacy_zlib:
            return len(self.get_value())
        return int(struct.unpack("<L", self.gzipvalue[-4:])[0])

    def splitlines(self):
        """Behaves like splitlines() for a normal string."""
        return self.get_value().splitlines()


class ProblemReport(collections.UserDict):
    def __init__(self, problem_type="Crash", date=None):
        """Initialize a fresh problem report.

        problem_type can be 'Crash', 'Packaging', 'KernelCrash' or
        'KernelOops'. date is the desired date/time string; if
        None (default), the current local time is used.
        """
        if date is None:
            date = time.asctime()
        super().__init__({"ProblemType": problem_type, "Date": date})

        # keeps track of keys which were added since the last ctor or load()
        self.old_keys = set()

    def load(self, file, binary=True, key_filter=None):
        """Initialize problem report from a file-like object.

        If binary is False, binary data is not loaded; the dictionary key is
        created, but its value will be an empty string. If it is True, it is
        transparently uncompressed and available as dictionary byte array
        values. If binary is 'compressed', the compressed value is retained,
        and the dictionary value will be a CompressedValue object. This is
        useful if the compressed value is still useful (to avoid recompression
        if the file needs to be written back).

        file needs to be opened in binary mode.

        If key_filter is given, only those keys will be loaded.

        Files are in RFC822 format, but with case sensitive keys.
        """
        self._assert_bin_mode(file)
        self.data.clear()
        key = None
        value = None
        b64_block = False
        bd = None
        if key_filter:
            remaining_keys = set(key_filter)
        else:
            remaining_keys = None
        for line in file:
            # continuation line
            if line.startswith(b" "):
                if b64_block and not binary:
                    value = None
                    continue
                assert key is not None and value is not None
                if b64_block:
                    bd, value = self._decompress_line(line, bd, value)
                else:
                    if len(value) > 0:
                        value += b"\n"
                    if line.endswith(b"\n"):
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
                    if remaining_keys is not None:
                        try:
                            remaining_keys.remove(key)
                            self.data[key] = self._try_unicode(value)
                            if not remaining_keys:
                                key = None
                                break
                        except KeyError:
                            pass
                    else:
                        self.data[key] = self._try_unicode(value)

                try:
                    (key, value) = line.split(b":", 1)
                except ValueError:
                    raise MalformedProblemReport(
                        f"Malformed problem report: Line"
                        f" {line.decode(errors='backslashreplace')!r}"
                        f" does not contain a colon for separating"
                        f" the key from the value."
                    ) from None
                try:
                    key = key.decode("ASCII")
                except UnicodeDecodeError as error:
                    raise MalformedProblemReport(
                        f"Malformed problem report: {error}. "
                        f"Is this a proper .crash text file?"
                    ) from None
                value = value.strip()
                if value == b"base64":
                    if binary == "compressed":
                        value = CompressedValue(key.encode())
                        value.gzipvalue = b""
                    else:
                        value = b""
                    b64_block = True

        if key is not None:
            self.data[key] = self._try_unicode(value)

        self.old_keys = set(self.data.keys())

    def extract_keys(self, file, bin_keys, directory):
        """Extract only one binary element from the problem report.

        Binary elements like kernel crash dumps can be very big. This method
        extracts directly files without loading the report into memory.
        """
        self._assert_bin_mode(file)
        # support singe key and collection of keys
        if isinstance(bin_keys, str):
            bin_keys = [bin_keys]
        key = None
        value = None
        missing_keys = list(bin_keys)
        b64_block = {}
        bd = None
        out = None
        for line in file:
            # Identify the bin_keys we're looking for
            while not line.startswith(b" "):
                (key, value) = line.split(b":", 1)
                key = key.decode("ASCII")
                if key not in missing_keys:
                    break
                b64_block[key] = False
                missing_keys.remove(key)
                value = value.strip()
                if value == b"base64":
                    value = b""
                    b64_block[key] = True
                    key_path = os.path.join(directory, key)
                    try:
                        bd = None
                        with open(key_path, "wb") as out:
                            # pylint: disable=redefined-outer-name
                            for line in file:
                                # continuation line
                                if line.startswith(b" "):
                                    assert (
                                        key is not None and value is not None
                                    )
                                    if b64_block[key]:
                                        bd, line_value = self._decompress_line(
                                            line, bd
                                        )
                                        if line_value:
                                            out.write(line_value)
                                else:
                                    break
                    except OSError as error:
                        raise OSError(f"unable to open {key_path}") from error
                else:
                    break
        if missing_keys:
            raise KeyError(
                "Cannot find %s in report" % ", ".join(missing_keys)
            )
        if False in b64_block.values():
            raise ValueError(
                "%s has no binary content"
                % [
                    item
                    for item, element in b64_block.items()
                    if element is False
                ]
            )

    def get_timestamp(self) -> typing.Optional[int]:
        """Get timestamp (seconds since epoch) from Date field.

        Return None if it is not present.
        """
        # report time is from asctime(), not in locale representation
        orig_ctime = locale.getlocale(locale.LC_TIME)
        try:
            try:
                locale.setlocale(locale.LC_TIME, "C")
                return int(time.mktime(time.strptime(self["Date"])))
            except KeyError:
                return None
            finally:
                locale.setlocale(locale.LC_TIME, orig_ctime)
        except locale.Error:
            return None

    def has_removed_fields(self):
        """Check if the report has any keys which were not loaded.

        This could happen when using binary=False in load().
        """
        return None in self.values()

    @classmethod
    def _decompress_line(cls, line, decompressor, value=b""):
        """Decompress a Base64 encoded line of gzip compressed data."""
        try:
            block = base64.b64decode(line)
        except binascii.Error as error:
            raise MalformedProblemReport(
                f"Malformed problem report: {error}."
            ) from None
        if decompressor:
            value += decompressor.decompress(block)
        else:
            if isinstance(value, CompressedValue):
                # check gzip header; if absent, we have legacy zlib
                # data
                if value.gzipvalue == b"" and not block.startswith(
                    GZIP_HEADER_START
                ):
                    value.legacy_zlib = True
                value.gzipvalue += block
            else:
                # lazy initialization of decompressor
                # skip gzip header, if present
                if block.startswith(GZIP_HEADER_START):
                    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                    value = decompressor.decompress(
                        cls._strip_gzip_header(block)
                    )
                else:
                    # legacy zlib-only format used default block
                    # size
                    decompressor = zlib.decompressobj()
                    value += decompressor.decompress(block)

        return decompressor, value

    @staticmethod
    def is_binary(string):
        """Check if the given strings contains binary data."""
        if isinstance(string, bytes):
            for c in string:
                if c < 32 and not chr(c).isspace():
                    return True
        return False

    @classmethod
    def _try_unicode(cls, value):
        """Try to convert bytearray value to Unicode."""
        if isinstance(value, bytes) and not cls.is_binary(value):
            try:
                return value.decode("UTF-8")
            except UnicodeDecodeError:
                return value
        return value

    def write(self, file, only_new=False):
        """Write information into the given file-like object.

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
        fail_on_empty is True, reading zero bytes will cause an OSError.

        file needs to be opened in binary mode.

        Files are written in RFC822 format.
        """
        self._assert_bin_mode(file)

        # sort keys into ASCII non-ASCII/binary attachment ones, so that
        # the base64 ones appear last in the report
        asckeys = []
        binkeys = []
        for k in self.data.keys():
            if only_new and k in self.old_keys:
                continue
            v = self.data[k]
            if hasattr(v, "find"):
                if self.is_binary(v):
                    binkeys.append(k)
                else:
                    asckeys.append(k)
            else:
                if (
                    not isinstance(v, CompressedValue)
                    and len(v) >= 2
                    and not v[1]
                ):
                    # force uncompressed
                    asckeys.append(k)
                else:
                    binkeys.append(k)

        asckeys.sort()
        if "ProblemType" in asckeys:
            asckeys.remove("ProblemType")
            asckeys.insert(0, "ProblemType")
        binkeys.sort()

        # write the ASCII keys first
        for k in asckeys:
            v = self.data[k]

            # if it's a tuple, we have a file reference; read the contents
            if not hasattr(v, "find"):
                if len(v) >= 3 and v[2] is not None:
                    limit = v[2]
                else:
                    limit = None

                fail_on_empty = len(v) >= 4 and v[3]

                if hasattr(v[0], "read"):
                    v = v[0].read()  # file-like object
                else:
                    with open(v[0], "rb") as f:  # file name
                        v = f.read()

                if fail_on_empty and len(v) == 0:
                    raise OSError("did not get any data for field " + k)

                if limit is not None and len(v) > limit:
                    del self.data[k]
                    continue

            if isinstance(v, str):
                # unicode → str
                v = v.encode("UTF-8")

            file.write(k.encode("ASCII"))
            if b"\n" in v:
                # multiline value
                file.write(b":\n ")
                file.write(v.replace(b"\n", b"\n "))
            else:
                file.write(b": ")
                file.write(v)
            file.write(b"\n")

        # now write the binary keys with gzip compression and base64 encoding
        for k in binkeys:
            v = self.data[k]
            limit = None
            size = 0

            curr_pos = file.tell()
            file.write(k.encode("ASCII"))
            file.write(b": base64\n ")

            # CompressedValue
            if isinstance(v, CompressedValue):
                file.write(base64.b64encode(v.gzipvalue))
                file.write(b"\n")
                continue

            # write gzip header
            gzip_header = (
                GZIP_HEADER_START
                + b"\010\000\000\000\000\002\377"
                + k.encode("UTF-8")
                + b"\000"
            )
            file.write(base64.b64encode(gzip_header))
            file.write(b"\n ")
            crc = zlib.crc32(b"")

            bc = zlib.compressobj(
                6, zlib.DEFLATED, -zlib.MAX_WBITS, zlib.DEF_MEM_LEVEL, 0
            )
            # direct value
            if hasattr(v, "find"):
                size += len(v)
                crc = zlib.crc32(v, crc)
                outblock = bc.compress(v)
                if outblock:
                    file.write(base64.b64encode(outblock))
                    file.write(b"\n ")
            # file reference
            else:
                if len(v) >= 3 and v[2] is not None:
                    limit = v[2]

                if hasattr(v[0], "read"):
                    f = v[0]  # file-like object
                else:
                    # hard to change, pylint: disable=consider-using-with
                    f = open(v[0], "rb")  # file name
                while True:
                    block = f.read(1048576)
                    size += len(block)
                    crc = zlib.crc32(block, crc)
                    if limit is not None:
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
                            file.write(b"\n ")
                    else:
                        break
                if not hasattr(v[0], "read"):
                    f.close()

                if len(v) >= 4 and v[3]:
                    if size == 0:
                        raise OSError(
                            "did not get any data for field %s from %s"
                            % (k, str(v[0]))
                        )

            # flush compressor and write the rest
            if not limit or size <= limit:
                block = bc.flush()
                # append gzip trailer: crc (32 bit) and size (32 bit)
                if crc:
                    block += struct.pack("<L", crc & 0xFFFFFFFF)
                    block += struct.pack("<L", size & 0xFFFFFFFF)

                file.write(base64.b64encode(block))
                file.write(b"\n")

    def add_to_existing(self, reportfile, keep_times=False):
        """Add this report's data to an already existing report file.

        The file will be temporarily chmod'ed to 000 to prevent frontends
        from picking up a hal-updated report file. If keep_times
        is True, then the file's atime and mtime restored after updating.
        """
        st = os.stat(reportfile)
        try:
            with open(reportfile, "ab") as report:
                os.chmod(reportfile, 0)
                self.write(report)
        finally:
            if keep_times:
                os.utime(reportfile, (st.st_atime, st.st_mtime))
            os.chmod(reportfile, st.st_mode)

    def write_mime(
        self,
        file,
        attach_treshold=5,
        extra_headers=None,
        skip_keys=None,
        priority_fields=None,
    ):
        """Write MIME/Multipart RFC 2822 formatted data into file.

        file must be a file-like object, not a path.  It needs to be opened in
        binary mode.

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
        """
        self._assert_bin_mode(file)

        keys = sorted(self.data.keys())

        text = ""
        attachments = []

        if "ProblemType" in keys:
            keys.remove("ProblemType")
            keys.insert(0, "ProblemType")

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
            elif not hasattr(v, "find"):
                attach_value = ""
                if hasattr(v[0], "read"):
                    f = v[0]  # file-like object
                else:
                    # hard to change, pylint: disable=consider-using-with
                    f = open(v[0], "rb")  # file name
                if k.endswith(".gz"):
                    attach_value = f.read()
                else:
                    out = io.BytesIO()
                    gf = gzip.GzipFile(k, mode="wb", fileobj=out, mtime=0)
                    while True:
                        block = f.read(1048576)
                        if block:
                            gf.write(block)
                        else:
                            gf.close()
                            break
                    attach_value = out.getvalue()
                f.close()

            # binary value
            elif self.is_binary(v):
                if k.endswith(".gz"):
                    attach_value = v
                else:
                    attach_value = CompressedValue(v, k).gzipvalue

            # if we have an attachment value, create an attachment
            if attach_value:
                att = email.mime.base.MIMEBase("application", "x-gzip")
                if k.endswith(".gz"):
                    att.add_header(
                        "Content-Disposition", "attachment", filename=k
                    )
                else:
                    att.add_header(
                        "Content-Disposition", "attachment", filename=k + ".gz"
                    )
                att.set_payload(attach_value)
                email.encoders.encode_base64(att)
                attachments.append(att)
            else:
                # plain text value
                size = len(v)

                # ensure that byte arrays are valid UTF-8
                if isinstance(v, bytes):
                    v = v.decode("UTF-8", "replace")
                # convert unicode to UTF-8 str
                assert isinstance(v, str)

                lines = len(v.splitlines())
                if size <= 1000 and lines == 1:
                    v = v.rstrip()
                    text += k + ": " + v + "\n"
                elif size <= 1000 and lines <= attach_treshold:
                    text += k + ":\n "
                    if not v.endswith("\n"):
                        v += "\n"
                    text += v.strip().replace("\n", "\n ") + "\n"
                else:
                    # too large, separate attachment
                    att = email.mime.text.MIMEText(v, _charset="UTF-8")
                    att.add_header(
                        "Content-Disposition",
                        "attachment",
                        filename=k + ".txt",
                    )
                    attachments.append(att)

        # create initial text attachment
        att = email.mime.text.MIMEText(text, _charset="UTF-8")
        att.add_header("Content-Disposition", "inline")
        attachments.insert(0, att)

        msg = email.mime.multipart.MIMEMultipart()
        if extra_headers:
            for k, v in extra_headers.items():
                msg.add_header(k, v)
        for a in attachments:
            msg.attach(a)

        file.write(msg.as_string().encode("UTF-8"))
        file.write(b"\n")

    def __setitem__(self, k, v):
        assert hasattr(k, "isalnum")
        if not k.replace(".", "").replace("-", "").replace("_", "").isalnum():
            raise ValueError(
                "key '%s' contains invalid characters"
                " (only numbers, letters, '.', '_', and '-' are allowed)" % k
            )
        # value must be a string or a CompressedValue or a file reference
        # (tuple (string|file [, bool, [, max_size [, fail_on_empty]]]))
        if not (
            isinstance(v, CompressedValue)
            or hasattr(v, "isalnum")
            or (
                isinstance(v, tuple)
                and (
                    len(v) == 1
                    or (len(v) >= 2 and len(v) <= 4 and v[1] in (True, False))
                )
                and (hasattr(v[0], "isalnum") or hasattr(v[0], "read"))
            )
        ):
            raise TypeError(
                "value for key %s must be a string, CompressedValue,"
                " or a file reference" % k
            )

        return self.data.__setitem__(k, v)

    def new_keys(self):
        """Return newly added keys.

        Return the set of keys which have been added to the report since it
        was constructed or loaded.
        """
        return set(self.data.keys()) - self.old_keys

    @staticmethod
    def _strip_gzip_header(line):
        """Strip gzip header from line and return the rest."""
        flags = line[3]
        offset = 10
        if flags & 4:  # FLG.FEXTRA
            offset += line[offset] + 1
        if flags & 8:  # FLG.FNAME
            while line[offset] != 0:
                offset += 1
            offset += 1
        if flags & 16:  # FLG.FCOMMENT
            while line[offset] != 0:
                offset += 1
            offset += 1
        if flags & 2:  # FLG.FHCRC
            offset += 2

        return line[offset:]

    @staticmethod
    def _assert_bin_mode(file):
        """Assert that given file object is in binary mode."""
        assert not hasattr(
            file, "encoding"
        ), "file stream must be in binary mode"
