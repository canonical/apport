"""Store, load, and handle problem reports."""

# Copyright (C) 2006 - 2012 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import base64
import binascii
import collections
import dataclasses
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
from collections.abc import Generator, Iterable, Iterator

# magic number (0x1F 0x8B) and compression method (0x08 for DEFLATE)
GZIP_HEADER_START = b"\037\213\010"
ZSTANDARD_MAGIC_NUMBER = b"\x28\xB5\x2F\xFD"


class MalformedProblemReport(ValueError):
    """Raised when a problem report violates the crash report format.

    This exception might be raised when the keys of the report are not ASCII.
    """

    def __init__(self, message: str, *args: object):
        super().__init__(
            f"Malformed problem report: {message}."
            f" Is this a proper .crash text file?",
            *args,
        )


class _SizeLimitExceeded(RuntimeError):
    """Raised internally to signal a value that is too big to encode."""


class _EntryParser(Iterator):
    """Iterator over entries in RFC822 formatted files.

    This iterator reads ahead one line to determine the boundaries between
    the entries. Each returned entry is a line-based iterator.
    """

    def __init__(self, iterator: Iterator[bytes]) -> None:
        self.iterator = iterator
        self.next_line: bytes | None = None
        self.entry_read = True

    def entry_iterator(self) -> Iterator[bytes]:
        """Iterate over all lines of one entry."""
        assert self.next_line
        yield self.next_line
        self.next_line = None
        for line in self.iterator:
            if line.startswith(b" "):
                yield line
            else:
                self.next_line = line
                break
        self.entry_read = True

    def __next__(self) -> Iterator[bytes]:
        if not self.entry_read:
            for _ in self.entry_iterator():
                pass
        if not self.next_line:
            self.next_line = next(self.iterator)
        self.entry_read = False
        return self.entry_iterator()


def _base64_decoder(entry: Iterable[bytes]) -> Iterator[bytes]:
    for line in entry:
        try:
            yield base64.b64decode(line)
        except binascii.Error as error:
            raise MalformedProblemReport(str(error)) from None


def _strip_gzip_header(line: bytes) -> bytes:
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


def _text_decoder(entry: Iterator[bytes], first_line: bytes) -> Iterator[bytes]:
    line = first_line.strip()
    yield line
    length = len(line)
    for line in entry:
        if length > 0:
            yield b"\n"
        if line.endswith(b"\n"):
            yield line[1:-1]
            length += len(line) - 2
        else:
            yield line[1:]
            length += len(line) - 1


def _get_zstandard_decompressor():
    try:
        # pylint: disable-next=import-outside-toplevel
        import zstandard
    except ImportError as error:
        raise RuntimeError(
            f"Failed to import zstandard library: {error}."
            f" Please install python3-zstandard."
        ) from None
    return zstandard.ZstdDecompressor()


def _zstandard_decoder(entry: Iterator[bytes], first_block: bytes) -> Iterator[bytes]:
    decompressor = _get_zstandard_decompressor().decompressobj()
    yield decompressor.decompress(first_block)
    for block in entry:
        yield decompressor.decompress(block)


def _parse_entry(entry: Iterator[bytes]) -> tuple[str, Iterator[bytes], bool]:
    """Parse the given entry and return key and value.

    Return the key and a line iterator over the value. Also return a
    boolean if the entry is base64 encoded (i.e. is a binary value).
    """
    first_line = next(entry)
    try:
        (key_in_bytes, first_line_value) = first_line.split(b":", 1)
    except ValueError:
        raise MalformedProblemReport(
            f"Line {first_line.decode(errors='backslashreplace')!r}"
            f" does not contain a colon for separating"
            f" the key from the value"
        ) from None

    try:
        key = key_in_bytes.decode("ASCII")
    except UnicodeDecodeError as error:
        raise MalformedProblemReport(str(error)) from None

    base64_encoded = first_line_value.strip() == b"base64"
    if base64_encoded:
        value_iterator = _base64_decoder(entry)
    else:
        value_iterator = _text_decoder(entry, first_line_value)

    return key, value_iterator, base64_encoded


@dataclasses.dataclass
class CompressedFile:
    """Represents a ProblemReport value which points to a compressed file.

    The file is expected to be compressed with gzip or zstandard.
    """

    filename: str

    def __init__(self, filename: str) -> None:
        self.filename = filename
        # pylint: disable-next=consider-using-with
        self._compressed_file = open(self.filename, "rb")

    def __del__(self):
        if hasattr(self, "_compressed_file"):
            self._compressed_file.close()

    def iter_compressed(self) -> Iterator[bytes]:
        """Iterate over the compressed content of the file in 1 MB chunks."""
        while True:
            block = self._compressed_file.read(1048576)
            if not block:
                break
            yield block

    def is_readable(self) -> bool:
        """Check if the compressed file is readable by the effective user."""
        return os.access(self.filename, os.R_OK, effective_ids=True)


class CompressedValue:
    """Represent a ProblemReport value which is gzip or zstandard compressed.

    By default, compressed values are in gzip format. Earlier versions of
    problem_report used zlib format (without gzip header).
    """

    def __init__(
        self,
        value: bytes | None = None,
        name: str | None = None,
        compressed_value: bytes | None = None,
    ) -> None:
        """Initialize an empty CompressedValue object with an optional name."""
        self.compressed_value = compressed_value
        self.name = name
        if value:
            self.set_value(value)

    def set_value(self, value: bytes) -> None:
        """Set uncompressed value."""
        out = io.BytesIO()
        with gzip.GzipFile(self.name, mode="wb", fileobj=out, mtime=0) as gz:
            gz.write(value)
        self.compressed_value = out.getvalue()

    def get_compressed_size(self) -> int:
        """Return size of the compressed (but not base64 encoded) value."""
        assert self.compressed_value is not None
        return len(self.compressed_value)

    def get_on_disk_size(self) -> int:
        """Return the size needed on disk to store the compressed value.

        The compressed value will be base64 encoded when written to disk
        which adds an overhead of 1/3 plus up to 2 bytes of padding. Additional
        spaces and newlines are ignored in this calculation.
        """
        return ((self.get_compressed_size() + 2) // 3) * 4

    @staticmethod
    def decode_compressed_stream(entry: Iterator[bytes]) -> Iterator[bytes]:
        """Decode the given compressed value (iterator version)."""
        block = next(entry, None)
        if block is None:
            return
        if block.startswith(ZSTANDARD_MAGIC_NUMBER):
            yield from _zstandard_decoder(entry, block)
            return
        # skip gzip header, if present
        if block.startswith(GZIP_HEADER_START):
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            yield decompressor.decompress(_strip_gzip_header(block))
        else:
            # legacy zlib-only format used default block size
            decompressor = zlib.decompressobj()
            yield decompressor.decompress(block)

        for block in entry:
            yield decompressor.decompress(block)
        yield decompressor.flush()

    def get_value(self) -> bytes:
        """Return uncompressed value."""
        assert self.compressed_value is not None

        if self.compressed_value.startswith(ZSTANDARD_MAGIC_NUMBER):
            return _get_zstandard_decompressor().decompress(self.compressed_value)
        if self.compressed_value.startswith(GZIP_HEADER_START):
            return gzip.decompress(self.compressed_value)
        # legacy zlib format
        return zlib.decompress(self.compressed_value)

    def write(self, file: typing.BinaryIO) -> None:
        """Write uncompressed value into given file-like object."""
        assert self.compressed_value

        if self.compressed_value.startswith(ZSTANDARD_MAGIC_NUMBER):
            decompressor = _get_zstandard_decompressor()
            decompressor.copy_stream(io.BytesIO(self.compressed_value), file)
            return

        if self.compressed_value.startswith(GZIP_HEADER_START):
            with gzip.GzipFile(fileobj=io.BytesIO(self.compressed_value)) as gz:
                while True:
                    block = gz.read(1048576)
                    if not block:
                        break
                    file.write(block)
                return

        # legacy zlib format
        file.write(zlib.decompress(self.compressed_value))

    def __len__(self) -> int:
        """Return length of uncompressed value."""
        assert self.compressed_value
        if self.compressed_value.startswith(GZIP_HEADER_START):
            return int(struct.unpack("<L", self.compressed_value[-4:])[0])
        # legacy zlib format
        return len(self.get_value())

    def splitlines(self) -> list[bytes]:
        """Behaves like splitlines() for a normal string."""
        return self.get_value().splitlines()


class ProblemReport(collections.UserDict):
    """Class to store, load, and handle problem reports."""

    def __init__(self, problem_type: str = "Crash", date: str | None = None) -> None:
        """Initialize a fresh problem report.

        problem_type can be 'Crash', 'Packaging', 'KernelCrash' or
        'KernelOops'. date is the desired date/time string; if
        None (default), the current local time is used.
        """
        if date is None:
            date = time.asctime()
        super().__init__({"ProblemType": problem_type, "Date": date})

        # keeps track of keys which were added since the last ctor or load()
        self.old_keys: set[str] = set()

    def add_tags(self, tags: Iterable[str]) -> None:
        """Add tags to the report. Duplicates are dropped."""
        current_tags = self.get_tags()
        new_tags = current_tags.union(tags)
        self["Tags"] = " ".join(sorted(new_tags))

    def load(
        self,
        file: gzip.GzipFile | typing.BinaryIO,
        binary: bool | typing.Literal["compressed"] = True,
        key_filter: Iterable[str] | None = None,
    ) -> None:
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
        if key_filter:
            remaining_keys = set(key_filter)
        else:
            remaining_keys = None

        for entry in _EntryParser(file):
            key, iterator, base64_encoded = _parse_entry(entry)
            if remaining_keys is not None and key not in remaining_keys:
                continue

            if base64_encoded:
                if binary is False:
                    self.data[key] = None
                elif binary == "compressed":
                    self.data[key] = CompressedValue(
                        name=key, compressed_value=b"".join(iterator)
                    )
                else:
                    self.data[key] = self._try_unicode(
                        b"".join(CompressedValue.decode_compressed_stream(iterator))
                    )

            else:
                self.data[key] = self._try_unicode(b"".join(iterator))

            if remaining_keys is not None:
                remaining_keys.remove(key)
                if len(remaining_keys) == 0:
                    break

        self.old_keys = set(self.data.keys())

    def extract_keys(
        self,
        file: gzip.GzipFile | typing.BinaryIO,
        bin_keys: Iterable[str] | str,
        directory: str,
    ) -> None:
        """Extract only given binary elements from the problem report.

        Binary elements like kernel crash dumps can be very big. This method
        extracts directly files without loading the report into memory.
        """
        self._assert_bin_mode(file)
        # support single key and collection of keys
        if isinstance(bin_keys, str):
            bin_keys = [bin_keys]
        missing_keys = list(bin_keys)
        b64_block = {}

        for entry in _EntryParser(file):
            key, iterator, base64_encoded = _parse_entry(entry)
            if key not in missing_keys:
                continue

            b64_block[key] = base64_encoded
            missing_keys.remove(key)
            if not base64_encoded:
                continue

            key_path = os.path.join(directory, key)
            try:
                with open(key_path, "wb") as out:
                    for block in CompressedValue.decode_compressed_stream(iterator):
                        out.write(block)
            except OSError as error:
                raise OSError(f"unable to open {key_path}") from error

        if missing_keys:
            raise KeyError(f"Cannot find {', '.join(missing_keys)} in report")
        if False in b64_block.values():
            items = [item for item, element in b64_block.items() if element is False]
            raise ValueError(f"{items} has no binary content")

    def get_tags(self) -> set[str]:
        """Return the set of tags."""
        if "Tags" not in self:
            return set()
        return set(self["Tags"].split(" "))

    def get_timestamp(self) -> int | None:
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

    def has_removed_fields(self) -> bool:
        """Check if the report has any keys which were not loaded.

        This could happen when using binary=False in load().
        """
        return None in self.values()

    @staticmethod
    def is_binary(string: bytes | str) -> bool:
        """Check if the given strings contains binary data."""
        if isinstance(string, bytes):
            for c in string:
                if c < 32 and not chr(c).isspace():
                    return True
        return False

    @classmethod
    def _try_unicode(cls, value: bytes | str) -> bytes | str:
        """Try to convert bytearray value to Unicode."""
        if isinstance(value, bytes) and not cls.is_binary(value):
            try:
                return value.decode("UTF-8")
            except UnicodeDecodeError:
                return value
        return value

    def sorted_items(
        self, keys: Iterable[str] | None = None
    ) -> Iterator[tuple[str, (bytes | CompressedValue | str | tuple)]]:
        """Iterate over all non-internal items sorted.

        The most interesting fields will be returned first. The remaining
        items will be returned in alphabetical order. Keys starting with
        an underscore are considered internal and are skipped. Also values
        that are None will be skipped.

        If keys is provided, only those keys will be iterated over.
        """
        if keys:
            keys = sorted(set(self.keys()) & set(keys))
        else:
            keys = sorted(self.keys())
        # show the most interesting items on top
        for key in (
            "Traceback",
            "StackTrace",
            "Title",
            "ProblemType",
            "Package",
            "ExecutablePath",
        ):
            if key in keys:
                keys.remove(key)
                keys.insert(0, key)
        for key in keys:
            # ignore internal keys
            if key.startswith("_"):
                continue
            value = self[key]
            if value is None:
                continue
            yield key, self[key]

    def write(self, file: typing.BinaryIO, only_new: bool = False) -> None:
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

        asckeys, binkeys = self._get_sorted_keys(only_new)

        for k in asckeys:
            self._write_ascii_item(file, k)

        for k in binkeys:
            self._write_binary_item_compressed_and_encoded(file, k)

    def _get_sorted_keys(self, only_new: bool) -> tuple[list[str], list[str]]:
        """Sort keys into ASCII non-ASCII/binary attachment ones, so that
        the base64 ones appear last in the report
        """
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
            elif (
                not isinstance(v, (CompressedFile, CompressedValue))
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
        return asckeys, binkeys

    def _write_ascii_item(self, file: typing.BinaryIO, key: str) -> None:
        v = self.data[key]

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
                raise OSError("did not get any data for field " + key)

            if limit is not None and len(v) > limit:
                del self.data[key]
                return

        if isinstance(v, str):
            # unicode → str
            v = v.encode("UTF-8")

        file.write(key.encode("ASCII"))
        if b"\n" in v:
            # multiline value
            file.write(b":\n ")
            file.write(v.replace(b"\n", b"\n "))
        else:
            file.write(b": ")
            file.write(v)
        file.write(b"\n")

    @staticmethod
    def _write_binary_item_base64_encoded(
        file: typing.BinaryIO, key: str, chunks: Iterable[bytes]
    ) -> None:
        """Write out binary chunks as a base64-encoded RFC822 multiline field."""
        reset_position = file.tell()
        try:
            file.write(f"{key}: base64".encode("ASCII"))
            for chunk in chunks:
                file.write(b"\n ")
                file.write(base64.b64encode(chunk))
            file.write(b"\n")
        except Exception:
            file.seek(reset_position)
            file.truncate(reset_position)
            raise

    def _generate_compressed_chunks(self, key: str) -> Generator[bytes, None, None]:
        """Generator taking the value out of self.data and outputing it
        in compressed chunks of binary data.

        Throws a _SizeLimitExceeded exception if the value exceeds its specified
        size limit, in which case it will also remove the value from self.data entirely.
        """
        # TODO: split into smaller subgenerators
        # pylint: disable=too-many-branches
        value = self.data[key]
        if isinstance(value, CompressedFile):
            yield from value.iter_compressed()
            return
        if isinstance(value, CompressedValue):
            assert value.compressed_value is not None
            yield value.compressed_value
            return
        gzip_header = (
            GZIP_HEADER_START
            + b"\010\000\000\000\000\002\377"
            + key.encode("UTF-8")
            + b"\000"
        )
        yield gzip_header

        crc = zlib.crc32(b"")
        bc = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS, zlib.DEF_MEM_LEVEL, 0)
        size = 0

        # direct value
        if hasattr(value, "find"):
            size += len(value)
            crc = zlib.crc32(value, crc)
            outblock = bc.compress(value)
            if outblock:
                yield outblock
        # file reference
        else:
            limit = None
            if len(value) >= 3 and value[2] is not None:
                limit = value[2]

            if hasattr(value[0], "read"):
                f = value[0]  # file-like object
            else:
                # hard to change, pylint: disable=consider-using-with
                f = open(value[0], "rb")  # file name
            while True:
                block = f.read(1048576)
                size += len(block)
                crc = zlib.crc32(block, crc)
                if limit is not None:
                    if size > limit:
                        del self.data[key]
                        raise _SizeLimitExceeded(
                            "Binary data bigger than the limit ({limit}b)"
                        )
                if block:
                    outblock = bc.compress(block)
                    if outblock:
                        yield outblock
                else:
                    break
            if not hasattr(value[0], "read"):
                f.close()

            if len(value) >= 4 and value[3]:
                if size == 0:
                    raise OSError(
                        f"did not get any data for field {key} from {str(value[0])}"
                    )

        # flush compressor and write the rest
        block = bc.flush()
        # append gzip trailer: crc (32 bit) and size (32 bit)
        block += struct.pack("<L", crc & 0xFFFFFFFF)
        block += struct.pack("<L", size & 0xFFFFFFFF)
        yield block

    def _write_binary_item_compressed_and_encoded(
        self, file: typing.BinaryIO, key: str
    ) -> None:
        """Write the binary keys with gzip compression and base64 encoding"""
        try:
            self._write_binary_item_base64_encoded(
                file, key, self._generate_compressed_chunks(key)
            )
        except _SizeLimitExceeded:
            # TODO: this should be logged out!
            pass

    def add_to_existing(self, reportfile: str, keep_times: bool = False) -> None:
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
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-locals,too-many-statements
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
                attach_value = v.compressed_value

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
                    with gzip.GzipFile(k, mode="wb", fileobj=out, mtime=0) as gz:
                        while True:
                            block = f.read(1048576)
                            if block:
                                gz.write(block)
                            else:
                                break
                    attach_value = out.getvalue()
                f.close()

            # binary value
            elif self.is_binary(v):
                if k.endswith(".gz"):
                    attach_value = v
                else:
                    attach_value = CompressedValue(v, k).compressed_value

            # if we have an attachment value, create an attachment
            if attach_value:
                att = email.mime.base.MIMEBase("application", "x-gzip")
                if k.endswith(".gz"):
                    att.add_header("Content-Disposition", "attachment", filename=k)
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
                        "Content-Disposition", "attachment", filename=k + ".txt"
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

    def __setitem__(
        self, k: str, v: bytes | CompressedFile | CompressedValue | str | tuple
    ) -> None:
        assert hasattr(k, "isalnum")
        if not k.replace(".", "").replace("-", "").replace("_", "").isalnum():
            raise ValueError(
                f"key '{k}' contains invalid characters"
                f" (only numbers, letters, '.', '_', and '-' are allowed)"
            )
        # value must be a string or a CompressedValue or a file reference
        # (tuple (string|file [, bool, [, max_size [, fail_on_empty]]]))
        if not (
            isinstance(v, (CompressedFile, CompressedValue))
            or hasattr(v, "isalnum")
            or (
                isinstance(v, tuple)
                and (
                    len(v) == 1
                    or (len(v) >= 2 and len(v) <= 4 and v[1] in {True, False})
                )
                and (hasattr(v[0], "isalnum") or hasattr(v[0], "read"))
            )
        ):
            raise TypeError(
                f"value for key {k} must be a string, CompressedValue,"
                f" or a file reference"
            )

        return self.data.__setitem__(k, v)

    def new_keys(self) -> set[str]:
        """Return newly added keys.

        Return the set of keys which have been added to the report since it
        was constructed or loaded.
        """
        return set(self.data.keys()) - self.old_keys

    @staticmethod
    def _assert_bin_mode(file: object) -> None:
        """Assert that given file object is in binary mode."""
        assert not hasattr(file, "encoding"), "file stream must be in binary mode"
