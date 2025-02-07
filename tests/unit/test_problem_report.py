"""Unit tests for the problem_report module."""

# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import base64
import contextlib
import datetime
import email
import io
import locale
import sys
import textwrap
import time
import unittest
import unittest.mock
from unittest.mock import MagicMock

try:
    import zstandard
except ImportError:
    zstandard = None  # type: ignore

import problem_report

bin_data = b"ABABABABAB\0\0\0Z\x01\x02"


class T(unittest.TestCase):  # pylint: disable=too-many-public-methods
    """Unit tests for the problem_report module."""

    def test_add_tags(self) -> None:
        """Test ProblemReport.add_tags()."""
        report = problem_report.ProblemReport()
        report.add_tags({"tag1"})
        self.assertEqual(report["Tags"], "tag1")
        report.add_tags(["tag2", "next_tag"])
        self.assertEqual(report["Tags"], "next_tag tag1 tag2")

    def test_add_tag_drop_duplicates(self) -> None:
        """Test ProblemReport.add_tags() dropping duplicates."""
        report = problem_report.ProblemReport()
        report.add_tags({"same"})
        self.assertEqual(report["Tags"], "same")
        report.add_tags(["same"])
        self.assertEqual(report["Tags"], "same")

    def test_basic_operations(self) -> None:
        """Basic creation and operation."""
        pr = problem_report.ProblemReport()
        pr["foo"] = "bar"
        pr["bar"] = " foo   bar\nbaz\n   blip  "
        pr["dash-key"] = "1"
        pr["dot.key"] = "1"
        pr["underscore_key"] = "1"
        self.assertEqual(pr["foo"], "bar")
        self.assertEqual(pr["bar"], " foo   bar\nbaz\n   blip  ")
        self.assertEqual(pr["ProblemType"], "Crash")
        locale_time = locale.getlocale(locale.LC_TIME)
        locale.setlocale(locale.LC_TIME, "C")
        try:
            self.assertTrue(time.strptime(pr["Date"]))
        finally:
            locale.setlocale(locale.LC_TIME, locale_time)
        self.assertEqual(pr["dash-key"], "1")
        self.assertEqual(pr["dot.key"], "1")
        self.assertEqual(pr["underscore_key"], "1")

    def test_ctor_arguments(self) -> None:
        """non-default constructor arguments."""
        pr = problem_report.ProblemReport("KernelCrash")
        self.assertEqual(pr["ProblemType"], "KernelCrash")
        pr = problem_report.ProblemReport(date="19801224 12:34")
        self.assertEqual(pr["Date"], "19801224 12:34")

    def test_get_timestamp(self) -> None:
        """get_timestamp() returns timestamp."""
        r = problem_report.ProblemReport()
        timestamp = r.get_timestamp()
        assert timestamp
        self.assertAlmostEqual(timestamp, time.time(), delta=2)

        r["Date"] = "Thu Jan 9 12:00:00 2014"
        # delta is ±12 hours, as this depends on the timezone that the test is
        # run in
        timestamp = r.get_timestamp()
        assert timestamp
        self.assertAlmostEqual(timestamp, 1389265200, delta=43200)

    def test_get_timestamp_locale_german(self) -> None:
        """get_timestamp() returns date when LC_TIME is set."""
        now = datetime.datetime.now()

        pr = problem_report.ProblemReport(date=now.strftime("%a %b %d %H:%M:%S %Y"))
        orig_ctime = locale.getlocale(locale.LC_TIME)
        try:
            locale.setlocale(locale.LC_TIME, "de_DE.UTF-8")
        except locale.Error:
            self.skipTest("Missing German locale support")
        self.assertEqual(pr.get_timestamp(), int(now.timestamp()))
        locale.setlocale(locale.LC_TIME, orig_ctime)

    def test_get_timestamp_returns_none(self) -> None:
        """get_timestamp() returns None."""
        pr = problem_report.ProblemReport()
        del pr["Date"]
        self.assertIsNone(pr.get_timestamp())

    def test_consistency_checks(self) -> None:
        """Various error conditions."""
        pr = problem_report.ProblemReport()
        self.assertRaises(ValueError, pr.__setitem__, "a b", "1")
        self.assertRaises(TypeError, pr.__setitem__, "a", 1)
        self.assertRaises(TypeError, pr.__setitem__, "a", (1,))
        self.assertRaises(TypeError, pr.__setitem__, "a", ("/tmp/nonexistent", ""))
        self.assertRaises(
            TypeError,
            pr.__setitem__,
            "a",
            ("/tmp/nonexistent", False, 0, True, "bogus"),
        )
        self.assertRaises(TypeError, pr.__setitem__, "a", ["/tmp/nonexistent"])
        self.assertRaises(KeyError, pr.__getitem__, "Nonexistent")

    def test_write(self) -> None:
        """write() and proper formatting."""
        pr = problem_report.ProblemReport(date="now!")
        pr["Simple"] = "bar"
        pr["SimpleUTF8"] = "1äö2Φ3".encode("UTF-8")
        pr["SimpleUnicode"] = "1äö2Φ3"
        pr["TwoLineUnicode"] = "pi-π\nnu-η"
        pr["TwoLineUTF8"] = "pi-π\nnu-η".encode("UTF-8")
        pr["WhiteSpace"] = " foo   bar\nbaz\n  blip  \n\nafteremptyline"
        # Unicode with a non-space low ASCII character \x05 in it
        pr["UnprintableUnicode"] = b"a\xc3\xa4\x05z1\xc3\xa9".decode("UTF-8")
        out = io.BytesIO()
        pr.write(out)
        expected = (
            textwrap.dedent(
                """\
                ProblemType: Crash
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
                UnprintableUnicode: aä\x05z1é
                WhiteSpace:
                """
            )
            + "  foo   bar\n baz\n   blip  \n \n afteremptyline\n"
        ).encode("UTF-8")
        self.assertEqual(out.getvalue(), expected)

    def test_load(self) -> None:
        """load() with various formatting."""
        report = textwrap.dedent(
            f"""\
            ProblemType: Crash
            Date: now!
            Simple: bar
            WhiteSpace:
              foo   bar
             baz
               blip{'  '}
            """
        )
        pr = problem_report.ProblemReport()
        pr.load(io.BytesIO(report.encode()))
        self.assertEqual(pr["ProblemType"], "Crash")
        self.assertEqual(pr["Date"], "now!")
        self.assertEqual(pr["Simple"], "bar")
        self.assertEqual(pr["WhiteSpace"], " foo   bar\nbaz\n  blip  ")

        # test last field a bit more
        report += " \n"
        pr.load(io.BytesIO(report.encode()))
        self.assertEqual(pr["ProblemType"], "Crash")
        self.assertEqual(pr["Date"], "now!")
        self.assertEqual(pr["Simple"], "bar")
        self.assertEqual(pr["WhiteSpace"], " foo   bar\nbaz\n  blip  \n")

        # last field might not be \n terminated
        pr.load(
            io.BytesIO(
                textwrap.dedent(
                    """\
                    ProblemType: Crash
                    Date: now!
                    Simple: bar
                    WhiteSpace:
                     foo
                     bar"""
                ).encode()
            )
        )
        self.assertEqual(pr["ProblemType"], "Crash")
        self.assertEqual(pr["Date"], "now!")
        self.assertEqual(pr["Simple"], "bar")
        self.assertEqual(pr["WhiteSpace"], "foo\nbar")

        report = (
            "ProblemType: Crash\n"
            "WhiteSpace:\n"
            "  foo   bar\n"
            " baz\n"
            " \n"
            "   blip  \n"
            "Last: foo\n"
        )
        pr = problem_report.ProblemReport()
        pr.load(io.BytesIO(report.encode()))
        self.assertEqual(pr["WhiteSpace"], " foo   bar\nbaz\n\n  blip  ")
        self.assertEqual(pr["Last"], "foo")

        report += " \n"
        pr = problem_report.ProblemReport()
        pr.load(io.BytesIO(report.encode()))
        self.assertEqual(pr["WhiteSpace"], " foo   bar\nbaz\n\n  blip  ")
        self.assertEqual(pr["Last"], "foo\n")

        # empty lines in values must have a leading space in coding
        invalid_spacing = io.BytesIO(
            textwrap.dedent(
                """\
                WhiteSpace:
                 first

                 second
                """
            ).encode()
        )
        pr = problem_report.ProblemReport()
        self.assertRaises(ValueError, pr.load, invalid_spacing)

        # test that load() cleans up properly
        pr.load(io.BytesIO(b"ProblemType: Crash"))
        self.assertEqual(list(pr.keys()), ["ProblemType"])

    def test_load_binary_blob(self) -> None:
        """Throw exception when binary file (e.g. core) is loaded."""
        report = problem_report.ProblemReport()
        with io.BytesIO(b"AB\xfc:CD") as report_file:
            with self.assertRaisesRegex(
                problem_report.MalformedProblemReport,
                "codec can't decode byte 0xfc in position 2",
            ):
                report.load(report_file)

    def test_load_missing_colon(self) -> None:
        """Throw exception when key-value line misses a colon as separator."""
        report = problem_report.ProblemReport()
        with io.BytesIO(b"\n") as report_file:
            with self.assertRaisesRegex(
                problem_report.MalformedProblemReport,
                r"Line '\\n' does not contain a colon",
            ):
                report.load(report_file)

    def test_load_invalid_utf8(self) -> None:
        """Throw exception when binary file is invalid UTF-8."""
        report = problem_report.ProblemReport()
        with io.BytesIO(b"\x7fELF\x02\x01\xb0j") as report_file:
            with self.assertRaisesRegex(
                problem_report.MalformedProblemReport,
                r"Line '\\x7fELF\\x02\\x01\\\\xb0j' does not contain a colon",
            ):
                report.load(report_file)

    def test_load_incorrect_padding(self) -> None:
        """Throw exception when base64 encoded data has incorrect padding."""
        report = problem_report.ProblemReport()
        content = (
            b"CoreDump: base64\n"
            b" H4sICAAAAAAC/0NvcmVEdW1wAA==\n"
            b" 7Z0LYFPV/cdP0rQ\n"
        )
        with io.BytesIO(content) as report_file:
            with self.assertRaisesRegex(
                problem_report.MalformedProblemReport,
                "^Malformed problem report: Incorrect padding."
                " Is this a proper .crash text file\\?$",
            ):
                report.load(report_file)

    @unittest.skipUnless(zstandard, "zstandard Python module not available")
    def test_load_zstd_compressed_data(self) -> None:
        """Test reading zstd-compressed data."""
        report = problem_report.ProblemReport()
        content = (
            b"CoreDump: base64\n"
            b" KLUv/SROHQIAgoQOEqC7ASCSGCybZRrN7//Hsn7dVyActu7bbMcLaav0RC06\n"
            b" m6fCZ/N7aeOeyqxspRVn88bSx8a8opWQAwEA/8OEAhOOwLA=\n"
        )
        with io.BytesIO(content) as report_file:
            report.load(report_file)
        self.assertEqual(
            report["CoreDump"],
            "sample data that is compressed with zstd"
            " and is long enough for zstd to work.\n",
        )

    @unittest.skipUnless(zstandard, "zstandard Python module not available")
    def test_reading_zstd_compressed_value(self) -> None:
        """Test reading zstd-compressed CompressedValue."""
        report = problem_report.ProblemReport()
        content = (
            b"CoreDump: base64\n"
            b" KLUv/SRPHQIA8sQPFKClOoBIEkjIbmfbhiz9/1/96mYFATGiz9JHLfTZY9aV\n"
            b" a9QBRdQz0AkUjbdbVqNQorP3UpGC1NIi9X3UgygBAEyQcYs=\n"
        )
        with io.BytesIO(content) as report_file:
            report.load(report_file, binary="compressed")
        self.assertEqual(
            report["CoreDump"].get_value(),
            b"fake core dump data for testing purposes"
            b" which is long enough to be compressed\n",
        )

    @unittest.skipUnless(zstandard, "zstandard Python module not available")
    def test_writing_zstd_compressed_value(self) -> None:
        """Test writing zstd-compressed CompressedValue."""
        compressed_value = problem_report.CompressedValue(
            compressed_value=base64.b64decode(
                b"KLUv/SRCvQEAIsQMEMC3AbLcS0WaZ8rvf69jyw3ghpXr6pBr5i7HiCKroc60"
                b"3+tB4rC/4TV1osHyJUXme6IIAD6PTiM="
            )
        )
        output = io.BytesIO()
        compressed_value.write(output)
        self.assertEqual(
            output.getvalue(),
            b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam\n",
        )

    @unittest.skipUnless(zstandard, "zstandard Python module not available")
    def test_zstd_compressed_value_length(self) -> None:
        """Test getting length of zstd-compressed CompressedValue."""
        compressed_value = problem_report.CompressedValue(
            compressed_value=base64.b64decode(
                b"KLUv/SRB3QEAwoMMEbDrOJRilklIQlLIJC3OvFUMIIwdaHxrV6aSHEv6rFlP"
                b"/ll/IaXfo19actUkdvm8hggBAAlhlgHbiBMF"
            )
        )
        self.assertEqual(len(compressed_value), 65)

    @unittest.skipUnless(zstandard, "zstandard Python module not available")
    def test_len_zstd_compressed_value_nosize(self) -> None:
        """Test len() on zstd-compressed CompressedValue without a size header."""
        compressed_value = problem_report.CompressedValue(
            compressed_value=base64.b64decode(b"KLUv/QBYEQAAe30=")
        )
        self.assertEqual(len(compressed_value), 2)

    @unittest.mock.patch("builtins.__import__")
    def test_zstandard_missing(self, import_mock: MagicMock) -> None:
        """Test reading zstd-compressed data when zstandard is missing."""
        with contextlib.suppress(KeyError):
            sys.modules.pop("zstandard")
        import_mock.side_effect = ImportError("mocked import error")

        report = problem_report.ProblemReport()
        content = (
            b"CoreDump: base64\n"
            b" KLUv/SROHQIAgoQOEqC7ASCSGCybZRrN7//Hsn7dVyActu7bbMcLaav0RC06\n"
            b" m6fCZ/N7aeOeyqxspRVn88bSx8a8opWQAwEA/8OEAhOOwLA=\n"
        )
        expected_message = (
            "Failed to import zstandard library: mocked import error."
            " Please install python3-zstandard."
        )
        with self.assertRaisesRegex(RuntimeError, expected_message):
            with io.BytesIO(content) as report_file:
                report.load(report_file)

    def test_write_fileobj(self) -> None:
        """Write a report with a pointer to a file-like object."""
        tempbin = io.BytesIO(bin_data)
        tempasc = io.BytesIO(b"Hello World")

        pr = problem_report.ProblemReport(date="now!")
        pr["BinFile"] = (tempbin,)
        pr["AscFile"] = (tempasc, False)
        out = io.BytesIO()
        pr.write(out)
        out.seek(0)

        pr = problem_report.ProblemReport()
        pr.load(out)
        self.assertEqual(pr["BinFile"], tempbin.getvalue())
        self.assertEqual(pr["AscFile"], tempasc.getvalue().decode())

    def test_write_empty_fileobj(self) -> None:
        """Write a report with a pointer to a file-like object with
        enforcing non-emptyness."""
        tempbin = io.BytesIO(b"")
        tempasc = io.BytesIO(b"")

        pr = problem_report.ProblemReport(date="now!")
        pr["BinFile"] = (tempbin, True, None, True)
        out = io.BytesIO()
        self.assertRaises(OSError, pr.write, out)

        pr = problem_report.ProblemReport(date="now!")
        pr["AscFile"] = (tempasc, False, None, True)
        out = io.BytesIO()
        self.assertRaises(OSError, pr.write, out)

    def test_read_file(self) -> None:
        """Read a report with binary data."""
        bin_report = textwrap.dedent(
            """\
            ProblemType: Crash
            Date: now!
            File: base64
             H4sICAAAAAAC/0ZpbGUA
             c3RyhEIGBoYoRiYAM5XUCxAAAAA=
            Foo: Bar
            """
        ).encode()

        # test with reading everything
        pr = problem_report.ProblemReport()
        pr.load(io.BytesIO(bin_report))
        self.assertEqual(pr["File"], bin_data)
        self.assertEqual(pr.has_removed_fields(), False)

        # test with skipping binary data
        pr.load(io.BytesIO(bin_report), binary=False)
        self.assertIsNone(pr["File"])
        self.assertEqual(pr.has_removed_fields(), True)

        # test with keeping compressed binary data
        pr.load(io.BytesIO(bin_report), binary="compressed")
        self.assertEqual(pr["Foo"], "Bar")
        self.assertEqual(pr.has_removed_fields(), False)
        self.assertTrue(isinstance(pr["File"], problem_report.CompressedValue))
        self.assertEqual(len(pr["File"]), len(bin_data))
        self.assertEqual(pr["File"].get_value(), bin_data)
        self.assertEqual(pr["File"].name, "File")

    def test_read_file_legacy(self) -> None:
        """Read a report with binary data in legacy format without gzip
        header."""
        bin_report = textwrap.dedent(
            """\
            ProblemType: Crash
            Date: now!
            File: base64
             eJw=
             c3RyxIAMcBAFAG55BXk=
            Foo: Bar
            """
        ).encode()

        # test with reading everything
        pr = problem_report.ProblemReport()
        pr.load(io.BytesIO(bin_report))
        self.assertEqual(pr["File"], b"AB" * 10 + b"\0" * 10 + b"Z")
        self.assertEqual(pr.has_removed_fields(), False)

        # test with skipping binary data
        pr.load(io.BytesIO(bin_report), binary=False)
        self.assertIsNone(pr["File"])
        self.assertEqual(pr.has_removed_fields(), True)

        # test with keeping CompressedValues
        pr.load(io.BytesIO(bin_report), binary="compressed")
        self.assertEqual(pr.has_removed_fields(), False)
        self.assertEqual(len(pr["File"]), 31)
        self.assertEqual(pr["File"].get_value(), b"AB" * 10 + b"\0" * 10 + b"Z")
        self.assertEqual(pr["File"].name, "File")
        out = io.BytesIO()
        pr["File"].write(out)
        out.seek(0)
        self.assertEqual(out.read(), b"AB" * 10 + b"\0" * 10 + b"Z")

    def test_iter(self) -> None:
        """problem_report.ProblemReport iteration."""
        pr = problem_report.ProblemReport()
        pr["foo"] = "bar"

        keys = []
        for k in pr:
            keys.append(k)
        keys.sort()
        self.assertEqual(" ".join(keys), "Date ProblemType foo")

        self.assertEqual(len([k for k in pr if k != "foo"]), 2)

    def test_modify(self) -> None:
        """reading, modifying fields, and writing back."""
        report = textwrap.dedent(
            """\
            ProblemType: Crash
            Date: now!
            Long:
             xxx
             .
             yyy
            Short: Bar
            File: base64
             H4sICAAAAAAC/0ZpbGUA
             c3RyxIAMcBAFAK/2p9MfAAAA
            """
        ).encode()

        pr = problem_report.ProblemReport()
        pr.load(io.BytesIO(report))

        self.assertEqual(pr["Long"], "xxx\n.\nyyy")
        self.assertEqual(pr["Short"], "Bar")
        self.assertEqual(pr["File"], b"ABABABABABABABABABAB\0\0\0\0\0\0\0\0\0\0Z")

        # write back unmodified
        out = io.BytesIO()
        pr.write(out)
        self.assertEqual(out.getvalue(), report)

        pr["Short"] = "aaa\nbbb"
        pr["Long"] = "123"
        out = io.BytesIO()
        pr.write(out)
        self.assertEqual(
            out.getvalue(),
            textwrap.dedent(
                """\
                ProblemType: Crash
                Date: now!
                Long: 123
                Short:
                 aaa
                 bbb
                File: base64
                 H4sICAAAAAAC/0ZpbGUA
                 c3RyxIAMcBAFAK/2p9MfAAAA
                """
            ).encode(),
        )

    def test_sorted_items(self) -> None:
        """Test ProblemReport.sorted_items()."""
        bin_report = textwrap.dedent(
            """\
            ProblemType: Crash
            Date: now!
            File: base64
             eJw=
             c3RyxIAMcBAFAG55BXk=
            _MarkForUpload: False
            Architecture: amd64
            ExecutablePath: /usr/bin/python3
            Package: python3.12-minimal
            """
        ).encode()

        report = problem_report.ProblemReport()
        report.load(io.BytesIO(bin_report), binary=False)
        self.assertEqual(
            list(report.sorted_items()),
            [
                ("ExecutablePath", "/usr/bin/python3"),
                ("Package", "python3.12-minimal"),
                ("ProblemType", "Crash"),
                ("Architecture", "amd64"),
                ("Date", "now!"),
            ],
        )

    def test_write_mime_text(self) -> None:
        """write_mime() for text values."""
        pr = problem_report.ProblemReport(date="now!")
        pr["Simple"] = "bar"
        pr["SimpleUTF8"] = "1äö2Φ3".encode("UTF-8")
        pr["SimpleUnicode"] = "1äö2Φ3"
        pr["TwoLineUnicode"] = "pi-π\nnu-η\n"
        pr["TwoLineUTF8"] = "pi-π\nnu-η\n".encode("UTF-8")
        pr["SimpleLineEnd"] = "bar\n"
        pr["TwoLine"] = "first\nsecond\n"
        pr["InlineMargin"] = "first\nsecond\nthird\nfourth\nfifth\n"
        pr["Multiline"] = " foo   bar\nbaz\n  blip  \nline4\nline♥5!!\nłıµ€ ⅝\n"

        # still small enough for inline text
        pr["Largeline"] = "A" * 999
        pr["LargeMultiline"] = f"{'A' * 120}\n{'B' * 90}"

        # too big for inline text, these become attachments
        pr["Hugeline"] = "A" * 10000
        pr["HugeMultiline"] = f"{'A' * 900}\n{'B' * 900}\n{'C' * 900}"
        out = io.BytesIO()
        pr.write_mime(out)
        out.seek(0)

        msg = email.message_from_binary_file(out)
        parts = list(msg.walk())
        self.assertEqual(len(parts), 5)

        # first part is the multipart container
        self.assertTrue(parts[0].is_multipart())

        # second part should be an inline text/plain attachments with all short
        # fields
        self.assertTrue(not parts[1].is_multipart())
        self.assertEqual(parts[1].get_content_type(), "text/plain")
        self.assertEqual(parts[1].get_content_charset(), "utf-8")
        self.assertIsNone(parts[1].get_filename())
        expected = textwrap.dedent(
            f"""\
            ProblemType: Crash
            Date: now!
            InlineMargin:
             first
             second
             third
             fourth
             fifth
            LargeMultiline:
             {'A' * 120}
             {'B' * 90}
            Largeline: {'A' * 999}
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
            """
        ).encode("UTF-8")
        self.assertEqual(parts[1].get_payload(decode=True), expected)

        # third part should be the HugeMultiline: field as attachment
        self.assertTrue(not parts[2].is_multipart())
        self.assertEqual(parts[2].get_content_type(), "text/plain")
        self.assertEqual(parts[2].get_content_charset(), "utf-8")
        self.assertEqual(parts[2].get_filename(), "HugeMultiline.txt")
        self.assertEqual(
            parts[2].get_payload(decode=True), pr["HugeMultiline"].encode()
        )

        # fourth part should be the Hugeline: field as attachment
        self.assertTrue(not parts[3].is_multipart())
        self.assertEqual(parts[3].get_content_type(), "text/plain")
        self.assertEqual(parts[3].get_content_charset(), "utf-8")
        self.assertEqual(parts[3].get_filename(), "Hugeline.txt")
        self.assertEqual(parts[3].get_payload(decode=True), pr["Hugeline"].encode())

        # fifth part should be the Multiline: field as attachment
        self.assertTrue(not parts[4].is_multipart())
        self.assertEqual(parts[4].get_content_type(), "text/plain")
        self.assertEqual(parts[4].get_content_charset(), "utf-8")
        self.assertEqual(parts[4].get_filename(), "Multiline.txt")
        expected = textwrap.dedent(
            f"""\
             foo   bar
            baz
              blip{'  '}
            line4
            line♥5!!
            łıµ€ ⅝
            """
        ).encode("UTF-8")
        self.assertEqual(parts[4].get_payload(decode=True), expected)

    def test_write_mime_extra_headers(self) -> None:
        """write_mime() with extra headers."""
        pr = problem_report.ProblemReport(date="now!")
        pr["Simple"] = "bar"
        pr["TwoLine"] = "first\nsecond\n"
        out = io.BytesIO()
        pr.write_mime(out, extra_headers={"Greeting": "hello world", "Foo": "Bar"})
        out.seek(0)

        msg = email.message_from_binary_file(out)
        self.assertEqual(msg["Greeting"], "hello world")
        self.assertEqual(msg["Foo"], "Bar")
        parts = list(msg.walk())
        self.assertEqual(len(parts), 2)

        # first part is the multipart container
        self.assertTrue(parts[0].is_multipart())

        # second part should be an inline text/plain attachments with all short
        # fields
        self.assertTrue(not parts[1].is_multipart())
        self.assertEqual(parts[1].get_content_type(), "text/plain")
        self.assertIn(b"Simple: bar", parts[1].get_payload(decode=True))

    def test_write_mime_order(self) -> None:
        """write_mime() with keys ordered."""
        pr = problem_report.ProblemReport(date="now!")
        pr["SecondText"] = "What"
        pr["FirstText"] = "Who"
        pr["FourthText"] = "Today"
        pr["ThirdText"] = "I Don't Know"
        out = io.BytesIO()
        pr.write_mime(
            out,
            priority_fields=[
                "FirstText",
                "SecondText",
                "ThirdText",
                "Unknown",
                "FourthText",
            ],
        )
        out.seek(0)

        msg = email.message_from_binary_file(out)
        parts = list(msg.walk())
        self.assertEqual(len(parts), 2)

        # first part is the multipart container
        self.assertTrue(parts[0].is_multipart())

        # second part should be an inline text/plain attachments with all short
        # fields
        self.assertTrue(not parts[1].is_multipart())
        self.assertEqual(parts[1].get_content_type(), "text/plain")
        self.assertEqual(parts[1].get_content_charset(), "utf-8")
        self.assertIsNone(parts[1].get_filename())
        self.assertEqual(
            parts[1].get_payload(decode=True),
            textwrap.dedent(
                """\
                FirstText: Who
                SecondText: What
                ThirdText: I Don't Know
                FourthText: Today
                ProblemType: Crash
                Date: now!
                """
            ).encode(),
        )

    def test_updating(self) -> None:
        """new_keys() and write() with only_new=True."""
        pr = problem_report.ProblemReport()
        self.assertEqual(pr.new_keys(), set(["ProblemType", "Date"]))
        pr.load(
            io.BytesIO(
                textwrap.dedent(
                    """\
                    ProblemType: Crash
                    Date: now!
                    Foo: bar
                    Baz: blob
                    """
                ).encode()
            )
        )

        self.assertEqual(pr.new_keys(), set())

        pr["Foo"] = "changed"
        pr["NewKey"] = "new new"
        self.assertEqual(pr.new_keys(), set(["NewKey"]))

        out = io.BytesIO()
        pr.write(out, only_new=True)
        self.assertEqual(out.getvalue(), b"NewKey: new new\n")

    def test_import_dict(self) -> None:
        """Import a dictionary with update()."""
        pr = problem_report.ProblemReport()
        pr["oldtext"] = "Hello world"
        pr["oldbin"] = bin_data
        pr["overwrite"] = "I am crap"

        d = {
            "newtext": "Goodbye world",
            "newbin": "11\000\001\002\xffZZ",
            "overwrite": "I am good",
        }

        pr.update(d)
        self.assertEqual(pr["oldtext"], "Hello world")
        self.assertEqual(pr["oldbin"], bin_data)
        self.assertEqual(pr["newtext"], "Goodbye world")
        self.assertEqual(pr["newbin"], "11\000\001\002\xffZZ")
        self.assertEqual(pr["overwrite"], "I am good")

    def test_load_key_filter(self) -> None:
        """Load a report with filtering keys."""
        report = textwrap.dedent(
            """\
            ProblemType: Crash
            DataNo: nonono
            GoodFile: base64
             H4sICAAAAAAC/0FmaWxlAA==
             c3RyhEIGBoYoRiYAM5XUCxAAAAA=
            DataYes: yesyes
            BadFile: base64
             H4sICAAAAAAC/0ZpbGUA
             S8vPZ0hKLAIACq50HgcAAAA=
            """
        ).encode()
        pr = problem_report.ProblemReport()
        pr.load(io.BytesIO(report), key_filter=["DataYes", "GoodFile"])
        self.assertEqual(pr["DataYes"], "yesyes")
        self.assertEqual(pr["GoodFile"], bin_data)
        self.assertEqual(sorted(pr.keys()), ["DataYes", "GoodFile"])

    def test_get_on_disk_size(self) -> None:
        """Test CompressedValue.get_on_disk_size()."""
        compressed_value = problem_report.CompressedValue(b"somedata")
        self.assertEqual(compressed_value.get_compressed_size(), 28)
        assert compressed_value.compressed_value is not None
        base64_encoded = base64.b64encode(compressed_value.compressed_value)
        self.assertEqual(compressed_value.get_on_disk_size(), len(base64_encoded))


class TestEntryParser(unittest.TestCase):
    # pylint: disable=protected-access
    """Test _EntryParser class."""

    def test_parse(self) -> None:
        """Test parsing a report file with _EntryParser."""
        report_file = io.BytesIO(
            textwrap.dedent(
                """\
                First: single line
                Second: multi
                 line
                """
            ).encode()
        )
        entries = []
        for entry in problem_report._EntryParser(report_file):
            entries.append(list(entry))
        self.assertEqual(
            entries, [[b"First: single line\n"], [b"Second: multi\n", b" line\n"]]
        )

    def test_skip_entries(self) -> None:
        """Test skipping reading one entry."""
        report_file = io.BytesIO(
            textwrap.dedent(
                """\
                First: this entry
                 will be skipped
                Second: single line
                """
            ).encode()
        )
        iterator = problem_report._EntryParser(report_file)
        next(iterator)
        self.assertEqual(list(next(iterator)), [b"Second: single line\n"])

    def test_skip_partial_entries(self) -> None:
        """Test skipping reading one entry."""
        report_file = io.BytesIO(
            textwrap.dedent(
                """\
                First: this line is read,
                 but these lines
                 will be skipped
                Second: single line
                """
            ).encode()
        )
        iterator = problem_report._EntryParser(report_file)
        self.assertEqual(next(next(iterator)), b"First: this line is read,\n")
        self.assertEqual(list(next(iterator)), [b"Second: single line\n"])

    def test_skip_last_entry(self) -> None:
        """Test skipping reading the last entry."""
        report_file = io.BytesIO(
            textwrap.dedent(
                """\
                First: this line is read
                Second: this line is skipped
                """
            ).encode()
        )
        iterator = problem_report._EntryParser(report_file)
        self.assertEqual(list(next(iterator)), [b"First: this line is read\n"])
        next(iterator)
        with self.assertRaises(StopIteration):
            next(iterator)
