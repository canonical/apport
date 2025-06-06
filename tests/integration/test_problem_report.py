"""Integration tests for the problem_report module."""

import email
import email.message
import gzip
import io
import os
import shutil
import tempfile
import textwrap
import time
import unittest

import problem_report

BIN_DATA = b"ABABABABAB\0\0\0Z\x01\x02"


class T(unittest.TestCase):
    # pylint: disable=missing-class-docstring,missing-function-docstring

    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.workdir)

    def test_compressed_values(self) -> None:
        """Handle of CompressedValue values."""
        large_val = b"A" * 5000000

        pr = problem_report.ProblemReport()
        pr["Foo"] = problem_report.CompressedValue(b"FooFoo!")
        pr["Bin"] = problem_report.CompressedValue()
        pr["Bin"].set_value(BIN_DATA)
        pr["Large"] = problem_report.CompressedValue(large_val)

        self.assertTrue(isinstance(pr["Foo"], problem_report.CompressedValue))
        self.assertTrue(isinstance(pr["Bin"], problem_report.CompressedValue))
        self.assertEqual(pr["Foo"].get_value(), b"FooFoo!")
        self.assertEqual(pr["Bin"].get_value(), BIN_DATA)
        self.assertEqual(pr["Large"].get_value(), large_val)
        self.assertEqual(len(pr["Foo"]), 7)
        self.assertEqual(len(pr["Bin"]), len(BIN_DATA))
        self.assertEqual(len(pr["Large"]), len(large_val))

        out = io.BytesIO()
        pr["Bin"].write(out)
        self.assertEqual(out.getvalue(), BIN_DATA)
        out = io.BytesIO()
        pr["Large"].write(out)
        self.assertEqual(out.getvalue(), large_val)

        pr["Multiline"] = problem_report.CompressedValue(b"\1\1\1\n\2\2\n\3\3\3")
        self.assertEqual(pr["Multiline"].splitlines(), [b"\1\1\1", b"\2\2", b"\3\3\3"])

        # test writing of reports with CompressedValues
        out = io.BytesIO()
        pr.write(out)
        out.seek(0)
        pr = problem_report.ProblemReport()
        pr.load(out)
        self.assertEqual(pr["Foo"], "FooFoo!")
        self.assertEqual(pr["Bin"], BIN_DATA)
        self.assertEqual(pr["Large"], large_val.decode("ASCII"))

    def test_write_append(self) -> None:
        """write() with appending to an existing file."""
        pr = problem_report.ProblemReport(date="now!")
        pr["Simple"] = "bar"
        pr["WhiteSpace"] = " foo   bar\nbaz\n  blip  "
        out = io.BytesIO()
        pr.write(out)

        pr.clear()
        pr["Extra"] = "appended"
        pr.write(out)

        self.assertEqual(
            out.getvalue().decode(),
            textwrap.dedent(
                f"""\
                ProblemType: Crash
                Date: now!
                Simple: bar
                WhiteSpace:
                  foo   bar
                 baz
                   blip{'  '}
                Extra: appended
                """
            ),
        )

        with tempfile.NamedTemporaryFile() as temp:
            temp.write(BIN_DATA)
            temp.flush()

            pr = problem_report.ProblemReport(date="now!")
            pr["File"] = (temp.name,)
            out = io.BytesIO()
            pr.write(out)

        pr.clear()
        pr["Extra"] = "appended"
        pr.write(out)

        out.seek(0)
        pr = problem_report.ProblemReport()
        pr.load(out)

        self.assertEqual(pr["Date"], "now!")
        self.assertEqual(pr["File"], BIN_DATA)
        self.assertEqual(pr["Extra"], "appended")

    def test_extract_keys(self) -> None:
        """extract_keys() with various binary elements."""
        # create a test report with binary elements
        large_val = b"A" * 5000000

        pr = problem_report.ProblemReport()
        pr["Txt"] = "some text"
        pr["MoreTxt"] = "some more text"
        pr["Foo"] = problem_report.CompressedValue(b"FooFoo!")
        pr["Uncompressed"] = BIN_DATA
        pr["Bin"] = problem_report.CompressedValue()
        pr["Bin"].set_value(BIN_DATA)
        pr["Large"] = problem_report.CompressedValue(large_val)
        pr["Multiline"] = problem_report.CompressedValue(b"\1\1\1\n\2\2\n\3\3\3")

        report = io.BytesIO()
        pr.write(report)
        report.seek(0)

        self.assertRaises(
            OSError,
            pr.extract_keys,
            report,
            "Bin",
            os.path.join(self.workdir, "nonexistent"),
        )
        # Test exception handling: Non-binary and nonexistent key
        exception_tests = [
            (ValueError, "Txt"),
            (ValueError, ["Foo", "Txt"]),
            (KeyError, "Bar"),
            (KeyError, ["Foo", "Bar"]),
        ]
        for exc, keys_arg in exception_tests:
            report.seek(0)
            self.assertRaises(exc, pr.extract_keys, report, keys_arg, self.workdir)

        # Check valid single elements
        tests = {
            "Foo": b"FooFoo!",
            "Uncompressed": BIN_DATA,
            "Bin": BIN_DATA,
            "Large": large_val,
            "Multiline": b"\1\1\1\n\2\2\n\3\3\3",
        }
        for key, expected in tests.items():
            report.seek(0)
            pr.extract_keys(report, key, self.workdir)
            with open(os.path.join(self.workdir, key), "rb") as f:
                self.assertEqual(f.read(), expected)
            # remove file for next pass
            os.remove(os.path.join(self.workdir, key))

        # Check element list
        report.seek(0)
        tests = {"Foo": b"FooFoo!", "Uncompressed": BIN_DATA}
        pr.extract_keys(report, tests.keys(), self.workdir)
        for key, expected in tests.items():
            with open(os.path.join(self.workdir, key), "rb") as f:
                self.assertEqual(f.read(), expected)

    def test_write_file(self) -> None:
        """Write a report with binary file data."""
        with tempfile.NamedTemporaryFile() as temp:
            temp.write(BIN_DATA)
            temp.flush()

            pr = problem_report.ProblemReport(date="now!")
            pr["File"] = (temp.name,)
            pr["Afile"] = (temp.name,)
            out = io.BytesIO()
            pr.write(out)

        self.assertIn("Afile: base64\n", out.getvalue().decode())
        self.assertIn("File: base64\n", out.getvalue().decode())
        report = problem_report.ProblemReport()
        out.seek(0)
        report.load(out)
        self.assertEqual(report["File"], BIN_DATA)
        self.assertEqual(report["Afile"], BIN_DATA)

        # force compression/encoding bool
        with tempfile.NamedTemporaryFile() as temp:
            temp.write(b"foo\0bar")
            temp.flush()
            pr = problem_report.ProblemReport(date="now!")
            pr["File"] = (temp.name, False)
            out = io.BytesIO()
            pr.write(out)

            self.assertEqual(
                out.getvalue().decode(),
                textwrap.dedent(
                    """\
                    ProblemType: Crash
                    Date: now!
                    File: foo\0bar
                    """
                ),
            )

            pr["File"] = (temp.name, True)
            out = io.BytesIO()
            pr.write(out)

            # check that written report is read correctly again
            report = problem_report.ProblemReport()
            out.seek(0)
            report.load(out, binary="compressed")
            self.assertIsInstance(report["File"], problem_report.CompressedValue)
            self.assertEqual(report["File"].get_value(), b"foo\0bar")

    def test_write_delayed_fileobj(self) -> None:
        """Write a report with file pointers and delayed data."""
        (fout, fin) = os.pipe()

        if os.fork() == 0:
            os.close(fout)
            time.sleep(0.3)
            os.write(fin, b"ab" * 512 * 1024)
            time.sleep(0.3)
            os.write(fin, b"hello")
            time.sleep(0.3)
            os.write(fin, b" world")
            os.close(fin)
            os._exit(0)

        os.close(fin)

        pr = problem_report.ProblemReport(date="now!")
        out = io.BytesIO()
        with os.fdopen(fout, "rb") as f:
            pr["BinFile"] = (f,)
            pr.write(out)
        assert os.wait()[1] == 0

        out.seek(0)

        pr2 = problem_report.ProblemReport()
        pr2.load(out)
        self.assertEqual(pr2["BinFile"], "ab" * 512 * 1024 + "hello world")

    def test_big_file(self) -> None:
        """Write and re-decoding a big random file."""
        # create a big random file (not exceeding the chunk size to avoid line wrapping)
        with tempfile.NamedTemporaryFile() as temp:
            data = os.urandom(problem_report.CHUNK_SIZE)
            temp.write(data)
            temp.flush()

            # write it into problem report
            pr = problem_report.ProblemReport()
            pr["File"] = (temp.name,)
            pr["Before"] = "xtestx"
            pr["ZAfter"] = "ytesty"
            out = io.BytesIO()
            pr.write(out)

        # read it again
        out.seek(0)
        pr = problem_report.ProblemReport()
        pr.load(out)

        self.assertEqual(pr["File"], data)
        self.assertEqual(pr["Before"], "xtestx")
        self.assertEqual(pr["ZAfter"], "ytesty")

        # write it again
        io2 = io.BytesIO()
        pr.write(io2)
        self.assertEqual(out.getvalue(), io2.getvalue())

        # check gzip compatibility
        out.seek(0)
        pr = problem_report.ProblemReport()
        pr.load(out, binary="compressed")
        self.assertEqual(pr["File"].get_value(), data)
        self.assertEqual(pr["File"].name, "File")

    def test_size_limit(self) -> None:
        """Write and a big random file with a size limit key."""
        # create 1 MB random file
        with tempfile.NamedTemporaryFile() as temp:
            data = os.urandom(1048576)
            temp.write(data)
            temp.flush()

            # write it into problem report
            pr = problem_report.ProblemReport()
            pr["FileSmallLimit"] = (temp.name, True, 100)
            pr["FileLimitMinus1"] = (temp.name, True, 1048575)
            pr["FileExactLimit"] = (temp.name, True, 1048576)
            pr["FileLimitPlus1"] = (temp.name, True, 1048577)
            pr["FileLimitNone"] = (temp.name, True, None)
            pr["Before"] = "xtestx"
            pr["ZAfter"] = "ytesty"
            out = io.BytesIO()
            pr.write(out)

        # read it again
        out.seek(0)
        pr = problem_report.ProblemReport()
        pr.load(out)

        self.assertNotIn("FileSmallLimit", pr)
        self.assertNotIn("FileLimitMinus1", pr)
        self.assertEqual(pr["FileExactLimit"], data)
        self.assertEqual(pr["FileLimitPlus1"], data)
        self.assertEqual(pr["FileLimitNone"], data)
        self.assertEqual(pr["Before"], "xtestx")
        self.assertEqual(pr["ZAfter"], "ytesty")

    def test_add_to_existing(self) -> None:  # pylint: disable=too-many-statements
        """Add information to an existing report."""
        # original report
        pr = problem_report.ProblemReport()
        pr["old1"] = "11"
        pr["old2"] = "22"

        (fd, rep) = tempfile.mkstemp()
        os.close(fd)
        with open(rep, "wb") as f:
            pr.write(f)

        origstat = os.stat(rep)

        # create a new one and add it
        pr = problem_report.ProblemReport()
        pr.clear()
        pr["new1"] = "33"

        pr.add_to_existing(rep, keep_times=True)

        # check keep_times
        newstat = os.stat(rep)
        self.assertEqual(origstat.st_mode, newstat.st_mode)
        self.assertAlmostEqual(origstat.st_atime, newstat.st_atime, 1)
        self.assertAlmostEqual(origstat.st_mtime, newstat.st_mtime, 1)

        # check report contents
        newpr = problem_report.ProblemReport()
        with open(rep, "rb") as f:
            newpr.load(f)
        self.assertEqual(newpr["old1"], "11")
        self.assertEqual(newpr["old2"], "22")
        self.assertEqual(newpr["new1"], "33")

        # create a another new one and add it, but make sure mtime must be
        # different
        time.sleep(1)
        with open(rep, encoding="utf-8") as f:
            f.read()  # bump atime
        time.sleep(1)

        pr = problem_report.ProblemReport()
        pr.clear()
        pr["new2"] = "44"

        pr.add_to_existing(rep)

        # check that timestamps have been updates
        newstat = os.stat(rep)
        self.assertEqual(origstat.st_mode, newstat.st_mode)
        self.assertNotEqual(origstat.st_mtime, newstat.st_mtime)
        # skip atime check if filesystem is mounted noatime
        skip_atime = False
        directory = rep
        while len(directory) > 1:
            directory = os.path.split(directory)[0]
            if os.path.ismount(directory):
                with open("/proc/mounts", encoding="utf-8") as f:
                    for line in f:
                        mount, _, options = line.split(" ")[1:4]
                        if mount == directory and "noatime" in options.split(","):
                            skip_atime = True
                            break
                break
        if not skip_atime:
            self.assertNotEqual(origstat.st_atime, newstat.st_atime)

        # check report contents
        newpr = problem_report.ProblemReport()
        with open(rep, "rb") as f:
            newpr.load(f)
        self.assertEqual(newpr["old1"], "11")
        self.assertEqual(newpr["old2"], "22")
        self.assertEqual(newpr["new1"], "33")
        self.assertEqual(newpr["new2"], "44")

        os.unlink(rep)

    def test_write_mime_binary(self) -> None:
        """write_mime() for binary values and file references."""
        with tempfile.NamedTemporaryFile() as temp:
            with tempfile.NamedTemporaryFile() as tempgz:
                temp.write(BIN_DATA)
                temp.flush()

                with gzip.GzipFile("File1", "w", fileobj=tempgz) as gz:
                    gz.write(BIN_DATA)
                tempgz.flush()

                pr = problem_report.ProblemReport(date="now!")
                pr["Context"] = "Test suite"
                pr["File1"] = (temp.name,)
                pr["File1.gz"] = (tempgz.name,)
                pr["Value1"] = BIN_DATA
                with open(tempgz.name, "rb") as f:
                    pr["Value1.gz"] = f.read()
                pr["ZValue"] = problem_report.CompressedValue(BIN_DATA)
                out = io.BytesIO()
                pr.write_mime(out)
                out.seek(0)

        msg = email.message_from_binary_file(out)
        parts = list(msg.walk())
        self.assertEqual(len(parts), 7)

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
            b"ProblemType: Crash\nContext: Test suite\nDate: now!\n",
        )

        # third part should be the File1: file contents as gzip'ed attachment
        self.assertTrue(not parts[2].is_multipart())
        self.assertEqual(parts[2].get_content_type(), "application/x-gzip")
        self.assertEqual(parts[2].get_filename(), "File1.gz")
        self.assertEqual(self.decode_gzipped_message(parts[2]), BIN_DATA)

        # fourth part should be the File1.gz: file contents as gzip'ed
        # attachment; write_mime() should not compress it again
        self.assertTrue(not parts[3].is_multipart())
        self.assertEqual(parts[3].get_content_type(), "application/x-gzip")
        self.assertEqual(parts[3].get_filename(), "File1.gz")
        self.assertEqual(self.decode_gzipped_message(parts[3]), BIN_DATA)

        # fifth part should be the Value1: value as gzip'ed attachment
        self.assertTrue(not parts[4].is_multipart())
        self.assertEqual(parts[4].get_content_type(), "application/x-gzip")
        self.assertEqual(parts[4].get_filename(), "Value1.gz")
        self.assertEqual(self.decode_gzipped_message(parts[4]), BIN_DATA)

        # sixth part should be the Value1: value as gzip'ed attachment;
        # write_mime should not compress it again
        self.assertTrue(not parts[5].is_multipart())
        self.assertEqual(parts[5].get_content_type(), "application/x-gzip")
        self.assertEqual(parts[5].get_filename(), "Value1.gz")
        self.assertEqual(self.decode_gzipped_message(parts[5]), BIN_DATA)

        # seventh part should be the ZValue: value as gzip'ed attachment;
        # write_mime should not compress it again
        self.assertTrue(not parts[6].is_multipart())
        self.assertEqual(parts[6].get_content_type(), "application/x-gzip")
        self.assertEqual(parts[6].get_filename(), "ZValue.gz")
        self.assertEqual(self.decode_gzipped_message(parts[6]), BIN_DATA)

    def test_write_mime_filter(self) -> None:
        """write_mime() with key filters."""
        pr = problem_report.ProblemReport(date="now!")
        pr["GoodText"] = "Hi"
        pr["BadText"] = "YouDontSeeMe"
        pr["GoodBin"] = BIN_DATA
        pr["BadBin"] = "Y" + "\x05" * 10 + "-"
        out = io.BytesIO()
        pr.write_mime(out, skip_keys=["BadText", "BadBin"])
        out.seek(0)

        msg = email.message_from_binary_file(out)
        parts = list(msg.walk())
        self.assertEqual(len(parts), 3)

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
                ProblemType: Crash
                Date: now!
                GoodText: Hi
                """
            ).encode(),
        )

        # third part should be the GoodBin: field as attachment
        self.assertTrue(not parts[2].is_multipart())
        self.assertEqual(self.decode_gzipped_message(parts[2]), BIN_DATA)

    @staticmethod
    def decode_gzipped_message(message: email.message.Message) -> bytes:
        payload = message.get_payload(decode=True)
        assert isinstance(payload, bytes)
        with gzip.GzipFile(mode="rb", fileobj=io.BytesIO(payload)) as gzip_file:
            return gzip_file.read()
