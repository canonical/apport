import email
import gzip
import io
import os
import shutil
import tempfile
import textwrap
import time
import unittest

import problem_report

bin_data = b"ABABABABAB\0\0\0Z\x01\x02"


class T(unittest.TestCase):
    @classmethod
    def setUp(self):
        self.workdir = tempfile.mkdtemp()

    @classmethod
    def tearDown(self):
        shutil.rmtree(self.workdir)

    def test_compressed_values(self):
        """handling of CompressedValue values."""

        large_val = b"A" * 5000000

        pr = problem_report.ProblemReport()
        pr["Foo"] = problem_report.CompressedValue(b"FooFoo!")
        pr["Bin"] = problem_report.CompressedValue()
        pr["Bin"].set_value(bin_data)
        pr["Large"] = problem_report.CompressedValue(large_val)

        self.assertTrue(isinstance(pr["Foo"], problem_report.CompressedValue))
        self.assertTrue(isinstance(pr["Bin"], problem_report.CompressedValue))
        self.assertEqual(pr["Foo"].get_value(), b"FooFoo!")
        self.assertEqual(pr["Bin"].get_value(), bin_data)
        self.assertEqual(pr["Large"].get_value(), large_val)
        self.assertEqual(len(pr["Foo"]), 7)
        self.assertEqual(len(pr["Bin"]), len(bin_data))
        self.assertEqual(len(pr["Large"]), len(large_val))

        out = io.BytesIO()
        pr["Bin"].write(out)
        self.assertEqual(out.getvalue(), bin_data)
        out = io.BytesIO()
        pr["Large"].write(out)
        self.assertEqual(out.getvalue(), large_val)

        pr["Multiline"] = problem_report.CompressedValue(
            b"\1\1\1\n\2\2\n\3\3\3"
        )
        self.assertEqual(
            pr["Multiline"].splitlines(), [b"\1\1\1", b"\2\2", b"\3\3\3"]
        )

        # test writing of reports with CompressedValues
        out = io.BytesIO()
        pr.write(out)
        out.seek(0)
        pr = problem_report.ProblemReport()
        pr.load(out)
        self.assertEqual(pr["Foo"], "FooFoo!")
        self.assertEqual(pr["Bin"], bin_data)
        self.assertEqual(pr["Large"], large_val.decode("ASCII"))

    def test_write_append(self):
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

        temp = tempfile.NamedTemporaryFile()
        temp.write(bin_data)
        temp.flush()

        pr = problem_report.ProblemReport(date="now!")
        pr["File"] = (temp.name,)
        out = io.BytesIO()
        pr.write(out)
        temp.close()

        pr.clear()
        pr["Extra"] = "appended"
        pr.write(out)

        out.seek(0)
        pr = problem_report.ProblemReport()
        pr.load(out)

        self.assertEqual(pr["Date"], "now!")
        self.assertEqual(pr["File"], bin_data)
        self.assertEqual(pr["Extra"], "appended")

    def test_extract_keys(self):
        """extract_keys() with various binary elements."""

        # create a test report with binary elements
        large_val = b"A" * 5000000

        pr = problem_report.ProblemReport()
        pr["Txt"] = "some text"
        pr["MoreTxt"] = "some more text"
        pr["Foo"] = problem_report.CompressedValue(b"FooFoo!")
        pr["Uncompressed"] = bin_data
        pr["Bin"] = problem_report.CompressedValue()
        pr["Bin"].set_value(bin_data)
        pr["Large"] = problem_report.CompressedValue(large_val)
        pr["Multiline"] = problem_report.CompressedValue(
            b"\1\1\1\n\2\2\n\3\3\3"
        )

        report = io.BytesIO()
        pr.write(report)
        report.seek(0)

        self.assertRaises(
            OSError,
            pr.extract_keys,
            report,
            "Bin",
            os.path.join(self.workdir, "nonexistant"),
        )
        # Test exception handling: Non-binary and nonexistent key
        tests = [
            (ValueError, "Txt"),
            (ValueError, ["Foo", "Txt"]),
            (KeyError, "Bar"),
            (KeyError, ["Foo", "Bar"]),
        ]
        for exc, keys_arg in tests:
            report.seek(0)
            self.assertRaises(
                exc, pr.extract_keys, report, keys_arg, self.workdir
            )

        # Check valid single elements
        tests = {
            "Foo": b"FooFoo!",
            "Uncompressed": bin_data,
            "Bin": bin_data,
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
        tests = {"Foo": b"FooFoo!", "Uncompressed": bin_data}
        pr.extract_keys(report, tests.keys(), self.workdir)
        for key, expected in tests.items():
            with open(os.path.join(self.workdir, key), "rb") as f:
                self.assertEqual(f.read(), expected)

    def test_write_file(self):
        """writing a report with binary file data."""

        temp = tempfile.NamedTemporaryFile()
        temp.write(bin_data)
        temp.flush()

        pr = problem_report.ProblemReport(date="now!")
        pr["File"] = (temp.name,)
        pr["Afile"] = (temp.name,)
        out = io.BytesIO()
        pr.write(out)
        temp.close()

        self.assertEqual(
            out.getvalue().decode(),
            textwrap.dedent(
                """\
                ProblemType: Crash
                Date: now!
                Afile: base64
                 H4sICAAAAAAC/0FmaWxlAA==
                 c3RyhEIGBoYoRiYAM5XUCxAAAAA=
                File: base64
                 H4sICAAAAAAC/0ZpbGUA
                 c3RyhEIGBoYoRiYAM5XUCxAAAAA=
                """
            ),
        )

        # force compression/encoding bool
        temp = tempfile.NamedTemporaryFile()
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

        self.assertEqual(
            out.getvalue().decode(),
            textwrap.dedent(
                """\
                ProblemType: Crash
                Date: now!
                File: base64
                 H4sICAAAAAAC/0ZpbGUA
                 S8vPZ0hKLAIACq50HgcAAAA=
                """
            ),
        )
        temp.close()

    def test_write_delayed_fileobj(self):
        """writing a report with file pointers and delayed data."""

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

    def test_big_file(self):
        """writing and re-decoding a big random file."""

        # create 1 MB random file
        temp = tempfile.NamedTemporaryFile()
        data = os.urandom(1048576)
        temp.write(data)
        temp.flush()

        # write it into problem report
        pr = problem_report.ProblemReport()
        pr["File"] = (temp.name,)
        pr["Before"] = "xtestx"
        pr["ZAfter"] = "ytesty"
        out = io.BytesIO()
        pr.write(out)
        temp.close()

        # read it again
        out.seek(0)
        pr = problem_report.ProblemReport()
        pr.load(out)

        self.assertTrue(pr["File"] == data)
        self.assertEqual(pr["Before"], "xtestx")
        self.assertEqual(pr["ZAfter"], "ytesty")

        # write it again
        io2 = io.BytesIO()
        pr.write(io2)
        self.assertTrue(out.getvalue() == io2.getvalue())

        # check gzip compatibility
        out.seek(0)
        pr = problem_report.ProblemReport()
        pr.load(out, binary="compressed")
        self.assertEqual(pr["File"].get_value(), data)

    def test_size_limit(self):
        """writing and a big random file with a size limit key."""

        # create 1 MB random file
        temp = tempfile.NamedTemporaryFile()
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
        temp.close()

        # read it again
        out.seek(0)
        pr = problem_report.ProblemReport()
        pr.load(out)

        self.assertNotIn("FileSmallLimit", pr)
        self.assertNotIn("FileLimitMinus1", pr)
        self.assertTrue(pr["FileExactLimit"] == data)
        self.assertTrue(pr["FileLimitPlus1"] == data)
        self.assertTrue(pr["FileLimitNone"] == data)
        self.assertEqual(pr["Before"], "xtestx")
        self.assertEqual(pr["ZAfter"], "ytesty")

    def test_add_to_existing(self):
        """adding information to an existing report."""

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
        with open(rep) as f:
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
        dir = rep
        while len(dir) > 1:
            dir, filename = os.path.split(dir)
            if os.path.ismount(dir):
                with open("/proc/mounts") as f:
                    for line in f:
                        mount, fs, options = line.split(" ")[1:4]
                        if mount == dir and "noatime" in options.split(","):
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

    def test_write_mime_binary(self):
        """write_mime() for binary values and file references."""

        temp = tempfile.NamedTemporaryFile()
        temp.write(bin_data)
        temp.flush()

        tempgz = tempfile.NamedTemporaryFile()
        gz = gzip.GzipFile("File1", "w", fileobj=tempgz)
        gz.write(bin_data)
        gz.close()
        tempgz.flush()

        pr = problem_report.ProblemReport(date="now!")
        pr["Context"] = "Test suite"
        pr["File1"] = (temp.name,)
        pr["File1.gz"] = (tempgz.name,)
        pr["Value1"] = bin_data
        with open(tempgz.name, "rb") as f:
            pr["Value1.gz"] = f.read()
        pr["ZValue"] = problem_report.CompressedValue(bin_data)
        out = io.BytesIO()
        pr.write_mime(out)
        out.seek(0)

        msg = email.message_from_binary_file(out)
        parts = [p for p in msg.walk()]
        self.assertEqual(len(parts), 7)

        # first part is the multipart container
        self.assertTrue(parts[0].is_multipart())

        # second part should be an inline text/plain attachments with all short
        # fields
        self.assertTrue(not parts[1].is_multipart())
        self.assertEqual(parts[1].get_content_type(), "text/plain")
        self.assertEqual(parts[1].get_content_charset(), "utf-8")
        self.assertEqual(parts[1].get_filename(), None)
        self.assertEqual(
            parts[1].get_payload(decode=True),
            b"ProblemType: Crash\nContext: Test suite\nDate: now!\n",
        )

        # third part should be the File1: file contents as gzip'ed attachment
        self.assertTrue(not parts[2].is_multipart())
        self.assertEqual(parts[2].get_content_type(), "application/x-gzip")
        self.assertEqual(parts[2].get_filename(), "File1.gz")
        self.assertEqual(self.decode_gzipped_message(parts[2]), bin_data)

        # fourth part should be the File1.gz: file contents as gzip'ed
        # attachment; write_mime() should not compress it again
        self.assertTrue(not parts[3].is_multipart())
        self.assertEqual(parts[3].get_content_type(), "application/x-gzip")
        self.assertEqual(parts[3].get_filename(), "File1.gz")
        self.assertEqual(self.decode_gzipped_message(parts[3]), bin_data)

        # fifth part should be the Value1: value as gzip'ed attachment
        self.assertTrue(not parts[4].is_multipart())
        self.assertEqual(parts[4].get_content_type(), "application/x-gzip")
        self.assertEqual(parts[4].get_filename(), "Value1.gz")
        self.assertEqual(self.decode_gzipped_message(parts[4]), bin_data)

        # sixth part should be the Value1: value as gzip'ed attachment;
        # write_mime should not compress it again
        self.assertTrue(not parts[5].is_multipart())
        self.assertEqual(parts[5].get_content_type(), "application/x-gzip")
        self.assertEqual(parts[5].get_filename(), "Value1.gz")
        self.assertEqual(self.decode_gzipped_message(parts[5]), bin_data)

        # seventh part should be the ZValue: value as gzip'ed attachment;
        # write_mime should not compress it again
        self.assertTrue(not parts[6].is_multipart())
        self.assertEqual(parts[6].get_content_type(), "application/x-gzip")
        self.assertEqual(parts[6].get_filename(), "ZValue.gz")
        self.assertEqual(self.decode_gzipped_message(parts[6]), bin_data)

    def test_write_mime_filter(self):
        """write_mime() with key filters."""

        pr = problem_report.ProblemReport(date="now!")
        pr["GoodText"] = "Hi"
        pr["BadText"] = "YouDontSeeMe"
        pr["GoodBin"] = bin_data
        pr["BadBin"] = "Y" + "\x05" * 10 + "-"
        out = io.BytesIO()
        pr.write_mime(out, skip_keys=["BadText", "BadBin"])
        out.seek(0)

        msg = email.message_from_binary_file(out)
        parts = [p for p in msg.walk()]
        self.assertEqual(len(parts), 3)

        # first part is the multipart container
        self.assertTrue(parts[0].is_multipart())

        # second part should be an inline text/plain attachments with all short
        # fields
        self.assertTrue(not parts[1].is_multipart())
        self.assertEqual(parts[1].get_content_type(), "text/plain")
        self.assertEqual(parts[1].get_content_charset(), "utf-8")
        self.assertEqual(parts[1].get_filename(), None)
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
        self.assertEqual(self.decode_gzipped_message(parts[2]), bin_data)

    def decode_gzipped_message(self, message: email.message.Message) -> bytes:
        with tempfile.TemporaryFile() as payload:
            payload.write(message.get_payload(decode=True))
            payload.seek(0)
            return gzip.GzipFile(mode="rb", fileobj=payload).read()
