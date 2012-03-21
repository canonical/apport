# vim: set encoding=UTF-8 fileencoding=UTF-8 :
import unittest, tempfile, os, email, gzip, time, sys

try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

import problem_report

class T(unittest.TestCase):
    def test_basic_operations(self):
        '''basic creation and operation.'''

        pr = problem_report.ProblemReport()
        pr['foo'] = 'bar'
        pr['bar'] = ' foo   bar\nbaz\n   blip  '
        pr['dash-key'] = '1'
        pr['dot.key'] = '1'
        pr['underscore_key'] = '1'
        self.assertEqual(pr['foo'], 'bar')
        self.assertEqual(pr['bar'], ' foo   bar\nbaz\n   blip  ')
        self.assertEqual(pr['ProblemType'], 'Crash')
        self.assertTrue(time.strptime(pr['Date']))
        self.assertEqual(pr['dash-key'], '1')
        self.assertEqual(pr['dot.key'], '1')
        self.assertEqual(pr['underscore_key'], '1')

    def test_ctor_arguments(self):
        '''non-default constructor arguments.'''

        pr = problem_report.ProblemReport('KernelCrash')
        self.assertEqual(pr['ProblemType'], 'KernelCrash')
        pr = problem_report.ProblemReport(date = '19801224 12:34')
        self.assertEqual(pr['Date'], '19801224 12:34')

    def test_sanity_checks(self):
        '''various error conditions.'''

        pr = problem_report.ProblemReport()
        self.assertRaises(AssertionError, pr.__setitem__, 'a b', '1')
        self.assertRaises(AssertionError, pr.__setitem__, 'a', 1)
        self.assertRaises(AssertionError, pr.__setitem__, 'a', 1)
        self.assertRaises(AssertionError, pr.__setitem__, 'a', (1,))
        self.assertRaises(AssertionError, pr.__setitem__, 'a', ('/tmp/nonexistant', ''))
        self.assertRaises(KeyError, pr.__getitem__, 'Nonexistant')

    def test_compressed_values(self):
        '''handling of CompressedValue values.'''

        large_val = 'A' * 5000000

        pr = problem_report.ProblemReport()
        pr['Foo'] = problem_report.CompressedValue('FooFoo!')
        pr['Bin'] = problem_report.CompressedValue()
        pr['Bin'].set_value('AB' * 10 + '\0' * 10 + 'Z')
        pr['Large'] = problem_report.CompressedValue(large_val)

        self.assertTrue(isinstance(pr['Foo'], problem_report.CompressedValue))
        self.assertTrue(isinstance(pr['Bin'], problem_report.CompressedValue))
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

        pr['Multiline'] = problem_report.CompressedValue('\1\1\1\n\2\2\n\3\3\3')
        self.assertEqual(pr['Multiline'].splitlines(),
            ['\1\1\1', '\2\2', '\3\3\3'])

        # test writing of reports with CompressedValues
        io = StringIO()
        pr.write(io)
        io.seek(0)
        pr = problem_report.ProblemReport()
        pr.load(io)
        self.assertEqual(pr['Foo'], 'FooFoo!')
        self.assertEqual(pr['Bin'], 'AB' * 10 + '\0' * 10 + 'Z')
        self.assertEqual(pr['Large'], large_val)

    def test_write(self):
        '''write() and proper formatting.'''

        pr = problem_report.ProblemReport(date = 'now!')
        pr['Simple'] = 'bar'
        if sys.version.startswith('2'):
            pr['SimpleUTF8'] = '1äö2Φ3'
            pr['SimpleUnicode'] = '1äö2Φ3'.decode('UTF-8')
            pr['TwoLineUnicode'] = 'pi-π\nnu-η'.decode('UTF-8')
            pr['TwoLineUTF8'] = 'pi-π\nnu-η'.decode('UTF-8')
        else:
            pr['SimpleUTF8'] = '1äö2Φ3'.encode('UTF-8')
            pr['SimpleUnicode'] = '1äö2Φ3'
            pr['TwoLineUnicode'] = 'pi-π\nnu-η'
            pr['TwoLineUTF8'] = 'pi-π\nnu-η'
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

        pr = problem_report.ProblemReport(date = 'now!')
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

        pr = problem_report.ProblemReport(date = 'now!')
        pr['File'] = (temp.name,)
        io = StringIO()
        pr.write(io)
        temp.close()

        pr.clear()
        pr['Extra'] = 'appended'
        pr.write(io)

        io.seek(0)
        pr = problem_report.ProblemReport()
        pr.load(io)

        self.assertEqual(pr['Date'], 'now!')
        self.assertEqual(pr['File'], 'AB' * 10 + '\0' * 10 + 'Z')
        self.assertEqual(pr['Extra'], 'appended')

    def test_load(self):
        '''load() with various formatting.'''

        pr = problem_report.ProblemReport()
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

        # last field might not be \n terminated
        pr.load(StringIO(
'''ProblemType: Crash
Date: now!
Simple: bar
WhiteSpace:
 foo
 bar'''))
        self.assertEqual(pr['ProblemType'], 'Crash')
        self.assertEqual(pr['Date'], 'now!')
        self.assertEqual(pr['Simple'], 'bar')
        self.assertEqual(pr['WhiteSpace'], 'foo\nbar')

        pr = problem_report.ProblemReport()
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
        pr = problem_report.ProblemReport()
        self.assertRaises(ValueError, pr.load, invalid_spacing)

        # test that load() cleans up properly
        pr.load(StringIO('ProblemType: Crash'))
        self.assertEqual(list(pr.keys()), ['ProblemType'])

    def test_write_file(self):
        '''writing a report with binary file data.'''

        temp = tempfile.NamedTemporaryFile()
        temp.write('AB' * 10 + '\0' * 10 + 'Z')
        temp.flush()

        pr = problem_report.ProblemReport(date = 'now!')
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
        pr = problem_report.ProblemReport(date = 'now!')
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

        pr = problem_report.ProblemReport(date = 'now!')
        pr['BinFile'] = (tempbin,)
        pr['AscFile'] = (tempasc, False)
        io = StringIO()
        pr.write(io)
        io.seek(0)

        pr = problem_report.ProblemReport()
        pr.load(io)
        self.assertEqual(pr['BinFile'], tempbin.getvalue())
        self.assertEqual(pr['AscFile'], tempasc.getvalue())

    def test_write_empty_fileobj(self):
        '''writing a report with a pointer to a file-like object with enforcing non-emptyness.'''

        tempbin = StringIO('')
        tempasc = StringIO('')

        pr = problem_report.ProblemReport(date = 'now!')
        pr['BinFile'] = (tempbin, True, None, True)
        io = StringIO()
        self.assertRaises(IOError, pr.write, io)

        pr = problem_report.ProblemReport(date = 'now!')
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

        pr = problem_report.ProblemReport(date = 'now!')
        pr['BinFile'] = (os.fdopen(fout),)
        io = StringIO()
        pr.write(io)
        assert os.wait()[1] == 0

        io.seek(0)

        pr2 = problem_report.ProblemReport()
        pr2.load(io)
        self.assertTrue(pr2['BinFile'].endswith('abhello world'))
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
        pr = problem_report.ProblemReport()
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
        self.assertTrue(isinstance(pr['File'], problem_report.CompressedValue))

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
        pr = problem_report.ProblemReport()
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
        pr = problem_report.ProblemReport()
        pr['File'] = (temp.name,)
        pr['Before'] = 'xtestx'
        pr['ZAfter'] = 'ytesty'
        io = StringIO()
        pr.write(io)
        temp.close()

        # read it again
        io.seek(0)
        pr = problem_report.ProblemReport()
        pr.load(io)

        self.assertTrue(pr['File'] == data)
        self.assertEqual(pr['Before'], 'xtestx')
        self.assertEqual(pr['ZAfter'], 'ytesty')

        # write it again
        io2 = StringIO()
        pr.write(io2)
        self.assertTrue(io.getvalue() == io2.getvalue())

        # check gzip compatibility
        io.seek(0)
        pr = problem_report.ProblemReport()
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
        pr = problem_report.ProblemReport()
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
        pr = problem_report.ProblemReport()
        pr.load(io)

        self.assertFalse('FileSmallLimit' in pr)
        self.assertFalse('FileLimitMinus1' in pr)
        self.assertTrue(pr['FileExactLimit'] == data)
        self.assertTrue(pr['FileLimitPlus1'] == data)
        self.assertTrue(pr['FileLimitNone'] == data)
        self.assertEqual(pr['Before'], 'xtestx')
        self.assertEqual(pr['ZAfter'], 'ytesty')

    def test_iter(self):
        '''problem_report.ProblemReport iteration.'''

        pr = problem_report.ProblemReport()
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

        pr = problem_report.ProblemReport()
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
        pr = problem_report.ProblemReport()
        pr['old1'] = '11'
        pr['old2'] = '22'

        (fd, rep) = tempfile.mkstemp()
        os.close(fd)
        pr.write(open(rep, 'w'))

        origstat = os.stat(rep)

        # create a new one and add it
        pr = problem_report.ProblemReport()
        pr.clear()
        pr['new1'] = '33'

        pr.add_to_existing(rep, keep_times=True)

        # check keep_times
        newstat = os.stat(rep)
        self.assertEqual(origstat.st_mode, newstat.st_mode)
        self.assertAlmostEqual(origstat.st_atime, newstat.st_atime, 1)
        self.assertAlmostEqual(origstat.st_mtime, newstat.st_mtime, 1)

        # check report contents
        newpr = problem_report.ProblemReport()
        newpr.load(open(rep))
        self.assertEqual(newpr['old1'], '11')
        self.assertEqual(newpr['old2'], '22')
        self.assertEqual(newpr['new1'], '33')

        # create a another new one and add it, but make sure mtime must be
        # different
        time.sleep(1)
        open(rep).read() # bump atime
        time.sleep(1)

        pr = problem_report.ProblemReport()
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
        newpr = problem_report.ProblemReport()
        newpr.load(open(rep))
        self.assertEqual(newpr['old1'], '11')
        self.assertEqual(newpr['old2'], '22')
        self.assertEqual(newpr['new1'], '33')
        self.assertEqual(newpr['new2'], '44')

        os.unlink(rep)

    def test_write_mime_text(self):
        '''write_mime() for text values.'''

        pr = problem_report.ProblemReport(date = 'now!')
        pr['Simple'] = 'bar'
        if sys.version.startswith('2'):
            pr['SimpleUTF8'] = '1äö2Φ3'
            pr['SimpleUnicode'] = '1äö2Φ3'.decode('UTF-8')
            pr['TwoLineUnicode'] = 'pi-π\nnu-η\n'.decode('UTF-8')
            pr['TwoLineUTF8'] = 'pi-π\nnu-η\n'.decode('UTF-8')
        else:
            pr['SimpleUTF8'] = '1äö2Φ3'.encode('UTF-8')
            pr['SimpleUnicode'] = '1äö2Φ3'
            pr['TwoLineUnicode'] = 'pi-π\nnu-η\n'
            pr['TwoLineUTF8'] = 'pi-π\nnu-η\n'
        pr['SimpleLineEnd'] = 'bar\n'
        pr['TwoLine'] = 'first\nsecond\n'
        pr['InlineMargin'] = 'first\nsecond\nthird\nfourth\nfifth\n'
        pr['Multiline'] = ' foo   bar\nbaz\n  blip  \nline4\nline♥5!!\nłıµ€ ⅝\n'
        pr['Hugeline'] = 'A' * 10000
        io = StringIO()
        pr.write_mime(io)
        io.seek(0)

        msg = email.message_from_file(io)
        parts = [p for p in msg.walk()]
        self.assertEqual(len(parts), 4)

        # first part is the multipart container
        self.assertTrue(parts[0].is_multipart())

        # second part should be an inline text/plain attachments with all short
        # fields
        self.assertTrue(not parts[1].is_multipart())
        self.assertEqual(parts[1].get_content_type(), 'text/plain')
        self.assertEqual(parts[1].get_content_charset(), 'utf-8')
        self.assertEqual(parts[1].get_filename(), None)
        self.assertEqual(parts[1].get_payload(decode=True), '''ProblemType: Crash
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

        # third part should be the Hugeline: field as attachment
        self.assertTrue(not parts[2].is_multipart())
        self.assertEqual(parts[2].get_content_type(), 'text/plain')
        self.assertEqual(parts[2].get_content_charset(), 'utf-8')
        self.assertEqual(parts[2].get_filename(), 'Hugeline.txt')
        self.assertEqual(parts[2].get_payload(decode=True), 'A' * 10000)

        # fourth part should be the Multiline: field as attachment
        self.assertTrue(not parts[3].is_multipart())
        self.assertEqual(parts[3].get_content_type(), 'text/plain')
        self.assertEqual(parts[3].get_content_charset(), 'utf-8')
        self.assertEqual(parts[3].get_filename(), 'Multiline.txt')
        self.assertEqual(parts[3].get_payload(decode=True), ''' foo   bar
baz
  blip  
line4
line♥5!!
łıµ€ ⅝
''')

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

        pr = problem_report.ProblemReport(date = 'now!')
        pr['Context'] = 'Test suite'
        pr['File1'] = (temp.name,)
        pr['File1.gz'] = (tempgz.name,)
        pr['Value1'] = bin_value
        pr['Value1.gz'] = open(tempgz.name).read()
        pr['ZValue'] = problem_report.CompressedValue(bin_value)
        io = StringIO()
        pr.write_mime(io)
        io.seek(0)

        msg = email.message_from_file(io)
        parts = [p for p in msg.walk()]
        self.assertEqual(len(parts), 7)

        # first part is the multipart container
        self.assertTrue(parts[0].is_multipart())

        # second part should be an inline text/plain attachments with all short
        # fields
        self.assertTrue(not parts[1].is_multipart())
        self.assertEqual(parts[1].get_content_type(), 'text/plain')
        self.assertEqual(parts[1].get_content_charset(), 'utf-8')
        self.assertEqual(parts[1].get_filename(), None)
        self.assertEqual(parts[1].get_payload(decode=True),
            'ProblemType: Crash\nContext: Test suite\nDate: now!\n')

        # third part should be the File1: file contents as gzip'ed attachment
        self.assertTrue(not parts[2].is_multipart())
        self.assertEqual(parts[2].get_content_type(), 'application/x-gzip')
        self.assertEqual(parts[2].get_filename(), 'File1.gz')
        f = tempfile.TemporaryFile()
        f.write(parts[2].get_payload(decode=True))
        f.seek(0)
        self.assertEqual(gzip.GzipFile(mode='rb', fileobj=f).read(), bin_value)

        # fourth part should be the File1.gz: file contents as gzip'ed
        # attachment; write_mime() should not compress it again
        self.assertTrue(not parts[3].is_multipart())
        self.assertEqual(parts[3].get_content_type(), 'application/x-gzip')
        self.assertEqual(parts[3].get_filename(), 'File1.gz')
        f = tempfile.TemporaryFile()
        f.write(parts[3].get_payload(decode=True))
        f.seek(0)
        self.assertEqual(gzip.GzipFile(mode='rb', fileobj=f).read(), bin_value)

        # fifth part should be the Value1: value as gzip'ed attachment
        self.assertTrue(not parts[4].is_multipart())
        self.assertEqual(parts[4].get_content_type(), 'application/x-gzip')
        self.assertEqual(parts[4].get_filename(), 'Value1.gz')
        f = tempfile.TemporaryFile()
        f.write(parts[4].get_payload(decode=True))
        f.seek(0)
        self.assertEqual(gzip.GzipFile(mode='rb', fileobj=f).read(), bin_value)

        # sixth part should be the Value1: value as gzip'ed attachment;
        # write_mime should not compress it again
        self.assertTrue(not parts[5].is_multipart())
        self.assertEqual(parts[5].get_content_type(), 'application/x-gzip')
        self.assertEqual(parts[5].get_filename(), 'Value1.gz')
        f = tempfile.TemporaryFile()
        f.write(parts[5].get_payload(decode=True))
        f.seek(0)
        self.assertEqual(gzip.GzipFile(mode='rb', fileobj=f).read(), bin_value)

        # seventh part should be the ZValue: value as gzip'ed attachment;
        # write_mime should not compress it again
        self.assertTrue(not parts[6].is_multipart())
        self.assertEqual(parts[6].get_content_type(), 'application/x-gzip')
        self.assertEqual(parts[6].get_filename(), 'ZValue.gz')
        f = tempfile.TemporaryFile()
        f.write(parts[6].get_payload(decode=True))
        f.seek(0)
        self.assertEqual(gzip.GzipFile(mode='rb', fileobj=f).read(), bin_value)

    def test_write_mime_extra_headers(self):
        '''write_mime() with extra headers.'''

        pr = problem_report.ProblemReport(date = 'now!')
        pr['Simple'] = 'bar'
        pr['TwoLine'] = 'first\nsecond\n'
        io = StringIO()
        pr.write_mime(io, extra_headers={'Greeting': 'hello world',
            'Foo': 'Bar'})
        io.seek(0)

        msg = email.message_from_file(io)
        self.assertEqual(msg['Greeting'], 'hello world')
        self.assertEqual(msg['Foo'], 'Bar')
        parts = [p for p in msg.walk()]
        self.assertEqual(len(parts), 2)

        # first part is the multipart container
        self.assertTrue(parts[0].is_multipart())

        # second part should be an inline text/plain attachments with all short
        # fields
        self.assertTrue(not parts[1].is_multipart())
        self.assertEqual(parts[1].get_content_type(), 'text/plain')
        self.assertTrue('Simple: bar' in parts[1].get_payload(decode=True))

    def test_write_mime_filter(self):
        '''write_mime() with key filters.'''

        bin_value = 'AB' * 10 + '\0' * 10 + 'Z'

        pr = problem_report.ProblemReport(date = 'now!')
        pr['GoodText'] = 'Hi'
        pr['BadText'] = 'YouDontSeeMe'
        pr['GoodBin'] = bin_value
        pr['BadBin'] = 'Y' + '\x05' * 10 + '-'
        io = StringIO()
        pr.write_mime(io, skip_keys=['BadText', 'BadBin'])
        io.seek(0)

        msg = email.message_from_file(io)
        parts = [p for p in msg.walk()]
        self.assertEqual(len(parts), 3)

        # first part is the multipart container
        self.assertTrue(parts[0].is_multipart())

        # second part should be an inline text/plain attachments with all short
        # fields
        self.assertTrue(not parts[1].is_multipart())
        self.assertEqual(parts[1].get_content_type(), 'text/plain')
        self.assertEqual(parts[1].get_content_charset(), 'utf-8')
        self.assertEqual(parts[1].get_filename(), None)
        self.assertEqual(parts[1].get_payload(decode=True), '''ProblemType: Crash
Date: now!
GoodText: Hi
''')

        # third part should be the GoodBin: field as attachment
        self.assertTrue(not parts[2].is_multipart())
        f = tempfile.TemporaryFile()
        f.write(parts[2].get_payload(decode=True))
        f.seek(0)
        self.assertEqual(gzip.GzipFile(mode='rb', fileobj=f).read(), bin_value)

    def test_write_mime_order(self):
        '''write_mime() with keys ordered.'''

        pr = problem_report.ProblemReport(date = 'now!')
        pr['SecondText'] = 'What'
        pr['FirstText'] = 'Who'
        pr['FourthText'] = 'Today'
        pr['ThirdText'] = "I Don't Know"
        io = StringIO()
        pr.write_mime(io, priority_fields=['FirstText', 'SecondText',
            'ThirdText', 'Unknown', 'FourthText'])
        io.seek(0)

        msg = email.message_from_file(io)
        parts = [p for p in msg.walk()]
        self.assertEqual(len(parts), 2)

        # first part is the multipart container
        self.assertTrue(parts[0].is_multipart())

        # second part should be an inline text/plain attachments with all short
        # fields
        self.assertTrue(not parts[1].is_multipart())
        self.assertEqual(parts[1].get_content_type(), 'text/plain')
        self.assertEqual(parts[1].get_content_charset(), 'utf-8')
        self.assertEqual(parts[1].get_filename(), None)
        self.assertEqual(parts[1].get_payload(decode=True), '''FirstText: Who
SecondText: What
ThirdText: I Don't Know
FourthText: Today
ProblemType: Crash
Date: now!
''')

    def test_updating(self):
        '''new_keys() and write() with only_new=True.'''

        pr = problem_report.ProblemReport()
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

        pr = problem_report.ProblemReport()
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
