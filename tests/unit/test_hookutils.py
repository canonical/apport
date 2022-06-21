import time
import unittest
import unittest.mock

import apport.hookutils


class T(unittest.TestCase):
    @unittest.mock.patch("apport.hookutils.root_command_output")
    def test_attach_dmesg(self, root_command_output_mock):
        '''attach_dmesg()'''
        root_command_output_mock.return_value = '[30804.972250] CPU0 is up'

        report = {}
        apport.hookutils.attach_dmesg(report)
        self.assertEqual(report, {'CurrentDmesg': '[30804.972250] CPU0 is up'})

        root_command_output_mock.assert_called_once_with(['dmesg'])

    def test_dmesg_overwrite(self):
        '''attach_dmesg() does not overwrite already existing data'''

        report = {'CurrentDmesg': 'existingcurrent'}

        apport.hookutils.attach_dmesg(report)
        self.assertEqual(report['CurrentDmesg'], 'existingcurrent')

    @unittest.mock.patch("subprocess.Popen")
    @unittest.mock.patch(
        "os.path.exists", unittest.mock.MagicMock(return_value=True)
    )
    def test_attach_journal_errors_with_date(self, popen_mock):
        popen_mock.return_value.returncode = 0
        popen_mock.return_value.communicate.return_value = (
            b"journalctl output",
            b"",
        )

        report = apport.Report(date="Wed May 18 18:31:08 2022")
        apport.hookutils.attach_journal_errors(report)

        self.assertEqual(popen_mock.call_count, 1)
        self.assertEqual(report.get("JournalErrors"), "journalctl output")
        self.assertEqual(
            popen_mock.call_args[0][0],
            [
                "journalctl",
                "--priority=warning",
                f"--since=@{1652898658 + time.altzone}",
                f"--until=@{1652898678 + time.altzone}",
            ],
        )

    @unittest.mock.patch("subprocess.Popen")
    @unittest.mock.patch(
        "os.path.exists", unittest.mock.MagicMock(return_value=True)
    )
    def test_attach_journal_errors_without_date(self, popen_mock):
        popen_mock.return_value.returncode = 0
        popen_mock.return_value.communicate.return_value = (
            b"journalctl output",
            b"",
        )

        report = apport.Report()
        del report["Date"]
        apport.hookutils.attach_journal_errors(report)

        self.assertEqual(popen_mock.call_count, 1)
        self.assertEqual(report.get("JournalErrors"), "journalctl output")
        self.assertEqual(
            popen_mock.call_args[0][0],
            ["journalctl", "--priority=warning", "-b", "--lines=1000"],
        )

    def test_path_to_key(self):
        '''transforming a file path to a valid report key'''

        self.assertEqual(apport.hookutils.path_to_key('simple.txt'),
                         'simple.txt')
        self.assertEqual(apport.hookutils.path_to_key('path/with/dirs.txt'),
                         'path.with.dirs.txt')
        self.assertEqual(apport.hookutils.path_to_key('/funny:characters!& ".txt'),
                         '.funny.characters.._..txt')
