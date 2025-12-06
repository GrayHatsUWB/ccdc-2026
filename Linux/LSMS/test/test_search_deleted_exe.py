import os
import sys
# Fix to workaround importing issues from test cases
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))

import shutil
import unittest
from unittest.mock import patch

from scripts.search_deleted_exe import search_deleted_exe_files


class TestSearchDeletedExe(unittest.TestCase):

    TempDirectory = "/tmp/TestSearchDeletedExe"

    def setUp(self):
        os.makedirs(TestSearchDeletedExe.TempDirectory)

    def tearDown(self):
        shutil.rmtree(TestSearchDeletedExe.TempDirectory)

    @patch("scripts.search_deleted_exe._get_deleted_exe_files")
    @patch("scripts.search_deleted_exe.output_error")
    @patch("scripts.search_deleted_exe.output_finding")
    def test_search_deleted_exe_files_no_result(self, output_finding_mock, output_error_mock, get_deleted_exe_files_mock):
        get_deleted_exe_files_mock.return_value = []

        search_deleted_exe_files()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

    @patch("scripts.search_deleted_exe._get_deleted_exe_files")
    @patch("scripts.search_deleted_exe.output_error")
    @patch("scripts.search_deleted_exe.output_finding")
    def test_search_deleted_exe_files_illegal_line(self, output_finding_mock, output_error_mock, get_deleted_exe_files_mock):
        get_deleted_exe_files_mock.return_value = ["something unexpected"]

        search_deleted_exe_files()

        output_error_mock.assert_called_once()
        self.assertEqual("Unable to parse: something unexpected", output_error_mock.call_args.args[1])
        output_finding_mock.assert_called_once()
        self.assertFalse("something unexpected" in output_finding_mock.call_args.args[1])

    @patch("scripts.search_deleted_exe._get_deleted_exe_files")
    @patch("scripts.search_deleted_exe.output_error")
    @patch("scripts.search_deleted_exe.output_finding")
    def test_search_deleted_exe_files_correct_line(self, output_finding_mock, output_error_mock, get_deleted_exe_files_mock):
        # Use PID of this process for tested routine to gather further information about the process
        pid = os.getpid()

        get_deleted_exe_files_mock.return_value = ["/proc/%d/exe -> /some/bogus/file (deleted)" % pid]

        search_deleted_exe_files()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        self.assertTrue("1 deleted executable file(s) found:" in output_finding_mock.call_args.args[1])
        self.assertTrue("/proc/%d/exe -> /some/bogus/file (deleted)" % pid in output_finding_mock.call_args.args[1])

    @patch("scripts.search_deleted_exe._get_deleted_exe_files")
    @patch("scripts.search_deleted_exe.output_error")
    @patch("scripts.search_deleted_exe.output_finding")
    @patch("scripts.search_deleted_exe.MONITORING_MODE", True)
    @patch("scripts.search_deleted_exe.STATE_DIR", TempDirectory)
    def test_search_deleted_exe_monitoring_persistence(self, output_finding_mock, output_error_mock, get_deleted_exe_files_mock):
        # Use PID of this process for tested routine to gather further information about the process
        pid = os.getpid()

        get_deleted_exe_files_mock.return_value = ["/proc/%d/exe -> /some/bogus/file (deleted)" % pid]

        search_deleted_exe_files()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        self.assertTrue("1 deleted executable file(s) found:" in output_finding_mock.call_args.args[1])
        self.assertTrue("/proc/%d/exe -> /some/bogus/file (deleted)" % pid in output_finding_mock.call_args.args[1])

        search_deleted_exe_files()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()

    @patch("scripts.search_deleted_exe._get_deleted_exe_files")
    @patch("scripts.search_deleted_exe.output_error")
    @patch("scripts.search_deleted_exe.output_finding")
    @patch("scripts.search_deleted_exe.MONITORING_MODE", True)
    @patch("scripts.search_deleted_exe.STATE_DIR", TempDirectory)
    def test_search_deleted_exe_monitoring_persistence_cleanup(self, output_finding_mock, output_error_mock, get_deleted_exe_files_mock):
        # Use PID of this process for tested routine to gather further information about the process
        pid = os.getpid()

        get_deleted_exe_files_mock.return_value = ["/proc/%d/exe -> /some/bogus/file (deleted)" % pid]

        search_deleted_exe_files()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        self.assertTrue("1 deleted executable file(s) found:" in output_finding_mock.call_args.args[1])
        self.assertTrue("/proc/%d/exe -> /some/bogus/file (deleted)" % pid in output_finding_mock.call_args.args[1])

        output_error_mock.reset_mock()
        output_finding_mock.reset_mock()
        get_deleted_exe_files_mock.return_value = []

        search_deleted_exe_files()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

        get_deleted_exe_files_mock.return_value = ["/proc/%d/exe -> /some/bogus/file (deleted)" % pid]

        search_deleted_exe_files()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        self.assertTrue("1 deleted executable file(s) found:" in output_finding_mock.call_args.args[1])
        self.assertTrue("/proc/%d/exe -> /some/bogus/file (deleted)" % pid in output_finding_mock.call_args.args[1])
