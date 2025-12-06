import os
import sys
# Fix to workaround importing issues from test cases
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))

import datetime
import unittest
import shutil
from unittest.mock import patch

from scripts.lib.util_utmp import UtmpEntry
from scripts.search_utmp_tampering import UtmpDetection, _check_utmp_type, _check_utmp_timestamp, _check_utmp_data, \
    search_utmp_tampering

class TestSearchUtmpTampering(unittest.TestCase):

    TempDirectory = "/tmp/TestSearchUtmpTampering"

    def setUp(self):
        os.makedirs(TestSearchUtmpTampering.TempDirectory)

    def tearDown(self):
        shutil.rmtree(TestSearchUtmpTampering.TempDirectory)

    def test_check_utmp_type(self):
        entity_clean = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")
        self.assertEqual(UtmpDetection.Clean, _check_utmp_type(entity_clean))

        entity_zero = UtmpEntry("[0] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")
        self.assertEqual(UtmpDetection.TypeError, _check_utmp_type(entity_zero))

        entity_greater_nine = UtmpEntry("[10] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")
        self.assertEqual(UtmpDetection.TypeError, _check_utmp_type(entity_greater_nine))

    @patch("scripts.search_utmp_tampering.UTMP_OLDEST_ENTRY", datetime.datetime.now() - datetime.timedelta(days=30))
    def test_check_utmp_timestamp(self):
        entity_clean = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")
        self.assertEqual(UtmpDetection.Clean, _check_utmp_timestamp(None, entity_clean, "/var/log/wtmp"))

        entity_time_zero = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [1970-01-01T00:00:00,000000+00:00]")
        self.assertEqual(UtmpDetection.TimeZero, _check_utmp_timestamp(None, entity_time_zero, "/var/log/wtmp"))

        entity_too_old = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-08-15T07:57:42,674975+00:00]")
        self.assertEqual(UtmpDetection.TimeTooOld, _check_utmp_timestamp(None, entity_too_old, "/var/log/wtmp"))

        entity_5after_before_clean = UtmpEntry("[1] [00000] [~~  ] [runlevel  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:47,674975+00:00]")
        self.assertEqual(UtmpDetection.Clean, _check_utmp_timestamp(entity_5after_before_clean, entity_clean, "/var/log/wtmp"))

        entity_6seconds_after_clean = UtmpEntry("[1] [00000] [~~  ] [runlevel  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:48,674975+00:00]")
        self.assertEqual(UtmpDetection.TimeInconsistency, _check_utmp_timestamp(entity_6seconds_after_clean, entity_clean, "/var/log/wtmp"))

        entity_120seconds_after_clean_type_2 = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:59:42,674975+00:00]")
        self.assertEqual(UtmpDetection.Clean, _check_utmp_timestamp(entity_120seconds_after_clean_type_2, entity_clean, "/var/log/wtmp"))

        entity_121seconds_after_clean_type_2 = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:59:43,674975+00:00]")
        self.assertEqual(UtmpDetection.TimeInconsistency, _check_utmp_timestamp(entity_121seconds_after_clean_type_2, entity_clean, "/var/log/wtmp"))
        self.assertEqual(UtmpDetection.Clean, _check_utmp_timestamp(entity_121seconds_after_clean_type_2, entity_clean, "/var/run/utmp"))

    def test_check_utmp_data(self):
        utmp_data = [
            UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]"),
            UtmpEntry("[0] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:43,674975+00:00]"),
            UtmpEntry("[10] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:44,674975+00:00]"),
            UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [1970-01-01T00:00:00,000000+00:00]")
        ]
        results = _check_utmp_data(utmp_data, "/var/log/wtmp")
        self.assertEqual(3, len(results))

    @patch("scripts.search_utmp_tampering._check_utmp_data")
    @patch("scripts.search_utmp_tampering.output_error")
    @patch("scripts.search_utmp_tampering.output_finding")
    @patch("scripts.search_utmp_tampering.UTMP_FILE_LOCATIONS", [os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "wtmp_benign")])
    def test_search_utmp_tampering_no_result(self, output_finding_mock, output_error_mock, check_utmp_data_mock):
        check_utmp_data_mock.return_value = {}

        search_utmp_tampering()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

    @patch("scripts.search_utmp_tampering._check_utmp_data")
    @patch("scripts.search_utmp_tampering.output_error")
    @patch("scripts.search_utmp_tampering.output_finding")
    @patch("scripts.search_utmp_tampering.UTMP_FILE_LOCATIONS", ["/something_that_does/not/exist",
                                                                 os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "wtmp_benign")])
    def test_search_utmp_tampering_file_not_found(self, output_finding_mock, output_error_mock, check_utmp_data_mock):
        check_utmp_data_mock.return_value = {}

        search_utmp_tampering()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

    @patch("scripts.search_utmp_tampering._check_utmp_data")
    @patch("scripts.search_utmp_tampering.output_error")
    @patch("scripts.search_utmp_tampering.output_finding")
    @patch("scripts.search_utmp_tampering.UTMP_FILE_LOCATIONS", [os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "wtmp_benign")])
    @patch("scripts.search_utmp_tampering.MONITORING_MODE", True)
    @patch("scripts.search_utmp_tampering.STATE_DIR", TempDirectory)
    def test_search_utmp_tampering_monitoring_persistence(self, output_finding_mock, output_error_mock, check_utmp_data_mock):
        entry = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")
        check_utmp_data_mock.return_value = {entry: [UtmpDetection.TypeError]}

        search_utmp_tampering()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        self.assertTrue("1 suspicious entry (or entries) in " in output_finding_mock.call_args.args[1])
        self.assertTrue("Line: %s" % entry.line in output_finding_mock.call_args.args[1])
        self.assertTrue("Detections: TypeError" in output_finding_mock.call_args.args[1])

        output_finding_mock.reset_mock()

        search_utmp_tampering()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

    @patch("scripts.search_utmp_tampering._check_utmp_data")
    @patch("scripts.search_utmp_tampering.output_error")
    @patch("scripts.search_utmp_tampering.output_finding")
    @patch("scripts.search_utmp_tampering.UTMP_FILE_LOCATIONS", [os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "wtmp_benign")])
    @patch("scripts.search_utmp_tampering.MONITORING_MODE", True)
    @patch("scripts.search_utmp_tampering.STATE_DIR", TempDirectory)
    def test_search_utmp_tampering_monitoring_persistence_cleanup(self, output_finding_mock, output_error_mock, check_utmp_data_mock):
        entry = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")
        check_utmp_data_mock.return_value = {entry: [UtmpDetection.TypeError]}

        search_utmp_tampering()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        self.assertTrue("1 suspicious entry (or entries) in " in output_finding_mock.call_args.args[1])
        self.assertTrue("Line: %s" % entry.line in output_finding_mock.call_args.args[1])
        self.assertTrue("Detections: TypeError" in output_finding_mock.call_args.args[1])

        output_error_mock.reset_mock()
        output_finding_mock.reset_mock()
        check_utmp_data_mock.return_value = {}

        search_utmp_tampering()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

        check_utmp_data_mock.return_value = {entry: [UtmpDetection.TypeError]}

        search_utmp_tampering()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        self.assertTrue("1 suspicious entry (or entries) in " in output_finding_mock.call_args.args[1])
        self.assertTrue("Line: %s" % entry.line in output_finding_mock.call_args.args[1])
        self.assertTrue("Detections: TypeError" in output_finding_mock.call_args.args[1])
