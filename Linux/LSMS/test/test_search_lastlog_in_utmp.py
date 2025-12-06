import os
import sys
# Fix to workaround importing issues from test cases
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))

import datetime
import unittest
import shutil
from unittest.mock import patch

from scripts.search_lastlog_in_utmp import _check_lastlog_in_umtp, search_lastlog_in_utmp
from scripts.lib.util_utmp import UtmpEntry
from scripts.lib.util_lastlog import LastlogEntry


class TestSearchLastlogInUtmp(unittest.TestCase):

    TempDirectory = "/tmp/TestSearchLastlogInUtmp"

    def setUp(self):
        os.makedirs(TestSearchLastlogInUtmp.TempDirectory)

    def tearDown(self):
        shutil.rmtree(TestSearchLastlogInUtmp.TempDirectory)

    def test_check_lastlog_in_umtp(self):
        utmp_entry = UtmpEntry("[7] [06556] [ts/1] [sqall   ] [pts/1       ] [172.19.80.1         ] [172.19.80.1    ] [2025-01-09T08:10:23,898892+00:00]")
        lastlog_entry = LastlogEntry(1000, "sqall", "pts/1", "172.19.80.1", 1736410223)

        result = _check_lastlog_in_umtp([lastlog_entry], [utmp_entry])
        self.assertEqual(0, len(result))

    def test_check_lastlog_in_umtp_missing_entry(self):
        utmp_entry = UtmpEntry("[7] [06556] [ts/1] [someone   ] [pts/1       ] [172.19.80.1         ] [172.19.80.1    ] [2025-01-09T08:10:23,898892+00:00]")
        lastlog_entry = LastlogEntry(1000, "sqall", "pts/1", "172.19.80.1", 1736410223)

        result = _check_lastlog_in_umtp([lastlog_entry], [utmp_entry])
        self.assertEqual(1, len(result))
        self.assertEqual(1000, result[0].uid)
        self.assertEqual("sqall", result[0].name)
        self.assertEqual("pts/1", result[0].device)
        self.assertEqual("172.19.80.1", result[0].host)
        self.assertEqual(1736410223, result[0].latest_time.timestamp())

    @patch("scripts.search_lastlog_in_utmp.output_error")
    @patch("scripts.search_lastlog_in_utmp.output_finding")
    @patch("scripts.search_lastlog_in_utmp.UTMP_FILE_LOCATIONS", [os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "wtmp_benign")])
    @patch("scripts.search_lastlog_in_utmp.LASTLOG_FILE_LOCATION", os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "lastlog"))
    @patch("scripts.search_lastlog_in_utmp.PASSWD_FILE_LOCATION", os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "passwd"))
    def test_search_lastlog_in_utmp(self, output_finding_mock, output_error_mock):
        search_lastlog_in_utmp()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()

        self.assertTrue("1 missing entry (or entries) in " in output_finding_mock.call_args.args[1])
        self.assertTrue("Missing entry: 1000 sqall pts/1 172.19.80.1 2025-01-09 08:10:23+00:00" in output_finding_mock.call_args.args[1])

    @patch("scripts.search_lastlog_in_utmp.output_error")
    @patch("scripts.search_lastlog_in_utmp.output_finding")
    @patch("scripts.search_lastlog_in_utmp.UTMP_FILE_LOCATIONS", [os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "wtmp_benign2")])
    @patch("scripts.search_lastlog_in_utmp.LASTLOG_FILE_LOCATION", os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "lastlog"))
    @patch("scripts.search_lastlog_in_utmp.PASSWD_FILE_LOCATION", os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "passwd"))
    def test_search_lastlog_in_utmp_no_result(self, output_finding_mock, output_error_mock):
        search_lastlog_in_utmp()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

    @patch("scripts.search_lastlog_in_utmp.output_error")
    @patch("scripts.search_lastlog_in_utmp.output_finding")
    @patch("scripts.search_lastlog_in_utmp.UTMP_FILE_LOCATIONS", [os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "wtmp_benign")])
    @patch("scripts.search_lastlog_in_utmp.LASTLOG_FILE_LOCATION", os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "lastlog"))
    @patch("scripts.search_lastlog_in_utmp.PASSWD_FILE_LOCATION", os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "passwd"))
    @patch("scripts.search_lastlog_in_utmp.MONITORING_MODE", True)
    @patch("scripts.search_lastlog_in_utmp.STATE_DIR", TempDirectory)
    def test_search_lastlog_in_utmp_monitoring_persistence(self, output_finding_mock, output_error_mock):
        search_lastlog_in_utmp()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()

        self.assertTrue("1 missing entry (or entries) in " in output_finding_mock.call_args.args[1])
        self.assertTrue("Missing entry: 1000 sqall pts/1 172.19.80.1 2025-01-09 08:10:23+00:00" in output_finding_mock.call_args.args[1])

        output_finding_mock.reset_mock()

        search_lastlog_in_utmp()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

    @patch("scripts.search_lastlog_in_utmp._check_lastlog_in_umtp")
    @patch("scripts.search_lastlog_in_utmp.output_error")
    @patch("scripts.search_lastlog_in_utmp.output_finding")
    @patch("scripts.search_lastlog_in_utmp.UTMP_FILE_LOCATIONS", [os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "wtmp_benign")])
    @patch("scripts.search_lastlog_in_utmp.LASTLOG_FILE_LOCATION", os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "lastlog"))
    @patch("scripts.search_lastlog_in_utmp.PASSWD_FILE_LOCATION", os.path.join(os.path.dirname(__file__),
                                                                              "resources",
                                                                              "passwd"))
    @patch("scripts.search_lastlog_in_utmp.MONITORING_MODE", True)
    @patch("scripts.search_lastlog_in_utmp.STATE_DIR", TempDirectory)
    def test_search_lastlog_in_utmp_monitoring_persistence_cleanup(self, output_finding_mock, output_error_mock, check_lastlog_in_umtp_mock):
        check_lastlog_in_umtp_mock.return_value = [LastlogEntry(1000, "sqall", "pts/1", "172.19.80.1", 1736410223)]

        search_lastlog_in_utmp()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()

        self.assertTrue("1 missing entry (or entries) in " in output_finding_mock.call_args.args[1])
        self.assertTrue("Missing entry: 1000 sqall pts/1 172.19.80.1 2025-01-09 08:10:23+00:00" in output_finding_mock.call_args.args[1])

        output_finding_mock.reset_mock()
        check_lastlog_in_umtp_mock.return_value = []

        search_lastlog_in_utmp()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

        check_lastlog_in_umtp_mock.return_value = [LastlogEntry(1000, "sqall", "pts/1", "172.19.80.1", 1736410223)]

        search_lastlog_in_utmp()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        self.assertTrue("1 missing entry (or entries) in " in output_finding_mock.call_args.args[1])
        self.assertTrue("Missing entry: 1000 sqall pts/1 172.19.80.1 2025-01-09 08:10:23+00:00" in output_finding_mock.call_args.args[1])
