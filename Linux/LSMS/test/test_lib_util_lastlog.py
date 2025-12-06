import os
import sys
# Fix to workaround importing issues from test cases
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))

import datetime
import unittest
import tempfile
from unittest.mock import patch

from scripts.lib.util_lastlog import LastlogEntry, LastlogException, parse_lastlog_file
from scripts.lib.util_user import SystemUser

class TestUtilLastlog(unittest.TestCase):

    def test_LastlogEntry_eq(self):
        temp_time = int(datetime.datetime.now().timestamp())
        entity1 = LastlogEntry(0, "root", "pts/1", "127.0.0.1", temp_time)
        entity2 = LastlogEntry(0, "root", "pts/1", "127.0.0.1", temp_time)
        entity3 = LastlogEntry(1, "toor", "pts/1", "127.0.0.1", temp_time)

        something_else = "something"
        self.assertEqual(entity1, entity2)
        self.assertNotEqual(entity1, entity3)
        self.assertNotEqual(entity1, something_else)

    def test_LastlogEntry_hash(self):
        temp_time = int(datetime.datetime.now().timestamp())
        entity1 = LastlogEntry(0, "root", "pts/1", "127.0.0.1", temp_time)
        entity2 = LastlogEntry(0, "root", "pts/1", "127.0.0.1", temp_time)
        entity3 = LastlogEntry(1, "toor", "pts/1", "127.0.0.1", temp_time)

        hash_set = set()
        hash_set.add(entity1)
        hash_set.add(entity2)
        hash_set.add(entity3)

        self.assertEqual(2, len(hash_set))

        found_module1 = False
        found_module3 = False
        for temp_module in hash_set:
            if temp_module == entity1:
                found_module1 = True
            elif temp_module == entity3:
                found_module3 = True

        self.assertTrue(found_module1)
        self.assertTrue(found_module3)

    def test_LastlogEntry_to_dict(self):
        temp_time = int(datetime.datetime.now().timestamp())
        entity1 = LastlogEntry(0, "root", "pts/1", "127.0.0.1", temp_time)
        entity2 = LastlogEntry(1, "toor", "pts/1", "127.0.0.1", temp_time)

        entity1_dict = entity1.to_dict()
        entity2_dict = entity2.to_dict()

        self.assertEqual(entity1.uid, entity1_dict["uid"])
        self.assertEqual(entity1.name, entity1_dict["name"])
        self.assertEqual(entity1.device, entity1_dict["device"])
        self.assertEqual(entity1.host, entity1_dict["host"])
        self.assertEqual(entity1.latest_time.timestamp(), entity1_dict["latest_time"])

        self.assertEqual(entity2.uid, entity2_dict["uid"])
        self.assertEqual(entity2.name, entity2_dict["name"])
        self.assertEqual(entity2.device, entity2_dict["device"])
        self.assertEqual(entity2.host, entity2_dict["host"])
        self.assertEqual(entity2.latest_time.timestamp(), entity2_dict["latest_time"])

    def test_LastlogEntry_from_dict(self):
        temp_time = datetime.datetime.now()
        entity1 = LastlogEntry(0, "root", "pts/1", "127.0.0.1", int(temp_time.timestamp()))
        entity2 = LastlogEntry(1, "toor", "pts/1", "127.0.0.1", int(temp_time.timestamp()))

        self.assertEqual(entity1, LastlogEntry.from_dict(entity1.to_dict()))
        self.assertEqual(entity2, LastlogEntry.from_dict(entity2.to_dict()))

    @patch("scripts.lib.util_lastlog.get_system_users")
    def test_parse_lastlog_file(self, get_system_users_mock):
        get_system_users_mock.return_value = [SystemUser("sqall",
                                                         "",
                                                         1000,
                                                         1000,
                                                         "",
                                                         "/home/sqall",
                                                         "/bin/bash")]

        lastlog_entries = parse_lastlog_file(os.path.join(os.path.dirname(__file__), "resources", "lastlog"))

        self.assertEqual(1, len(lastlog_entries))
        self.assertEqual(1000, lastlog_entries[0].uid)
        self.assertEqual("sqall", lastlog_entries[0].name)
        self.assertEqual("pts/1", lastlog_entries[0].device)
        self.assertEqual("172.19.80.1", lastlog_entries[0].host)
        self.assertEqual(datetime.datetime(2025, 1, 9, 8, 10, 23, tzinfo=datetime.timezone.utc),
                         lastlog_entries[0].latest_time)

    def test_parse_lastlog_file_no_file(self):
        self.assertRaises(LastlogException, parse_lastlog_file, "/something_that_does/not/exist")

    @patch("scripts.lib.util_lastlog.get_system_users")
    def test_parse_lastlog_file_parsing_error(self, get_system_users_mock):
        get_system_users_mock.return_value = []
        tmp_file = tempfile.NamedTemporaryFile(mode='w+t')
        tmp_file.write("\x12\x13\x14\x15\x00\x00")
        tmp_file.flush()
        self.assertRaises(LastlogException, parse_lastlog_file, tmp_file.name)

    @patch("scripts.lib.util_lastlog.get_system_users")
    def test_parse_lastlog_file_missing_user(self, get_system_users_mock):
        get_system_users_mock.return_value = []
        parse_lastlog_file(os.path.join(os.path.dirname(__file__), "resources", "lastlog"))
