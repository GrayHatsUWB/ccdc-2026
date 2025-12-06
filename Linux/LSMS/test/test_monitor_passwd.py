import os
import sys
# Fix to workaround importing issues from test cases
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))

import shutil
import unittest
from unittest.mock import patch

from scripts.monitor_passwd import (_check_changes, _check_uid_collision, _check_service_account_interactive_shell,
                                    _load_state, _store_state, monitor_passwd)
from scripts.lib.util_user import SystemUser


class TestMonitorPasswd(unittest.TestCase):

    TempDirectory = "/tmp/TestMonitorPasswd"

    def setUp(self):
        os.makedirs(TestMonitorPasswd.TempDirectory)


    def tearDown(self):
        shutil.rmtree(TestMonitorPasswd.TempDirectory)

    @patch("scripts.monitor_passwd.output_error")
    @patch("scripts.monitor_passwd.output_finding")
    def test_check_changes_user_add(self, output_finding_mock, output_error_mock):
        line = "root:x:0:0:root:/root:/bin/bash"
        stored_passwd_data = {}
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line)}

        _check_changes(stored_passwd_data, curr_passwd_data)

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()

        self.assertTrue("User 'root' was added." in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line in output_finding_mock.call_args.args[1])

    @patch("scripts.monitor_passwd.output_error")
    @patch("scripts.monitor_passwd.output_finding")
    def test_check_changes_user_delete(self, output_finding_mock, output_error_mock):
        line = "root:x:0:0:root:/root:/bin/bash"
        stored_passwd_data = {"root": SystemUser.from_passwd_line(line)}
        curr_passwd_data = {}

        _check_changes(stored_passwd_data, curr_passwd_data)

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()

        self.assertTrue("User 'root' was deleted." in output_finding_mock.call_args.args[1])

    @patch("scripts.monitor_passwd.output_error")
    @patch("scripts.monitor_passwd.output_finding")
    def test_check_changes_user_change(self, output_finding_mock, output_error_mock):
        line_old = "root:x:0:0:root:/root:/bin/dash"
        line_new = "root:x:0:0:root:/root:/bin/bash"
        stored_passwd_data = {"root": SystemUser.from_passwd_line(line_old)}
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line_new)}

        _check_changes(stored_passwd_data, curr_passwd_data)

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()

        self.assertTrue("Passwd entry for user 'root' was modified." in output_finding_mock.call_args.args[1])
        self.assertTrue("Old entry: %s" % line_old in output_finding_mock.call_args.args[1])
        self.assertTrue("New entry: %s" % line_new in output_finding_mock.call_args.args[1])

    @patch("scripts.monitor_passwd.output_error")
    @patch("scripts.monitor_passwd.output_finding")
    def test_check_changes_user_no_change(self, output_finding_mock, output_error_mock):
        line = "root:x:0:0:root:/root:/bin/dash"
        stored_passwd_data = {"root": SystemUser.from_passwd_line(line)}
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line)}

        _check_changes(stored_passwd_data, curr_passwd_data)

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

    @patch("scripts.monitor_passwd.output_error")
    @patch("scripts.monitor_passwd.output_finding")
    def test_check_changes_user_no_entry(self, output_finding_mock, output_error_mock):
        stored_passwd_data = {}
        curr_passwd_data = {}

        _check_changes(stored_passwd_data, curr_passwd_data)

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

    @patch("scripts.monitor_passwd._get_passwd")
    @patch("scripts.monitor_passwd.output_error")
    @patch("scripts.monitor_passwd.output_finding")
    @patch("scripts.monitor_passwd.STATE_DIR", TempDirectory)
    def test_monitor_passwd_no_state(self, output_finding_mock, output_error_mock, get_passwd_mock):
        line = "root:x:0:0:root:/root:/bin/dash"
        get_passwd_mock.return_value = {"root": SystemUser.from_passwd_line(line)}

        monitor_passwd()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()

        self.assertTrue("User 'root' was added." in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line in output_finding_mock.call_args.args[1])


    @patch("scripts.monitor_passwd._get_passwd")
    @patch("scripts.monitor_passwd.output_error")
    @patch("scripts.monitor_passwd.output_finding")
    @patch("scripts.monitor_passwd.STATE_DIR", TempDirectory)
    def test_monitor_passwd_state(self, output_finding_mock, output_error_mock, get_passwd_mock):
        line = "root:x:0:0:root:/root:/bin/dash"
        get_passwd_mock.return_value = {"root": SystemUser.from_passwd_line(line)}

        monitor_passwd()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()

        self.assertTrue("User 'root' was added." in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line in output_finding_mock.call_args.args[1])

        output_error_mock.reset_mock()
        output_finding_mock.reset_mock()

        monitor_passwd()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

        output_error_mock.reset_mock()
        output_finding_mock.reset_mock()

        line_new = "root:x:0:0:root:/root:/bin/bash"
        get_passwd_mock.return_value = {"root": SystemUser.from_passwd_line(line_new)}

        monitor_passwd()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()

        self.assertTrue("Passwd entry for user 'root' was modified." in output_finding_mock.call_args.args[1])
        self.assertTrue("Old entry: %s" % line in output_finding_mock.call_args.args[1])
        self.assertTrue("New entry: %s" % line_new in output_finding_mock.call_args.args[1])


    @patch("scripts.monitor_passwd.load_state")
    @patch("scripts.monitor_passwd.STATE_DIR", TempDirectory)
    def test_load_state_unknown_version(self, load_state_mock):
        load_state_mock.return_value = {"version": -1}
        self.assertRaises(ValueError, _load_state)


    @patch("scripts.monitor_passwd.load_state")
    @patch("scripts.monitor_passwd.STATE_DIR", TempDirectory)
    def test_load_state_v0(self, load_state_mock):
        line = "root:x:0:0:root:/root:/bin/dash"
        load_state_mock.return_value = {"root": line}

        data = _load_state()

        self.assertEqual(3, len(data.keys()))
        self.assertTrue("passwd" in data.keys())
        self.assertTrue("uid_collision" in data.keys())
        self.assertTrue("uid_service_interactive_shell" in data.keys())
        self.assertEqual(dict, type(data["passwd"]))
        self.assertEqual(1, len(data["passwd"].keys()))
        self.assertTrue("root" in data["passwd"].keys())
        self.assertEqual(SystemUser.from_passwd_line(line), data["passwd"]["root"])
        self.assertEqual(set, type(data["uid_collision"]))
        self.assertEqual(0, len(data["uid_collision"]))
        self.assertEqual(set, type(data["uid_service_interactive_shell"]))
        self.assertEqual(0, len(data["uid_service_interactive_shell"]))


    @patch("scripts.monitor_passwd.load_state")
    @patch("scripts.monitor_passwd.STATE_DIR", TempDirectory)
    def test_load_state_v1(self, load_state_mock):
        line = "root:x:0:0:root:/root:/bin/dash"
        load_state_mock.return_value = {"version": 1,
                                        "passwd": {"root": line},
                                        "uid_collision": [1, 2],
                                        "uid_service_interactive_shell": [3, 4]}

        data = _load_state()

        self.assertEqual(3, len(data.keys()))
        self.assertTrue("passwd" in data.keys())
        self.assertTrue("uid_collision" in data.keys())
        self.assertTrue("uid_service_interactive_shell" in data.keys())
        self.assertEqual(dict, type(data["passwd"]))
        self.assertEqual(1, len(data["passwd"].keys()))
        self.assertTrue("root" in data["passwd"].keys())
        self.assertEqual(SystemUser.from_passwd_line(line), data["passwd"]["root"])
        self.assertEqual(set, type(data["uid_collision"]))
        self.assertEqual(2, len(data["uid_collision"]))
        self.assertTrue(1 in data["uid_collision"])
        self.assertTrue(2 in data["uid_collision"])
        self.assertEqual(set, type(data["uid_service_interactive_shell"]))
        self.assertEqual(2, len(data["uid_service_interactive_shell"]))
        self.assertTrue(3 in data["uid_service_interactive_shell"])
        self.assertTrue(4 in data["uid_service_interactive_shell"])


    @patch("scripts.monitor_passwd.STATE_DIR", TempDirectory)
    def test_store_state(self):
        line1 = "root:x:0:0:root:/root:/bin/dash"
        line2 = "toor:x:0:0:root:/root:/bin/bash"
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line1),
                            "toor": SystemUser.from_passwd_line(line2)}
        curr_uid_collision_data = {1, 2}
        curr_uid_service_shell_data = {3, 4}

        _store_state(curr_passwd_data, curr_uid_collision_data, curr_uid_service_shell_data)

        data = _load_state()

        self.assertEqual(3, len(data.keys()))
        self.assertTrue("passwd" in data.keys())
        self.assertTrue("uid_collision" in data.keys())
        self.assertTrue("uid_service_interactive_shell" in data.keys())
        self.assertEqual(dict, type(data["passwd"]))
        self.assertEqual(2, len(data["passwd"].keys()))
        self.assertTrue("root" in data["passwd"].keys())
        self.assertTrue("toor" in data["passwd"].keys())
        self.assertEqual(SystemUser.from_passwd_line(line1), data["passwd"]["root"])
        self.assertEqual(SystemUser.from_passwd_line(line2), data["passwd"]["toor"])
        self.assertEqual(set, type(data["uid_collision"]))
        self.assertEqual(2, len(data["uid_collision"]))
        self.assertTrue(1 in data["uid_collision"])
        self.assertTrue(2 in data["uid_collision"])
        self.assertEqual(set, type(data["uid_service_interactive_shell"]))
        self.assertEqual(2, len(data["uid_service_interactive_shell"]))
        self.assertTrue(3 in data["uid_service_interactive_shell"])
        self.assertTrue(4 in data["uid_service_interactive_shell"])


    @patch("scripts.monitor_passwd.output_finding")
    def test_check_uid_collision_no_collision(self, output_finding_mock):
        line1 = "root:x:0:0:root:/root:/bin/dash"
        line2 = "toor:x:1:0:root:/root:/bin/bash"
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line1),
                            "toor": SystemUser.from_passwd_line(line2)}
        stored_uid_collision_data = set()

        _check_uid_collision(stored_uid_collision_data, curr_passwd_data)

        output_finding_mock.assert_not_called()


    @patch("scripts.monitor_passwd.output_finding")
    def test_check_uid_collision_single_collision(self, output_finding_mock):
        line1 = "root:x:0:0:root:/root:/bin/dash"
        line2 = "toor:x:0:0:root:/root:/bin/bash"
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line1),
                            "toor": SystemUser.from_passwd_line(line2)}
        stored_uid_collision_data = set()

        curr_uid_collision_data = _check_uid_collision(stored_uid_collision_data, curr_passwd_data)

        output_finding_mock.assert_called_once()

        self.assertEqual(1, len(curr_uid_collision_data))
        self.assertTrue(0 in curr_uid_collision_data)
        self.assertTrue("UID collisions found." in output_finding_mock.call_args.args[1])
        self.assertTrue("UID: %d" % curr_passwd_data["root"].uid in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line1 in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line2 in output_finding_mock.call_args.args[1])


    @patch("scripts.monitor_passwd.output_finding")
    def test_check_uid_collision_multi_collision(self, output_finding_mock):
        line_root = "root:x:0:0:root:/root:/bin/dash"
        line_toor = "toor:x:0:0:root:/root:/bin/bash"
        line_r00t = "r00t:x:0:0:root:/root:/bin/bash"
        line_user1 = "user1:x:1:0:root:/root:/bin/bash"
        line_user2 = "user2:x:1:0:root:/root:/bin/bash"
        line_user3 = "user3:x:3:0:root:/root:/bin/bash"
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line_root),
                            "toor": SystemUser.from_passwd_line(line_toor),
                            "r00t": SystemUser.from_passwd_line(line_r00t),
                            "user1": SystemUser.from_passwd_line(line_user1),
                            "user2": SystemUser.from_passwd_line(line_user2),
                            "user3": SystemUser.from_passwd_line(line_user3)}
        stored_uid_collision_data = set()

        curr_uid_collision_data = _check_uid_collision(stored_uid_collision_data, curr_passwd_data)

        output_finding_mock.assert_called_once()

        self.assertEqual(2, len(curr_uid_collision_data))
        self.assertTrue(0 in curr_uid_collision_data)
        self.assertTrue(1 in curr_uid_collision_data)
        self.assertTrue("UID collisions found." in output_finding_mock.call_args.args[1])
        self.assertTrue("UID: %d" % curr_passwd_data["root"].uid in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line_root in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line_toor in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line_r00t in output_finding_mock.call_args.args[1])
        self.assertTrue("UID: %d" % curr_passwd_data["user1"].uid in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line_user1 in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line_user2 in output_finding_mock.call_args.args[1])


    @patch("scripts.monitor_passwd.output_finding")
    def test_check_uid_collision_no_new_collision(self, output_finding_mock):
        line1 = "root:x:0:0:root:/root:/bin/dash"
        line2 = "toor:x:0:0:root:/root:/bin/bash"
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line1),
                            "toor": SystemUser.from_passwd_line(line2)}
        stored_uid_collision_data = {0}

        curr_uid_collision_data = _check_uid_collision(stored_uid_collision_data, curr_passwd_data)

        output_finding_mock.assert_not_called()

        self.assertEqual(1, len(curr_uid_collision_data))
        self.assertTrue(0 in curr_uid_collision_data)


    @patch("scripts.monitor_passwd.output_finding")
    def test_check_uid_collision_mix_new_collision(self, output_finding_mock):
        line_root = "root:x:0:0:root:/root:/bin/dash"
        line_toor = "toor:x:0:0:root:/root:/bin/bash"
        line_r00t = "r00t:x:0:0:root:/root:/bin/bash"
        line_user1 = "user1:x:1:0:root:/root:/bin/bash"
        line_user2 = "user2:x:1:0:root:/root:/bin/bash"
        line_user3 = "user3:x:3:0:root:/root:/bin/bash"
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line_root),
                            "toor": SystemUser.from_passwd_line(line_toor),
                            "r00t": SystemUser.from_passwd_line(line_r00t),
                            "user1": SystemUser.from_passwd_line(line_user1),
                            "user2": SystemUser.from_passwd_line(line_user2),
                            "user3": SystemUser.from_passwd_line(line_user3)}
        stored_uid_collision_data = {0}

        curr_uid_collision_data = _check_uid_collision(stored_uid_collision_data, curr_passwd_data)

        output_finding_mock.assert_called_once()

        self.assertEqual(2, len(curr_uid_collision_data))
        self.assertTrue(0 in curr_uid_collision_data)
        self.assertTrue(1 in curr_uid_collision_data)
        self.assertTrue("UID collisions found." in output_finding_mock.call_args.args[1])
        self.assertFalse("UID: %d" % curr_passwd_data["root"].uid in output_finding_mock.call_args.args[1])
        self.assertFalse("Entry: %s" % line_root in output_finding_mock.call_args.args[1])
        self.assertFalse("Entry: %s" % line_toor in output_finding_mock.call_args.args[1])
        self.assertFalse("Entry: %s" % line_r00t in output_finding_mock.call_args.args[1])
        self.assertTrue("UID: %d" % curr_passwd_data["user1"].uid in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line_user1 in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line_user2 in output_finding_mock.call_args.args[1])


    @patch("scripts.monitor_passwd.output_finding")
    def test_check_uid_collision_no_longer_collision(self, output_finding_mock):
        line_root = "root:x:0:0:root:/root:/bin/dash"
        line_toor = "toor:x:10:0:root:/root:/bin/bash"
        line_r00t = "r00t:x:11:0:root:/root:/bin/bash"
        line_user1 = "user1:x:1:0:root:/root:/bin/bash"
        line_user2 = "user2:x:12:0:root:/root:/bin/bash"
        line_user3 = "user3:x:3:0:root:/root:/bin/bash"
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line_root),
                            "toor": SystemUser.from_passwd_line(line_toor),
                            "r00t": SystemUser.from_passwd_line(line_r00t),
                            "user1": SystemUser.from_passwd_line(line_user1),
                            "user2": SystemUser.from_passwd_line(line_user2),
                            "user3": SystemUser.from_passwd_line(line_user3)}
        stored_uid_collision_data = {0, 1}

        curr_uid_collision_data = _check_uid_collision(stored_uid_collision_data, curr_passwd_data)

        output_finding_mock.assert_called_once()

        self.assertEqual(0, len(curr_uid_collision_data))
        self.assertTrue("UID collisions no longer exist." in output_finding_mock.call_args.args[1])
        self.assertTrue("UID: %d" % curr_passwd_data["root"].uid in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line_root in output_finding_mock.call_args.args[1])
        self.assertTrue("UID: %d" % curr_passwd_data["user1"].uid in output_finding_mock.call_args.args[1])
        self.assertTrue("Entry: %s" % line_user1 in output_finding_mock.call_args.args[1])


    @patch("scripts.monitor_passwd.output_finding")
    def test_check_service_account_interactive_shell_detection(self, output_finding_mock):
        line_root = "root:x:0:0:root:/root:/bin/dash"
        line_service1 = "service1:x:10:0:root:/root:/bin/bash"
        line_service2 = "service2:x:11:0:root:/root:/bin/bash"
        line_service3 = "service3:x:2:0:root:/root:/bin/bash"
        line_service4 = "service4:x:999:0:root:/root:/bin/bash"
        line_user1 = "user1:x:1000:0:root:/root:/bin/bash"
        line_user2 = "user2:x:1001:0:root:/root:/bin/bash"
        line_user3 = "user3:x:1002:0:root:/root:/bin/bash"
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line_root),
                            "service1": SystemUser.from_passwd_line(line_service1),
                            "service2": SystemUser.from_passwd_line(line_service2),
                            "service3": SystemUser.from_passwd_line(line_service3),
                            "service4": SystemUser.from_passwd_line(line_service4),
                            "user1": SystemUser.from_passwd_line(line_user1),
                            "user2": SystemUser.from_passwd_line(line_user2),
                            "user3": SystemUser.from_passwd_line(line_user3)}
        stored_uid_service_shell_data = set()

        curr_uid_service_shell_data = _check_service_account_interactive_shell(stored_uid_service_shell_data, curr_passwd_data)

        output_finding_mock.assert_called_once()

        self.assertEqual(4, len(curr_uid_service_shell_data))
        self.assertTrue(2 in curr_uid_service_shell_data)
        self.assertTrue(10 in curr_uid_service_shell_data)
        self.assertTrue(11 in curr_uid_service_shell_data)
        self.assertTrue(999 in curr_uid_service_shell_data)
        self.assertTrue("Service accounts with interactive shell found." in output_finding_mock.call_args.args[1])
        self.assertTrue(line_service1 in output_finding_mock.call_args.args[1])
        self.assertTrue(line_service2 in output_finding_mock.call_args.args[1])
        self.assertTrue(line_service3 in output_finding_mock.call_args.args[1])
        self.assertTrue(line_service4 in output_finding_mock.call_args.args[1])
        self.assertFalse(line_root in output_finding_mock.call_args.args[1])
        self.assertFalse(line_user1 in output_finding_mock.call_args.args[1])
        self.assertFalse(line_user2 in output_finding_mock.call_args.args[1])
        self.assertFalse(line_user3 in output_finding_mock.call_args.args[1])


    @patch("scripts.monitor_passwd.output_finding")
    def test_check_service_account_interactive_shell_no_new_detection(self, output_finding_mock):
        line_root = "root:x:0:0:root:/root:/bin/dash"
        line_service1 = "service1:x:10:0:root:/root:/bin/bash"
        line_service2 = "service2:x:11:0:root:/root:/bin/bash"
        line_service3 = "service3:x:2:0:root:/root:/bin/bash"
        line_service4 = "service4:x:999:0:root:/root:/bin/bash"
        line_user1 = "user1:x:1000:0:root:/root:/bin/bash"
        line_user2 = "user2:x:1001:0:root:/root:/bin/bash"
        line_user3 = "user3:x:1002:0:root:/root:/bin/bash"
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line_root),
                            "service1": SystemUser.from_passwd_line(line_service1),
                            "service2": SystemUser.from_passwd_line(line_service2),
                            "service3": SystemUser.from_passwd_line(line_service3),
                            "service4": SystemUser.from_passwd_line(line_service4),
                            "user1": SystemUser.from_passwd_line(line_user1),
                            "user2": SystemUser.from_passwd_line(line_user2),
                            "user3": SystemUser.from_passwd_line(line_user3)}
        stored_uid_service_shell_data = {10, 11, 2, 999}

        curr_uid_service_shell_data = _check_service_account_interactive_shell(stored_uid_service_shell_data, curr_passwd_data)

        output_finding_mock.assert_not_called()

        self.assertEqual(4, len(curr_uid_service_shell_data))
        self.assertTrue(2 in curr_uid_service_shell_data)
        self.assertTrue(10 in curr_uid_service_shell_data)
        self.assertTrue(11 in curr_uid_service_shell_data)
        self.assertTrue(999 in curr_uid_service_shell_data)


    @patch("scripts.monitor_passwd.SHELL_NO_LOGIN", {"/some/nologin/value"})
    @patch("scripts.monitor_passwd.output_finding")
    def test_check_service_account_interactive_shell_no_new_detection(self, output_finding_mock):
        line_root = "root:x:0:0:root:/root:/bin/dash"
        line_service1 = "service1:x:10:0:root:/root:/some/nologin/value"
        line_service2 = "service2:x:11:0:root:/root:/bin/bash"
        line_service3 = "service3:x:2:0:root:/root:/some/nologin/value"
        line_service4 = "service4:x:999:0:root:/root:/bin/bash"
        line_user1 = "user1:x:1000:0:root:/root:/bin/bash"
        line_user2 = "user2:x:1001:0:root:/root:/bin/bash"
        line_user3 = "user3:x:1002:0:root:/root:/bin/bash"
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line_root),
                            "service1": SystemUser.from_passwd_line(line_service1),
                            "service2": SystemUser.from_passwd_line(line_service2),
                            "service3": SystemUser.from_passwd_line(line_service3),
                            "service4": SystemUser.from_passwd_line(line_service4),
                            "user1": SystemUser.from_passwd_line(line_user1),
                            "user2": SystemUser.from_passwd_line(line_user2),
                            "user3": SystemUser.from_passwd_line(line_user3)}
        stored_uid_service_shell_data = {10, 11, 2, 999}

        curr_uid_service_shell_data = _check_service_account_interactive_shell(stored_uid_service_shell_data, curr_passwd_data)

        output_finding_mock.assert_called_once()

        self.assertEqual(2, len(curr_uid_service_shell_data))
        self.assertTrue(11 in curr_uid_service_shell_data)
        self.assertTrue(999 in curr_uid_service_shell_data)
        self.assertTrue("Service accounts removed interactive shell." in output_finding_mock.call_args.args[1])
        self.assertTrue(line_service1 in output_finding_mock.call_args.args[1])
        self.assertTrue(line_service3 in output_finding_mock.call_args.args[1])
        self.assertFalse(line_service2 in output_finding_mock.call_args.args[1])
        self.assertFalse(line_service4 in output_finding_mock.call_args.args[1])


    @patch("scripts.monitor_passwd.SERVICE_ACCOUNT_SHELL_WHITELIST", {"service1": {"/bin/bash"}, "service3": {"/bin/bash"}})
    @patch("scripts.monitor_passwd.output_finding")
    def test_check_service_account_interactive_shell_whitelist(self, output_finding_mock):
        line_root = "root:x:0:0:root:/root:/bin/dash"
        line_service1 = "service1:x:10:0:root:/root:/bin/bash"
        line_service2 = "service2:x:11:0:root:/root:/bin/bash"
        line_service3 = "service3:x:2:0:root:/root:/bin/bash"
        line_service4 = "service4:x:999:0:root:/root:/bin/bash"
        line_user1 = "user1:x:1000:0:root:/root:/bin/bash"
        line_user2 = "user2:x:1001:0:root:/root:/bin/bash"
        line_user3 = "user3:x:1002:0:root:/root:/bin/bash"
        curr_passwd_data = {"root": SystemUser.from_passwd_line(line_root),
                            "service1": SystemUser.from_passwd_line(line_service1),
                            "service2": SystemUser.from_passwd_line(line_service2),
                            "service3": SystemUser.from_passwd_line(line_service3),
                            "service4": SystemUser.from_passwd_line(line_service4),
                            "user1": SystemUser.from_passwd_line(line_user1),
                            "user2": SystemUser.from_passwd_line(line_user2),
                            "user3": SystemUser.from_passwd_line(line_user3)}
        stored_uid_service_shell_data = set()

        curr_uid_service_shell_data = _check_service_account_interactive_shell(stored_uid_service_shell_data, curr_passwd_data)

        output_finding_mock.assert_called_once()

        self.assertEqual(2, len(curr_uid_service_shell_data))
        self.assertTrue(11 in curr_uid_service_shell_data)
        self.assertTrue(999 in curr_uid_service_shell_data)
        self.assertTrue(line_service2 in output_finding_mock.call_args.args[1])
        self.assertTrue(line_service4 in output_finding_mock.call_args.args[1])
        self.assertFalse(line_service1 in output_finding_mock.call_args.args[1])
        self.assertFalse(line_service3 in output_finding_mock.call_args.args[1])
