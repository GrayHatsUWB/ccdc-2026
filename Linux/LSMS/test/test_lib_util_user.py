import os
import sys
# Fix to workaround importing issues from test cases
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))

import tempfile
import unittest

from scripts.lib.util_user import get_system_users, PasswdException, SystemUser


class TestUtilUser(unittest.TestCase):

    def test_get_system_users_empty_file(self):
        passwd_tmp_file = tempfile.NamedTemporaryFile(mode='w+t')

        users = get_system_users(passwd_tmp_file.name)

        self.assertEqual([], users)

    def test_get_system_users_no_file(self):
        self.assertRaises(PasswdException, get_system_users, "/something_that_does/not/exist")

    def test_get_system_users_one_line(self):
        passwd_tmp_file = tempfile.NamedTemporaryFile(mode='w+t')
        passwd_tmp_file.writelines(["root:x:0:0:root:/root:/bin/bash"])
        passwd_tmp_file.flush()

        users = get_system_users(passwd_tmp_file.name)

        self.assertEqual(1, len(users))
        self.assertEqual("root", users[0].name)
        self.assertEqual("x", users[0].password)
        self.assertEqual(0, users[0].uid)
        self.assertEqual(0, users[0].gid)
        self.assertEqual("root", users[0].info)
        self.assertEqual("/root", users[0].home)
        self.assertEqual("/bin/bash", users[0].shell)

    def test_get_system_users_multiple_lines(self):
        passwd_tmp_file = tempfile.NamedTemporaryFile(mode='w+t')
        passwd_tmp_file.writelines(["root:x:0:0:root:/root:/bin/bash\nsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\nfwupd-refresh:x:129:138:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin"])
        passwd_tmp_file.flush()

        users = get_system_users(passwd_tmp_file.name)

        self.assertEqual(3, len(users))
        self.assertEqual("root", users[0].name)
        self.assertEqual("x", users[0].password)
        self.assertEqual(0, users[0].uid)
        self.assertEqual(0, users[0].gid)
        self.assertEqual("root", users[0].info)
        self.assertEqual("/root", users[0].home)
        self.assertEqual("/bin/bash", users[0].shell)

        self.assertEqual("systemd-coredump", users[1].name)
        self.assertEqual("x", users[1].password)
        self.assertEqual(999, users[1].uid)
        self.assertEqual(999, users[1].gid)
        self.assertEqual("systemd Core Dumper", users[1].info)
        self.assertEqual("/", users[1].home)
        self.assertEqual("/usr/sbin/nologin", users[1].shell)

        self.assertEqual("fwupd-refresh", users[2].name)
        self.assertEqual("x", users[2].password)
        self.assertEqual(129, users[2].uid)
        self.assertEqual(138, users[2].gid)
        self.assertEqual("fwupd-refresh user,,,", users[2].info)
        self.assertEqual("/run/systemd", users[2].home)
        self.assertEqual("/usr/sbin/nologin", users[2].shell)

    def test_get_system_users_illegal_line(self):
        passwd_tmp_file = tempfile.NamedTemporaryFile(mode='w+t')
        passwd_tmp_file.writelines(["root:x:0:0:root"])
        passwd_tmp_file.flush()

        self.assertRaises(PasswdException, get_system_users, passwd_tmp_file.name)

    def test_SystemUser_from_passwd_line(self):
        user = SystemUser.from_passwd_line("root:x:0:0:root:/root:/bin/bash")

        self.assertEqual("root", user.name)
        self.assertEqual("x", user.password)
        self.assertEqual(0, user.uid)
        self.assertEqual(0, user.gid)
        self.assertEqual("root", user.info)
        self.assertEqual("/root", user.home)
        self.assertEqual("/bin/bash", user.shell)

    def test_SystemUser_from_passwd_line_illegal(self):
        self.assertRaises(ValueError, SystemUser.from_passwd_line, "root:x:0:0:root/root:/bin/bash")
        self.assertRaises(ValueError, SystemUser.from_passwd_line, "root:x:0:0:root:/root:/bin/bash:some")
        self.assertRaises(ValueError, SystemUser.from_passwd_line, "root:x:a:0:root:/root:/bin/bash")
        self.assertRaises(ValueError, SystemUser.from_passwd_line, "root:x:0:a:root:/root:/bin/bash")

    def test_SystemUser_eq(self):
        user1 = SystemUser.from_passwd_line("root:x:0:0:root:/root:/bin/bash")
        user2 = SystemUser.from_passwd_line("root:x:0:0:root:/root:/bin/bash")
        user3 = SystemUser.from_passwd_line("toor:x:0:0:root:/root:/bin/bash")

        something_else = "something"
        self.assertEqual(user1, user2)
        self.assertNotEqual(user1, user3)
        self.assertNotEqual(user1, something_else)

    def test_SystemUser_hash(self):
        user1 = SystemUser.from_passwd_line("root:x:0:0:root:/root:/bin/bash")
        user2 = SystemUser.from_passwd_line("root:x:0:0:root:/root:/bin/bash")
        user3 = SystemUser.from_passwd_line("toor:x:0:0:root:/root:/bin/bash")

        hash_set = set()
        hash_set.add(user1)
        hash_set.add(user2)
        hash_set.add(user3)

        self.assertEqual(2, len(hash_set))

        found_user1 = False
        found_user3 = False
        for temp_user in hash_set:
            if temp_user == user1:
                found_user1 = True
            elif temp_user == user3:
                found_user3 = True

        self.assertTrue(found_user1)
        self.assertTrue(found_user3)

    def test_SystemUser_str(self):
        line = "root:x:0:0:root:/root:/bin/bash"
        user = SystemUser.from_passwd_line(line)

        self.assertEqual(line, str(user))
