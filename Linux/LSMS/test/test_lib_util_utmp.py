import os
import sys
# Fix to workaround importing issues from test cases
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))

import unittest

from scripts.lib.util_utmp import UtmpEntry, UtmpException, parse_utmp_dump_line, parse_utmp_file

class TestUtilUtmp(unittest.TestCase):

    def test_UtmpEntry(self):
        line1 = "[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]"
        line2 = "[6] [659777] [    ] [sqall    ] [ssh:notty   ] [11.22.33.44       ] [11.22.33.44  ] [2025-09-05T09:38:06,000000+00:00]"
        line3 = "[7] [2654257] [ts/0] [sqall   ] [pts/0       ] [10.42.42.42         ] [10.42.42.42    ] [2024-01-23T07:46:40,563329+00:00]"
        line4 = "[2] [00000] [~~  ] [reboot  ] [~           ] [6.1.0-33-amd64      ] [0.0.0.0        ] [2025-04-21T10:58:14,544986+00:00]"
        UtmpEntry(line1)
        UtmpEntry(line2)
        UtmpEntry(line3)
        UtmpEntry(line4)

    def test_UtmpEntry_illegal_line(self):
        line = "foo[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]"
        self.assertRaises(ValueError, UtmpEntry, line)

    def test_UtmpEntry_eq(self):
        entity1 = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")
        entity2 = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")
        entity3 = UtmpEntry("[3] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")

        something_else = "something"
        self.assertEqual(entity1, entity2)
        self.assertNotEqual(entity1, entity3)
        self.assertNotEqual(entity1, something_else)

    def test_UtmpEntry_hash(self):
        entity1 = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")
        entity2 = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")
        entity3 = UtmpEntry("[3] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")

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

    def test_UtmpEntry_to_dict(self):
        entity1 = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")
        entity2 = UtmpEntry("[3] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")

        entity1_dict = entity1.to_dict()
        entity2_dict = entity2.to_dict()

        self.assertEqual(entity1.line, entity1_dict["line"])

        self.assertEqual(entity2.line, entity2_dict["line"])

    def test_UtmpEntry_from_dict(self):
        entity1 = UtmpEntry("[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")
        entity2 = UtmpEntry("[3] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]")

        self.assertEqual(entity1, UtmpEntry.from_dict(entity1.to_dict()))
        self.assertEqual(entity2, UtmpEntry.from_dict(entity2.to_dict()))

    def test_parse_utmp_dump_line(self):
        line = "[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]"
        entry = parse_utmp_dump_line(line)

        self.assertEqual(line, entry.line)

    def test_parse_utmp_dump_line_malformed(self):
        line = "foo[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.167.4-microsoft-standard-WSL2] [0.0.0.0        ] [2025-09-16T07:57:42,674975+00:00]"
        self.assertRaises(UtmpException, parse_utmp_dump_line, line)

    def test_parse_utmp_file(self):
        utmp_data = parse_utmp_file(os.path.join(os.path.dirname(__file__), "resources", "wtmp_benign"))
        self.assertEqual(551, len(utmp_data))

    def test_parse_utmp_file_no_file(self):
        self.assertRaises(UtmpException, parse_utmp_file, "/something_that_does/not/exist")
