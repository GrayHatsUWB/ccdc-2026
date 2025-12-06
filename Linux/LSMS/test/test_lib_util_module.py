import os
import sys
# Fix to workaround importing issues from test cases
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))

import tempfile
import unittest

from scripts.lib.util_module import get_system_modules, SystemModuleException, SystemModuleState, SystemModule, \
    SystemModuleTaintFlag


class TestUtilModule(unittest.TestCase):

    def test_get_system_modules_empty_file(self):
        tmp_file = tempfile.NamedTemporaryFile(mode='w+t')

        modules = get_system_modules(tmp_file.name)

        self.assertEqual([], modules)

    def test_get_system_modules_no_file(self):
        self.assertRaises(SystemModuleException, get_system_modules, "/something_that_does/not/exist")

    def test_get_system_modules_one_line(self):
        tmp_file = tempfile.NamedTemporaryFile(mode='w+t')
        tmp_file.write("mei_pxp 16384 0 - Live 0x0000000000000000")
        tmp_file.flush()

        modules = get_system_modules(tmp_file.name)

        self.assertEqual(1, len(modules))
        self.assertEqual("mei_pxp", modules[0].name)
        self.assertEqual(16384, modules[0].size)
        self.assertEqual(0, modules[0].reference_count)
        self.assertEqual(SystemModuleState.LIVE, modules[0].state)
        self.assertEqual(set([]), modules[0].dependencies)
        self.assertEqual(set([]), modules[0].taint_flags)

    def test_get_system_modules_multiple_lines(self):
        modules_str = ["mei_pxp 16384 0 - Live 0x0000000000000000",
                       "snd_soc_hda_codec 24576 1 snd_soc_avs, Unloading 0x0000000000000000",
                       "nvidia 56823808 2 nvidia_uvm,nvidia_modeset, Loading 0x0000000000000000 (PO)",
                       "rpcsec_gss_krb5 36864 0 - Live 0xffffffffc1611000",
                       "ipv6 450560 32 [permanent], Live 0x7f000000"  # Raspberry Pi
                       ]

        tmp_file = tempfile.NamedTemporaryFile(mode='w+t')
        tmp_file.write("\n".join(modules_str))
        tmp_file.flush()

        modules = get_system_modules(tmp_file.name)

        self.assertEqual(5, len(modules))
        self.assertEqual("mei_pxp", modules[0].name)
        self.assertEqual(16384, modules[0].size)
        self.assertEqual(0, modules[0].reference_count)
        self.assertEqual(SystemModuleState.LIVE, modules[0].state)
        self.assertEqual(set([]), modules[0].dependencies)
        self.assertEqual(set([]), modules[0].taint_flags)

        self.assertEqual("snd_soc_hda_codec", modules[1].name)
        self.assertEqual(24576, modules[1].size)
        self.assertEqual(1, modules[1].reference_count)
        self.assertEqual(SystemModuleState.UNLOADING, modules[1].state)
        self.assertEqual({"snd_soc_avs"}, modules[1].dependencies)
        self.assertEqual(set([]), modules[1].taint_flags)

        self.assertEqual("nvidia", modules[2].name)
        self.assertEqual(56823808, modules[2].size)
        self.assertEqual(2, modules[2].reference_count)
        self.assertEqual(SystemModuleState.LOADING, modules[2].state)
        self.assertEqual({"nvidia_uvm", "nvidia_modeset"}, modules[2].dependencies)
        self.assertEqual({SystemModuleTaintFlag.PROPRIETARY_MODULE, SystemModuleTaintFlag.OOT_MODULE}, modules[2].taint_flags)

        self.assertEqual("rpcsec_gss_krb5", modules[3].name)
        self.assertEqual(36864, modules[3].size)
        self.assertEqual(0, modules[3].reference_count)
        self.assertEqual(SystemModuleState.LIVE, modules[3].state)
        self.assertEqual(set([]), modules[3].dependencies)
        self.assertEqual(set([]), modules[3].taint_flags)

        self.assertEqual("ipv6", modules[4].name)
        self.assertEqual(450560, modules[4].size)
        self.assertEqual(32, modules[4].reference_count)
        self.assertEqual(SystemModuleState.LIVE, modules[4].state)
        self.assertEqual(set(["[permanent]"]), modules[4].dependencies)
        self.assertEqual(set([]), modules[4].taint_flags)

    def test_get_system_modules_illegal_line(self):
        tmp_file = tempfile.NamedTemporaryFile(mode='w+t')
        tmp_file.write("mei_pxp invalid 16384 0 - Live 0x0000000000000000")
        tmp_file.flush()

        self.assertRaises(SystemModuleException, get_system_modules, tmp_file.name)

    def test_SystemModule_from_proc_modules_line(self):
        module = SystemModule.from_proc_modules_line("mei_pxp 16384 0 - Live 0x0000000000000000")

        self.assertEqual("mei_pxp", module.name)
        self.assertEqual(16384, module.size)
        self.assertEqual(0, module.reference_count)
        self.assertEqual(SystemModuleState.LIVE, module.state)
        self.assertEqual(set([]), module.dependencies)

    def test_SystemModule_from_proc_modules_line_illegal(self):
        self.assertRaises(ValueError, SystemModule.from_proc_modules_line, "mei_pxp invalid 0 - Live 0x0000000000000000")
        self.assertRaises(ValueError, SystemModule.from_proc_modules_line, "mei_pxp 123 invalid - Live 0x0000000000000000")
        self.assertRaises(ValueError, SystemModule.from_proc_modules_line, "mei_pxp 16384 0 Live 0x0000000000000000")
        self.assertRaises(ValueError, SystemModule.from_proc_modules_line, "mei_pxp 16384 0 - Li ve 0x0000000000000000")
        self.assertRaises(ValueError, SystemModule.from_proc_modules_line, "mei_pxp 16384 0 - Live 1234")

    def test_SystemModule_eq(self):
        module1 = SystemModule.from_proc_modules_line("mei_pxp 16384 0 - Live 0x0000000000000000")
        module2 = SystemModule.from_proc_modules_line("mei_pxp 16384 0 - Live 0x0000000000000000")
        module3 = SystemModule.from_proc_modules_line("nei_pxp 16384 0 - Live 0x0000000000000000")

        something_else = "something"
        self.assertEqual(module1, module2)
        self.assertNotEqual(module1, module3)
        self.assertNotEqual(module1, something_else)

    def test_SystemModule_hash(self):
        module1 = SystemModule.from_proc_modules_line("mei_pxp 16384 0 - Live 0x0000000000000000")
        module2 = SystemModule.from_proc_modules_line("mei_pxp 16384 0 - Live 0x0000000000000000")
        module3 = SystemModule.from_proc_modules_line("mei_pxp 16384 0 - Live 0x0000000000000000 (PE)")

        hash_set = set()
        hash_set.add(module1)
        hash_set.add(module2)
        hash_set.add(module3)

        self.assertEqual(2, len(hash_set))

        found_module1 = False
        found_module3 = False
        for temp_module in hash_set:
            if temp_module == module1:
                found_module1 = True
            elif temp_module == module3:
                found_module3 = True

        self.assertTrue(found_module1)
        self.assertTrue(found_module3)

    def test_SystemModule_to_dict(self):
        module1 = SystemModule.from_proc_modules_line("mei_pxp 16384 0 - Live 0x0000000000000000 (OE)")
        module2 = SystemModule.from_proc_modules_line("mei_pxp 16384 3 something,else Live 0x0000000000000000")

        module1_dict = module1.to_dict()
        module2_dict = module2.to_dict()

        self.assertEqual("mei_pxp", module1_dict["name"])
        self.assertEqual(16384, module1_dict["size"])
        self.assertEqual(0, module1_dict["reference_count"])
        self.assertEqual("LIVE", module1_dict["state"])
        self.assertEqual([], module1_dict["dependencies"])
        self.assertEqual(2, len(module1_dict["taint_flags"]))
        self.assertEqual({"OOT_MODULE", "UNSIGNED_MODULE"}, set(module1_dict["taint_flags"]))

        self.assertEqual("mei_pxp", module2_dict["name"])
        self.assertEqual(16384, module2_dict["size"])
        self.assertEqual(3, module2_dict["reference_count"])
        self.assertEqual("LIVE", module2_dict["state"])
        self.assertEqual(2, len(module2_dict["dependencies"]))
        self.assertEqual({"something", "else"}, set(module2_dict["dependencies"]))
        self.assertEqual([], module2_dict["taint_flags"])

    def test_SystemModule_from_dict(self):
        module1 = SystemModule.from_proc_modules_line("mei_pxp 16384 0 - Live 0x0000000000000000 (OE)")
        module2 = SystemModule.from_proc_modules_line("mei_pxp 16384 3 something,else Live 0x0000000000000000")

        self.assertEqual(module1, SystemModule.from_dict(module1.to_dict()))
        self.assertEqual(module2, SystemModule.from_dict(module2.to_dict()))
