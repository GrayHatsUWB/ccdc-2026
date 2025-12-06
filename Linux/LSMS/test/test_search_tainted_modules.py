import os
import sys

from scripts.lib.util_module import SystemModule

# Fix to workaround importing issues from test cases
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))

import shutil
import unittest
from unittest.mock import patch

from scripts.search_tainted_modules import search_tainted_modules


class TestSearchTaintedModules(unittest.TestCase):

    TempDirectory = "/tmp/TestSearchTaintedModules"

    def setUp(self):
        os.makedirs(TestSearchTaintedModules.TempDirectory)

    def tearDown(self):
        shutil.rmtree(TestSearchTaintedModules.TempDirectory)

    @patch("scripts.search_tainted_modules._get_suspicious_modules")
    @patch("scripts.search_tainted_modules.output_error")
    @patch("scripts.search_tainted_modules.output_finding")
    def test_search_tainted_modules_no_result(self, output_finding_mock, output_error_mock, get_suspicious_modules_mock):
        get_suspicious_modules_mock.return_value = []

        search_tainted_modules()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

    @patch("scripts.search_tainted_modules._get_suspicious_modules")
    @patch("scripts.search_tainted_modules.output_error")
    @patch("scripts.search_tainted_modules.output_finding")
    def test_search_tainted_modules_multi_result(self, output_finding_mock, output_error_mock, get_suspicious_modules_mock):
        module1 = SystemModule.from_dict({'name': 'nvidia_uvm',
                                         'size': 1200128,
                                         'reference_count': 0,
                                         'state': 'LIVE',
                                         'dependencies': [],
                                         'taint_flags': ['PROPRIETARY_MODULE', 'OOT_MODULE', 'UNSIGNED_MODULE']})
        module2 = SystemModule.from_dict({'name': 'nvidia_drm',
                                         'size': 1234,
                                         'reference_count': 2,
                                         'state': 'LIVE',
                                         'dependencies': [],
                                         'taint_flags': ['PROPRIETARY_MODULE', 'OOT_MODULE']})
        get_suspicious_modules_mock.return_value = [module1, module2]

        search_tainted_modules()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        self.assertTrue("2 suspicious loaded module(s) found:" in output_finding_mock.call_args.args[1])
        self.assertTrue("%s - State: %s; Dependencies: %s; Taint Flags: %s" % (module1.name,
                                                                               module1.state.name,
                                                                               ",".join(module1.dependencies),
                                                                               ",".join(map(lambda x: x.name, module1.taint_flags)))
                        in output_finding_mock.call_args.args[1])
        self.assertTrue("%s - State: %s; Dependencies: %s; Taint Flags: %s" % (module2.name,
                                                                               module2.state.name,
                                                                               ",".join(module2.dependencies),
                                                                               ",".join(map(lambda x: x.name, module2.taint_flags)))
                        in output_finding_mock.call_args.args[1])

    @patch("scripts.search_tainted_modules._get_suspicious_modules")
    @patch("scripts.search_tainted_modules.output_error")
    @patch("scripts.search_tainted_modules.output_finding")
    def test_search_tainted_modules_one_result(self, output_finding_mock, output_error_mock, get_suspicious_modules_mock):
        module = SystemModule.from_dict({'name': 'nvidia_uvm',
                                         'size': 1200128,
                                         'reference_count': 0,
                                         'state': 'LIVE',
                                         'dependencies': [],
                                         'taint_flags': ['PROPRIETARY_MODULE', 'OOT_MODULE', 'UNSIGNED_MODULE']})
        get_suspicious_modules_mock.return_value = [module]

        search_tainted_modules()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        self.assertTrue("1 suspicious loaded module(s) found:" in output_finding_mock.call_args.args[1])
        self.assertTrue("%s - State: %s; Dependencies: %s; Taint Flags: %s" % (module.name,
                                                                               module.state.name,
                                                                               ",".join(module.dependencies),
                                                                               ",".join(map(lambda x: x.name, module.taint_flags)))
                        in output_finding_mock.call_args.args[1])

    @patch("scripts.search_tainted_modules._get_suspicious_modules")
    @patch("scripts.search_tainted_modules.output_error")
    @patch("scripts.search_tainted_modules.output_finding")
    @patch("scripts.search_tainted_modules.MONITORING_MODE", True)
    @patch("scripts.search_tainted_modules.STATE_DIR", TempDirectory)
    def test_search_tainted_modules_monitoring_persistence(self, output_finding_mock, output_error_mock, get_suspicious_modules_mock):
        module = SystemModule.from_dict({'name': 'nvidia_uvm',
                                         'size': 1200128,
                                         'reference_count': 0,
                                         'state': 'LIVE',
                                         'dependencies': [],
                                         'taint_flags': ['PROPRIETARY_MODULE', 'OOT_MODULE', 'UNSIGNED_MODULE']})
        get_suspicious_modules_mock.return_value = [module]

        search_tainted_modules()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        self.assertTrue("1 suspicious loaded module(s) found:" in output_finding_mock.call_args.args[1])
        self.assertTrue("%s - State: %s; Dependencies: %s; Taint Flags: %s" % (module.name,
                                                                               module.state.name,
                                                                               ",".join(module.dependencies),
                                                                               ",".join(map(lambda x: x.name, module.taint_flags)))
                        in output_finding_mock.call_args.args[1])

        search_tainted_modules()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()

    @patch("scripts.search_tainted_modules._get_suspicious_modules")
    @patch("scripts.search_tainted_modules.output_error")
    @patch("scripts.search_tainted_modules.output_finding")
    @patch("scripts.search_tainted_modules.MONITORING_MODE", True)
    @patch("scripts.search_tainted_modules.STATE_DIR", TempDirectory)
    def test_search_tainted_modules_monitoring_persistence_cleanup(self, output_finding_mock, output_error_mock, get_suspicious_modules_mock):
        module = SystemModule.from_dict({'name': 'nvidia_uvm',
                                         'size': 1200128,
                                         'reference_count': 0,
                                         'state': 'LIVE',
                                         'dependencies': [],
                                         'taint_flags': ['PROPRIETARY_MODULE', 'OOT_MODULE', 'UNSIGNED_MODULE']})
        get_suspicious_modules_mock.return_value = [module]

        search_tainted_modules()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        self.assertTrue("1 suspicious loaded module(s) found:" in output_finding_mock.call_args.args[1])
        self.assertTrue("%s - State: %s; Dependencies: %s; Taint Flags: %s" % (module.name,
                                                                               module.state.name,
                                                                               ",".join(module.dependencies),
                                                                               ",".join(map(lambda x: x.name, module.taint_flags)))
                        in output_finding_mock.call_args.args[1])

        output_error_mock.reset_mock()
        output_finding_mock.reset_mock()
        get_suspicious_modules_mock.return_value = []

        search_tainted_modules()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_not_called()

        get_suspicious_modules_mock.return_value = [module]

        search_tainted_modules()

        output_error_mock.assert_not_called()
        output_finding_mock.assert_called_once()
        self.assertTrue("1 suspicious loaded module(s) found:" in output_finding_mock.call_args.args[1])
        self.assertTrue("%s - State: %s; Dependencies: %s; Taint Flags: %s" % (module.name,
                                                                               module.state.name,
                                                                               ",".join(module.dependencies),
                                                                               ",".join(map(lambda x: x.name, module.taint_flags)))
                        in output_finding_mock.call_args.args[1])
