#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Search combinations of taint flags of loaded kernel modules that are an indicator of a malicious module.
A suspicious combination is an unsigned module flag with an out-of-tree build flag.

Requirements:
None

Reference:
https://twitter.com/CraigHRowland/status/1642263411437506561
"""

import os
import sys
from typing import List

from lib.state import load_state, store_state
from lib.util import output_finding, output_error
from lib.util_module import SystemModule, SystemModuleTaintFlag, get_system_modules

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.search_tainted_modules import ACTIVATED, MODULES_WHITELIST
    MONITORING_MODE = False
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    MODULES_WHITELIST = []
    MONITORING_MODE = False
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))


def _get_suspicious_modules() -> List[SystemModule]:
    suspicious_modules = []
    modules = get_system_modules()

    for module in modules:

        if module.name in MODULES_WHITELIST:
            continue

        # Suspicious modules are out-of-tree (not part of the Linux kernel tree) and are unsigned
        if (SystemModuleTaintFlag.OOT_MODULE in module.taint_flags
            and SystemModuleTaintFlag.UNSIGNED_MODULE in module.taint_flags):

            suspicious_modules.append(module)

    return suspicious_modules


def search_tainted_modules():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    last_suspicious_modules = []
    if MONITORING_MODE:
        try:
            stored_data = load_state(STATE_DIR)
            if "suspicious_modules" in stored_data.keys():
                last_suspicious_modules = list(map(lambda x: SystemModule.from_dict(x), stored_data["suspicious_modules"]))

        except Exception as e:
            output_error(__file__, str(e))
            return

    current_suspicious_modules = _get_suspicious_modules()

    # Extract new findings
    new_suspicious_modules = []
    for current_suspicious_module in current_suspicious_modules:
        if current_suspicious_module not in last_suspicious_modules:
            new_suspicious_modules.append(current_suspicious_module)

    # Remove stored findings that do no longer exist
    for last_suspicious_module in list(last_suspicious_modules):
        if last_suspicious_module not in current_suspicious_modules:
            last_suspicious_modules.remove(last_suspicious_module)

    if new_suspicious_modules:
        message = "%d suspicious loaded module(s) found:\n\n" % len(new_suspicious_modules)
        for suspicious_module in new_suspicious_modules:

            message += "%s - State: %s; Dependencies: %s; Taint Flags: %s\n" % (suspicious_module.name,
                                                                              suspicious_module.state.name,
                                                                              ",".join(suspicious_module.dependencies),
                                                                              ",".join(map(lambda x: x.name, suspicious_module.taint_flags)))

        output_finding(__file__, message)

    if MONITORING_MODE:
        try:
            last_suspicious_modules.extend(new_suspicious_modules)
            store_state(STATE_DIR, {"suspicious_modules": list(map(lambda x: x.to_dict(), last_suspicious_modules))})

        except Exception as e:
            output_error(__file__, str(e))


if __name__ == '__main__':
    is_init_run = False
    if len(sys.argv) > 1:
        if "--init" in sys.argv:
            is_init_run = True
        if "--monitoring" in sys.argv:
            MONITORING_MODE = True

    # Script does not need to establish a state.
    if not is_init_run:
        search_tainted_modules()
