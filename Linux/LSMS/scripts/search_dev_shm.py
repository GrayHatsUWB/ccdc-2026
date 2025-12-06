#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Search for binaries and scripts in /dev/shm.
Malware that tries to hide is often stored there.

Requirements:
None

Reference:
https://twitter.com/CraigHRowland/status/1268863172825346050
https://twitter.com/CraigHRowland/status/1269196509079166976
"""

import os
import sys

from lib.state import load_state, store_state
from lib.util import output_finding, output_error

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.search_dev_shm import ACTIVATED
    MONITORING_MODE = False
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    MONITORING_MODE = False
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))


def search_suspicious_files():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    last_suspicious_files = []
    if MONITORING_MODE:
        try:
            stored_data = load_state(STATE_DIR)
            if "suspicious_files" in stored_data.keys():
                last_suspicious_files = stored_data["suspicious_files"]

        except Exception as e:
            output_error(__file__, str(e))
            return

    # Get all suspicious ELF files.
    fd = os.popen("find /dev/shm -type f -exec file -p '{}' \\; | grep ELF")
    elf_raw = fd.read().strip()
    fd.close()

    # Get all suspicious script files.
    fd = os.popen("find /dev/shm -type f -exec file -p '{}' \\; | grep script")
    script_raw = fd.read().strip()
    fd.close()

    current_suspicious_files = []
    if elf_raw.strip():
        current_suspicious_files.extend(elf_raw.strip().split("\n"))
    if script_raw.strip():
        current_suspicious_files.extend(script_raw.strip().split("\n"))

    # Extract new findings
    new_suspicious_files = []
    for current_suspicious_file in current_suspicious_files:
        if current_suspicious_file not in last_suspicious_files:
            new_suspicious_files.append(current_suspicious_file)

    # Remove stored findings that do no longer exist
    for last_suspicious_file in list(last_suspicious_files):
        if last_suspicious_file not in current_suspicious_files:
            last_suspicious_files.remove(last_suspicious_file)

    if new_suspicious_files:
        message = "File(s) in /dev/shm suspicious:\n\n"
        message += "\n".join(new_suspicious_files)

        output_finding(__file__, message)

    if MONITORING_MODE:
        try:
            last_suspicious_files.extend(new_suspicious_files)
            store_state(STATE_DIR, {"suspicious_files": last_suspicious_files})

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
        search_suspicious_files()
