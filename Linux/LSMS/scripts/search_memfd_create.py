#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Malware uses calls such as memfd_create() to create an anonymous file in RAM that can be run.

Requirements:
None

Reference:
https://www.sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/
"""

import os
import sys

from lib.state import load_state, store_state
from lib.util import output_finding, output_error

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.search_memfd_create import ACTIVATED
    MONITORING_MODE = False
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    MONITORING_MODE = False
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))


def search_deleted_memfd_files():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    last_suspicious_exes = []
    if MONITORING_MODE:
        try:
            stored_data = load_state(STATE_DIR)
            if "suspicious_exes" in stored_data.keys():
                last_suspicious_exes = stored_data["suspicious_exes"]

        except Exception as e:
            output_error(__file__, str(e))
            return

    # Get all suspicious ELF files.
    fd = os.popen("ls -laR /proc/*/exe 2> /dev/null | grep memfd:.*\\(deleted\\)")
    suspicious_exe_raw = fd.read().strip()
    fd.close()

    current_suspicious_exes = []
    if suspicious_exe_raw.strip():
        current_suspicious_exes.extend(suspicious_exe_raw.strip().split("\n"))

    # Extract new findings
    new_suspicious_exes = []
    for current_suspicious_exe in current_suspicious_exes:
        if current_suspicious_exe not in last_suspicious_exes:
            new_suspicious_exes.append(current_suspicious_exe)

    # Remove stored findings that do no longer exist
    for last_suspicious_exe in list(last_suspicious_exes):
        if last_suspicious_exe not in current_suspicious_exes:
            last_suspicious_exes.remove(last_suspicious_exe)

    if new_suspicious_exes:
        message = "Deleted memfd file(s) found:\n\n"
        message += "\n".join(new_suspicious_exes)

        output_finding(__file__, message)

    if MONITORING_MODE:
        try:
            last_suspicious_exes.extend(new_suspicious_exes)
            store_state(STATE_DIR, {"suspicious_exes": last_suspicious_exes})

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
        search_deleted_memfd_files()
