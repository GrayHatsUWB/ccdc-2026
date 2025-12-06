#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Search running programs whose binary was deleted. Indicator of malicious programs.

Requirements:
None
"""

import os
import re
import sys
from typing import List

from lib.state import load_state, store_state
from lib.util import output_finding, output_error

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.search_deleted_exe import ACTIVATED
    MONITORING_MODE = False
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    MONITORING_MODE = False
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))


def _get_deleted_exe_files() -> List[str]:
    # Get all suspicious processes.
    # The Linux kernel appends " (deleted)" to the target location if file was deleted
    # https://github.com/torvalds/linux/blob/052d534373b7ed33712a63d5e17b2b6cdbce84fd/fs/d_path.c#L256
    fd = os.popen("ls -laR /proc/*/exe 2> /dev/null | grep -v memfd: | grep \\(deleted\\)")
    suspicious_exe_raw = fd.read().strip()
    fd.close()

    current_suspicious_exes = []
    if suspicious_exe_raw.strip():
        for suspicious_exe in suspicious_exe_raw.strip().split("\n"):
            match = re.search(r" (/proc/(\d+)/exe -> .*)$", suspicious_exe)
            if match:
                exe = match.group(1)
                current_suspicious_exes.append(exe)

    # Remove false-positives from result
    for current_suspicious_exe in list(current_suspicious_exes):
        # The Linux kernel can spawn processes that do not point to an executable
        # https://www.uninformativ.de/blog/postings/2022-06-11/0/POSTING-en.html
        match = re.search(r"(/proc/(\d+)/exe -> / \(deleted\))$", current_suspicious_exe)
        if match:
            current_suspicious_exes.remove(current_suspicious_exe)

    return current_suspicious_exes


def search_deleted_exe_files():

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

    current_suspicious_exes = _get_deleted_exe_files()

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
        message = "%d deleted executable file(s) found:\n\n" % len(new_suspicious_exes)
        for suspicious_exe in new_suspicious_exes:
            match = re.search(r"/proc/(\d+)/exe -> .*$", suspicious_exe)
            if not match:
                output_error(__file__, "Unable to parse: %s" % suspicious_exe, False)
                continue
            pid = match.group(1)
            message += "\n%s" % suspicious_exe
            with open("/proc/%s/cmdline" % pid, "rb") as fp:
                cmdline = fp.read()
                # Replace 0-bytes with whitespaces for readability
                cmdline = cmdline.replace(b"\x00", b" ")
                message += "\n/proc/%s/cmdline -> %s" % (pid, cmdline.decode("utf-8"))
            message += "\n"

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
        search_deleted_exe_files()
