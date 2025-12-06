#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Searches for indicators that utmp, wtmp and btmp were tampered with.
These files keep track of all logins and logouts to the system.

utmp - maintains a full accounting of the current status of the system, system boot time (used by uptime),
recording user logins at which terminals, logouts, system events etc.

wtmp - acts as a historical utmp

btmp - records failed login attempts

The following detections are possible:

TypeError - the type of the utmp entry is invalid since only 1-9 are allowed as value according to utmp(5)

TimeZero - the timestamp is set to zero and hence the entry could be trashed by a malicious clean-up tool

TimeTooOld - the timestamp in the entry is older than the one configured and could be set by a malicious clean-up tool

TimeInconsistency - the timestamp in the entry is not in chronological order as it usually is the case
(except for a few seconds/minutes depending on the system load/state)

NOTE: On RaspberryPis there are entries in wtmp and utmp which trigger TimeZero detection. It seems that these
entries are generated during boot time when the system time is not yet initialized.

Requirements:
pip package `python-dateutil`

Reference:
- https://en.wikipedia.org/wiki/Utmp
- https://sandflysecurity.com/blog/using-linux-utmpdump-for-forensics-and-detecting-log-file-tampering
"""

import datetime
import enum
import os
import sys
from typing import Dict, List, Optional, cast

from lib.state import load_state, store_state
from lib.util import output_error, output_finding
from lib.util_utmp import UtmpEntry, parse_utmp_file

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.search_utmp_tampering import ACTIVATED, UTMP_FILE_LOCATIONS, UTMP_OLDEST_ENTRY
    MONITORING_MODE = False
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    MONITORING_MODE = False
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))
    UTMP_FILE_LOCATIONS = ["/var/run/utmp", "/var/log/wtmp", "/var/log/btmp"]
    UTMP_OLDEST_ENTRY = datetime.datetime.now() - datetime.timedelta(days=3650)


class UtmpDetection(enum.Enum):
    Clean = 0
    TypeError = 1
    TimeZero = 2
    TimeTooOld = 3
    TimeInconsistency = 4


def _check_utmp_data(utmp_data: List[UtmpEntry], utmp_file: str) -> Dict[UtmpEntry, List[UtmpDetection]]:
    """
    Checks utmp data for suspicious entries.
    """
    detections = {}
    prev_entry = None
    for entry in utmp_data:
        entry_detections = []
        result = _check_utmp_type(entry)
        if result != UtmpDetection.Clean:
            entry_detections.append(result)

        result = _check_utmp_timestamp(prev_entry, entry, utmp_file)
        if result != UtmpDetection.Clean:
            entry_detections.append(result)

        if entry_detections:
            detections[entry] = entry_detections
        prev_entry = entry

    return detections


def _check_utmp_type(entry: UtmpEntry) -> UtmpDetection:
    """
    Checks the type value of the utmp entry for sanity.
    """
    # Only valid values are 1-9 according to utmp(5)
    if 0 < entry.ut_type <= 9:
        return UtmpDetection.Clean
    return UtmpDetection.TypeError


def _check_utmp_timestamp(prev: Optional[UtmpEntry], curr: UtmpEntry, utmp_file: str) -> UtmpDetection:
    """
    Checks the timestamp value of the utmp entry for sanity.
    """
    if curr.ut_time.year == 1970 and curr.ut_time.month == 1 and curr.ut_time.day == 1:
        return UtmpDetection.TimeZero

    if curr.ut_time.replace(tzinfo=None) < UTMP_OLDEST_ENTRY:
        return UtmpDetection.TimeTooOld

    # Ignore /var/run/utmp in the time inconsistency check because entries are not in chronological order in this file
    if prev is not None and not os.path.basename(utmp_file).endswith("utmp") and curr.ut_time < prev.ut_time:
        # If the current entry is younger than the previous one, check the difference between both
        # (since usually the difference is only a few microseconds in normal circumstances).
        # To be on the safe side we allow a few seconds difference.
        # Furthermore, type 2 (BOOT_TIME) in Microsoft WSL has sometimes greater differences.
        difference_in_seconds = (prev.ut_time - curr.ut_time).total_seconds()
        if ((prev.ut_type != 2 and difference_in_seconds > 5)
            or (prev.ut_type == 2 and difference_in_seconds > 120)):
                return UtmpDetection.TimeInconsistency

    return UtmpDetection.Clean


def search_utmp_tampering():
    """
    Starts the search for utmp tampering indicators in all configured files.
    """
    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    # Load last results if monitoring mode is active
    last_results = {}   # type: Dict[str, Dict[UtmpEntry, List[UtmpDetection]]]
    if MONITORING_MODE:
        try:
            stored_data = load_state(STATE_DIR)
            if "detections" in stored_data.keys():
                for utmp_file, stored_detections in stored_data["detections"].items():
                    last_results[utmp_file] = {}
                    for k, v in stored_detections.items():
                        last_results[utmp_file][UtmpEntry(k)] = cast(List[UtmpDetection], list(map(lambda x: UtmpDetection[x], v)))

        except Exception as e:
            output_error(__file__, str(e))
            return

    new_results = {}  # type: Dict[str, Dict[UtmpEntry, List[UtmpDetection]]]
    for utmp_file in UTMP_FILE_LOCATIONS:
        if not os.path.isfile(utmp_file):
            continue

        utmp_data = []
        try:
            utmp_data = parse_utmp_file(utmp_file)
        except Exception as e:
            output_error(__file__, str(e))
            continue

        detections = _check_utmp_data(utmp_data, utmp_file)

        # Check if a new detection has occurred
        # (in non-monitoring mode this will always yield new detections)
        has_new_detections = False
        if utmp_file not in last_results:
            has_new_detections = True
        else:
            for k, v in detections.items():
                if k in last_results[utmp_file] and last_results[utmp_file][k] == v:
                    continue
                has_new_detections = True

        # Only output findings if we have a new detection
        if has_new_detections and detections:
            message = "%d suspicious entry (or entries) in %s found:\n\n" % (len(detections), utmp_file)
            for k, v in detections.items():
                message += "\nLine: %s" % k.line
                message += "\nDetections: %s\n" % ", ".join(map(lambda x: x.name, v))

            output_finding(__file__, message)

        new_results[utmp_file] = detections

    # Store results if monitoring mode is active
    if MONITORING_MODE:
        try:
            temp_results = {}  # type: Dict[str, Dict[str, List[UtmpDetection]]]
            for utmp_file, temp_detections in new_results.items():
                temp_results[utmp_file] = {}
                for k, v in temp_detections.items():
                    temp_results[utmp_file][k.line] = list(map(lambda x: x.name, v))

            store_state(STATE_DIR, {"detections": temp_results})

        except Exception as e:
            output_error(__file__, str(e))


if __name__ == '__main__':
    is_init_run = False
    if len(sys.argv) == 2:
        if sys.argv[1] == "--init":
            is_init_run = True
        if "--monitoring" in sys.argv:
            MONITORING_MODE = True

    # Script does not need to establish a state.
    if not is_init_run:
        search_utmp_tampering()
