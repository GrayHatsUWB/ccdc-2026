#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Searches if all lastlog entries are also present in utmp and wtmp files. Otherwise, indicators for tampered
utmp and wtmp files are found.

lastlog - contains an entry of the last login of a user

utmp - maintains a full accounting of the current status of the system, system boot time (used by uptime),
recording user logins at which terminals, logouts, system events etc.

wtmp - acts as a historical utmp

Requirements:
pip package `python-dateutil`

Reference:
- https://en.wikipedia.org/wiki/Utmp
- https://sandflysecurity.com/blog/using-linux-utmpdump-for-forensics-and-detecting-log-file-tampering
"""

import os
import sys
from typing import List

from lib.state import load_state, store_state
from lib.util import output_error, output_finding
from lib.util_utmp import UtmpEntry, parse_utmp_file
from lib.util_lastlog import LastlogEntry, parse_lastlog_file

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.search_lastlog_in_utmp import ACTIVATED, UTMP_FILE_LOCATIONS, LASTLOG_FILE_LOCATION, \
        PASSWD_FILE_LOCATION
    MONITORING_MODE = False
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    MONITORING_MODE = False
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))
    UTMP_FILE_LOCATIONS = ["/var/run/utmp", "/var/log/wtmp"]
    LASTLOG_FILE_LOCATION = "/var/log/lastlog"
    PASSWD_FILE_LOCATION = "/etc/passwd"


def _check_lastlog_in_umtp(lastlog_data: List[LastlogEntry], utmp_data: List[UtmpEntry]) -> List[LastlogEntry]:
    """
    Checks if lastlog data is part of the utmp data.
    :param lastlog_data: List of LastlogEntry objects to check
    :param utmp_data: List of UtmpEntry objects to check against
    :return: List of LastlogEntry objects that are missing in the utmp data
    """
    result = []
    for lastlog_entry in lastlog_data:
        if not any(map(lambda x: x.ut_user == lastlog_entry.name
                                 # The timestamp in lastlog does only have a second precision, while the
                                 # one in utmp has microsecond precision
                                 and x.ut_time.year == lastlog_entry.latest_time.year
                                 and x.ut_time.month == lastlog_entry.latest_time.month
                                 and x.ut_time.day == lastlog_entry.latest_time.day
                                 and x.ut_time.hour == lastlog_entry.latest_time.hour
                                 and x.ut_time.minute == lastlog_entry.latest_time.minute
                                 and x.ut_time.second == lastlog_entry.latest_time.second,
                       utmp_data)):
            result.append(lastlog_entry)

    return result


def search_lastlog_in_utmp():
    """
    Starts the search if lastlog entries are present in utmp files.
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
    last_missing_entries = []   # type: List[LastlogEntry]
    if MONITORING_MODE:
        try:
            stored_data = load_state(STATE_DIR)
            if "missing_entries" in stored_data.keys():
                last_missing_entries = list(map(lambda x: LastlogEntry.from_dict(x), stored_data["missing_entries"]))

        except Exception as e:
            output_error(__file__, str(e))
            return

    lastlog_data = []
    try:
        lastlog_data = parse_lastlog_file(LASTLOG_FILE_LOCATION, PASSWD_FILE_LOCATION)
    except Exception as e:
        output_error(__file__, str(e))
        return

    utmp_data = []
    for utmp_file in UTMP_FILE_LOCATIONS:
        if not os.path.isfile(utmp_file):
            continue

        try:
            utmp_data.extend(parse_utmp_file(utmp_file))
        except Exception as e:
            output_error(__file__, str(e))
            continue

    missing_entries = _check_lastlog_in_umtp(lastlog_data, utmp_data)

    # Check if a new detection has occurred
    # (in non-monitoring mode this will always yield new detections)
    has_new_detections = False

    for missing_entry in missing_entries:
        if missing_entry not in last_missing_entries:
            has_new_detections = True
            break

    # Only output findings if we have a new detection
    if has_new_detections and missing_entries:
        message = "%d missing entry (or entries) in %s found:\n\n" % (len(missing_entries), LASTLOG_FILE_LOCATION)
        for missing_entry in missing_entries:
            message += "\nMissing entry: %s" % missing_entry

        output_finding(__file__, message)

    # Store results if monitoring mode is active
    if MONITORING_MODE:
        try:
            store_state(STATE_DIR, {"missing_entries": list(map(lambda x: x.to_dict(), missing_entries))})

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
        search_lastlog_in_utmp()
