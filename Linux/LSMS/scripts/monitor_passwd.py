#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
* Monitor /etc/passwd for changes to detect malicious attempts to hijack/change users.
* Search /etc/passwd for UID collisions that allow users to impersonate other users.
* Search /etc/passwd for service accounts that use an interactive login shell.

NOTE: The first execution of this script should be done with the argument "--init".
Otherwise, the script will only show you the current state of the environment since no state was established yet.
However, this assumes that the system is uncompromised during the initial execution.
Hence, if you are unsure this is the case you should verify the current state
before monitoring for changes will become an effective security measure.

Requirements:
None

References:
* https://archive.org/details/HalLinuxForensics
"""

import os
import sys
from typing import Dict, Set

import lib.global_vars
from lib.state import load_state, store_state
from lib.util import output_error, output_finding
from lib.util_user import get_system_users, SystemUser

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.monitor_passwd import ACTIVATED, SHELL_NO_LOGIN, SERVICE_ACCOUNT_SHELL_WHITELIST
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))
    SHELL_NO_LOGIN = {"/usr/bin/false",
                      "/bin/false",
                      "/sbin/nologin",
                      "/usr/sbin/nologin",
                      "/usr/bin/nologin",
                      "/bin/nologin"}
    SERVICE_ACCOUNT_SHELL_WHITELIST = {"sync": {"/bin/sync"}}


def _load_state():
    """
    Loads the data stored for passwd monitoring

    @return: stored data
    """
    stored_data = {"passwd": {},
                   "uid_collision": set(),
                   "uid_service_interactive_shell": set()}
    temp_stored_data = load_state(STATE_DIR)
    if "version" in temp_stored_data.keys() and type(temp_stored_data["version"]) == int:
        if temp_stored_data["version"] == 1:  # v1
            for k in temp_stored_data["passwd"].keys():
                stored_data["passwd"][k] = SystemUser.from_passwd_line(temp_stored_data["passwd"][k])

            stored_data["uid_collision"] = set(temp_stored_data["uid_collision"])
            stored_data["uid_service_interactive_shell"] = set(temp_stored_data["uid_service_interactive_shell"])
        else:
            raise ValueError("Unknown state version %d" % temp_stored_data["version"])

    else:  # v0
        stored_data["passwd"] = {}
        for k in temp_stored_data.keys():
            stored_data["passwd"][k] = SystemUser.from_passwd_line(temp_stored_data[k])

    return stored_data


def _store_state(curr_passwd_data: Dict[str, SystemUser],
                 curr_uid_collision_data: Set[int],
                 curr_uid_service_shell_data: Set[int]):
    """
    Stores the data of the passwd monitoring

    @param curr_passwd_data: current passwd data
    @param curr_uid_collision_data:  current uid collision data
    @param curr_uid_service_shell_data:  current service account interactive shell data
    """
    temp_data = {"version": 1,
                 "passwd": {},
                 "uid_collision": list(curr_uid_collision_data),
                 "uid_service_interactive_shell": list(curr_uid_service_shell_data)}
    for k in curr_passwd_data.keys():
        temp_data["passwd"][k] = str(curr_passwd_data[k])
    store_state(STATE_DIR, temp_data)


def _get_passwd() -> Dict[str, SystemUser]:
    """
    Gets passwd data from /etc/passwd

    @return: passwd data as dictionary key=username, value=SystemUser
    """
    passwd_data = {}
    for user_obj in get_system_users():
        passwd_data[user_obj.name] = user_obj

    return passwd_data


def _check_changes(stored_passwd_data: Dict[str, SystemUser], curr_passwd_data: Dict[str, SystemUser]):
    """
    Checks for changes made in the passwd data

    @param stored_passwd_data: reference passwd data to check against
    @param curr_passwd_data: current passwd data
    """
    # Compare stored data with current one.
    for stored_entry_user in stored_passwd_data.keys():

        # Extract current entry belonging to the same user.
        if stored_entry_user not in curr_passwd_data.keys():
            message = "User '%s' was deleted." % stored_entry_user

            output_finding(__file__, message)

            continue

        # Check entry was modified.
        if stored_passwd_data[stored_entry_user] != curr_passwd_data[stored_entry_user]:
            message = "Passwd entry for user '%s' was modified.\n\n" % stored_entry_user
            message += "Old entry: %s\n" % stored_passwd_data[stored_entry_user]
            message += "New entry: %s" % curr_passwd_data[stored_entry_user]

            output_finding(__file__, message)

    # Check new data was added.
    for curr_entry_user in curr_passwd_data.keys():
        if curr_entry_user not in stored_passwd_data.keys():
            message = "User '%s' was added.\n\n" % curr_entry_user
            message += "Entry: %s" % curr_passwd_data[curr_entry_user]

            output_finding(__file__, message)


def _check_uid_collision(stored_uid_collision_data: Set[int], curr_passwd_data: Dict[str, SystemUser]) -> Set[int]:
    """
    Checks for UID collisions in the passwd data

    @param stored_uid_collision_data: already detected UID collisions
    @param curr_passwd_data: current passwd data
    @return: current UIDs that collide
    """
    curr_uid_collision_data = set([])
    uid_processed = set([])

    # Search for UID collisions
    for k in curr_passwd_data.keys():
        if curr_passwd_data[k].uid in uid_processed:
            curr_uid_collision_data.add(curr_passwd_data[k].uid)
            continue

        uid_processed.add(curr_passwd_data[k].uid)

    new_uid_collisions = curr_uid_collision_data - stored_uid_collision_data
    if new_uid_collisions:
        message = "UID collisions found.\n\n"
        for uid_collision in new_uid_collisions:
            message += "UID: %d\n" % uid_collision
            for user in filter(lambda x: x.uid == uid_collision, curr_passwd_data.values()):
                message += "Entry: %s\n" % user
            message += "\n"

        output_finding(__file__, message)

    no_longer_collisions = stored_uid_collision_data - curr_uid_collision_data
    if no_longer_collisions:
        message = "UID collisions no longer exist.\n\n"
        for uid_collision in no_longer_collisions:
            message += "UID: %d\n" % uid_collision
            for user in filter(lambda x: x.uid == uid_collision, curr_passwd_data.values()):
                message += "Entry: %s\n" % user
            message += "\n"

        output_finding(__file__, message)

    return curr_uid_collision_data


def _check_service_account_interactive_shell(stored_uid_service_shell_data: Set[int], curr_passwd_data: Dict[str, SystemUser]):
    """
    Checks for service accounts that use an interactive shell

    @param stored_uid_service_shell_data: already detected service accounts
    @param curr_passwd_data: current passwd data
    @return: current UIDs of service accounts with interactive shell
    """

    curr_uid_service_shell_data = set([])

    # Find all service accounts that have an interactive shell
    for user in curr_passwd_data.values():

        # Accounts uid < 1000 are service accounts (ignoring 0 as it is root)
        if user.uid > 999 or user.uid == 0:
            continue

        # Ignore accounts that do not have an interactive shell
        if user.shell in SHELL_NO_LOGIN:
            continue

        # Ignore accounts which are whitelisted
        if (user.name in SERVICE_ACCOUNT_SHELL_WHITELIST.keys()
                and user.shell in SERVICE_ACCOUNT_SHELL_WHITELIST[user.name]):
            continue

        curr_uid_service_shell_data.add(user.uid)

    new_uid_service_shell_data = curr_uid_service_shell_data - stored_uid_service_shell_data
    if new_uid_service_shell_data:
        message = "Service accounts with interactive shell found.\n\n"
        for uid_service in new_uid_service_shell_data:
            for user in filter(lambda x: x.uid == uid_service, curr_passwd_data.values()):
                message += "Entry: %s\n" % user

        output_finding(__file__, message)

    removed_uid_service_shell_data = stored_uid_service_shell_data - curr_uid_service_shell_data
    if removed_uid_service_shell_data:
        message = "Service accounts removed interactive shell.\n\n"
        for uid_service in removed_uid_service_shell_data:
            for user in filter(lambda x: x.uid == uid_service, curr_passwd_data.values()):
                message += "Entry: %s\n" % user

        output_finding(__file__, message)

    return curr_uid_service_shell_data


def monitor_passwd():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    stored_data = {}
    try:
        stored_data = _load_state()
    except Exception as e:
        output_error(__file__, str(e))
        return

    curr_passwd_data = {}
    try:
        curr_passwd_data = _get_passwd()

    except Exception as e:
        output_error(__file__, str(e))
        return

    _check_changes(stored_data["passwd"], curr_passwd_data)
    curr_uid_collision_data = _check_uid_collision(stored_data["uid_collision"], curr_passwd_data)
    curr_uid_service_shell_data = _check_service_account_interactive_shell(stored_data["uid_service_interactive_shell"], curr_passwd_data)

    try:
        _store_state(curr_passwd_data, curr_uid_collision_data, curr_uid_service_shell_data)

    except Exception as e:
        output_error(__file__, str(e))


if __name__ == '__main__':
    if len(sys.argv) > 1:
        # Suppress output in our initial execution to establish a state.
        if "--init" in sys.argv:
            lib.global_vars.SUPPRESS_OUTPUT = True
    monitor_passwd()
