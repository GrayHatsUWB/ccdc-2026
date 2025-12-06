from typing import Dict, Set

# Is the script allowed to run or not?
ACTIVATED = True

# Shells that do not allow interactive login
SHELL_NO_LOGIN = {"/usr/bin/false",
                  "/bin/false",
                  "/sbin/nologin",
                  "/usr/sbin/nologin",
                  "/usr/bin/nologin",
                  "/bin/nologin"}  # type: Set[str]

# Service accounts that are allowed to have an interactive shell
SERVICE_ACCOUNT_SHELL_WHITELIST = {"sync": {"/bin/sync"}}  # type: Dict[str, Set[str]]