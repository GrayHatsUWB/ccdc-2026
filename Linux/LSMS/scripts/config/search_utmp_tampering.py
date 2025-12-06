import datetime
from typing import List

# Is the script allowed to run or not?
ACTIVATED = True

# File locations of utmp files
UTMP_FILE_LOCATIONS = ["/var/run/utmp", "/var/log/wtmp", "/var/log/wtmp.1", "/var/log/btmp"]  # type: List[str]

# Oldest allowed timestamp entry in utmp file
UTMP_OLDEST_ENTRY = datetime.datetime.now() - datetime.timedelta(days=3650)  # type: datetime.datetime
