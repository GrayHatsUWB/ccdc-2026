# Is the script allowed to run or not?
ACTIVATED = True

# File locations of utmp files
UTMP_FILE_LOCATIONS = ["/var/run/utmp", "/var/log/wtmp", "/var/log/wtmp.1"]  # type: List[str]

# File location of lastlog file
LASTLOG_FILE_LOCATION = "/var/log/lastlog"  # type: str

# File location of passwd file
PASSWD_FILE_LOCATION = "/etc/passwd"  # type: str
