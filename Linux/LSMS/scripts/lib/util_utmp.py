import datetime
import re
import subprocess
from dateutil import parser
from typing import Any, Dict, List


class UtmpException(Exception):
    pass


class UtmpEntry:
    """
    Class that stores an entry of an utmp file.
    """
    def __init__(self,
                 line: str):
        match = re.fullmatch(r"\[(\d+)\] \[(\d+)\] \[(.+)\] \[(.+)\] \[(.+)\] \[(.+)\] \[(.+)\] \[(.+)\]", line)
        if match is None:
            raise ValueError("Unable to parse line (no match) '%s'" % line)

        self._line = line
        self._ut_type = int(match.group(1))
        self._ut_pid = int(match.group(2))
        self._ut_id = match.group(3).strip()
        self._ut_user = match.group(4).strip()
        self._ut_line = match.group(5).strip()
        self._ut_host = match.group(6).strip()
        self._ut_addr_v6 = match.group(7).strip()
        self._ut_time = parser.parse(match.group(8))

    def __eq__(self, other):
        return (hasattr(other, "line")
                and self.line == other.line
                and hasattr(other, "ut_type")
                and self.ut_type == other.ut_type
                and hasattr(other, "ut_pid")
                and self.ut_pid == other.ut_pid
                and hasattr(other, "ut_id")
                and self.ut_id == other.ut_id
                and hasattr(other, "ut_user")
                and self.ut_user == other.ut_user
                and hasattr(other, "ut_line")
                and self.ut_line == other.ut_line
                and hasattr(other, "ut_host")
                and self.ut_host == other.ut_host
                and hasattr(other, "ut_addr_v6")
                and self.ut_addr_v6 == other.ut_addr_v6
                and hasattr(other, "ut_time")
                and self.ut_time == other.ut_time)

    def __hash__(self):
        return hash(self._line)

    def __str__(self):
        return self._line

    @property
    def line(self) -> str:
        return self._line

    @property
    def ut_type(self) -> int:
        return self._ut_type

    @property
    def ut_pid(self) -> int:
        return self._ut_pid

    @property
    def ut_id(self) -> str:
        return self._ut_id

    @property
    def ut_user(self) -> str:
        return self._ut_user

    @property
    def ut_line(self) -> str:
        return self._ut_line

    @property
    def ut_host(self) -> str:
        return self._ut_host

    @property
    def ut_addr_v6(self) -> str:
        return self._ut_addr_v6

    @property
    def ut_time(self) -> datetime.datetime:
        return self._ut_time

    def to_dict(self) -> Dict[str, Any]:
        return {"line": self.line}

    @staticmethod
    def from_dict(utmp_dict: Dict[str, Any]):
        return UtmpEntry(utmp_dict["line"])


def parse_utmp_dump_line(line: str) -> UtmpEntry:
    """
    Parse an utmp dump line into a UtmpEntry object.
    """
    try:
        return UtmpEntry(line)
    except Exception as e:
        raise UtmpException("Unable to parse line '%s'" % line) from e


def parse_utmp_file(file_location: str) -> List[UtmpEntry]:
    """
    Parse an utmp file into a list of UtmpEntry objects.
    """
    p = subprocess.Popen("utmpdump %s" % file_location, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    stderr_str = stderr.decode('utf-8')
    if not (stderr_str.startswith("Utmp dump of") and len(stderr.splitlines()) == 1):
        raise UtmpException("Unable to parse file '%s' with stderr: %s" % (file_location, stderr_str))

    utmp_data = []
    for line in stdout.strip().splitlines():
        utmp_data.append(parse_utmp_dump_line(line.decode("utf-8")))
    return utmp_data
