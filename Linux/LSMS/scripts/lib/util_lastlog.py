import datetime
import os
import struct
from typing import Any, Dict, List

from .util_user import get_system_users


class LastlogException(Exception):
    pass


class LastlogEntry:
    """
    Class that stores an entry of lastlog.
    """
    def __init__(self, uid: int, name: str, device: str, host: str, timestamp: int):
        self._uid = uid
        self._name = name
        self._device = device
        self._host = host
        self._latest_time = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)

    def __eq__(self, other):
        return (hasattr(other, "uid")
                and self.uid == other.uid
                and hasattr(other, "name")
                and self.name == other.name
                and hasattr(other, "device")
                and self.device == other.device
                and hasattr(other, "host")
                and self.host == other.host
                and hasattr(other, "latest_time")
                and self.latest_time == other.latest_time)

    def __hash__(self):
        return hash((self.uid, self.name, self.device, self.host, self.latest_time.timestamp()))

    def __str__(self):
        return "%d %s %s %s %s" % (self._uid, self._name, self._device, self._host, self._latest_time)

    @property
    def uid(self) -> int:
        return self._uid

    @property
    def name(self) -> str:
        return self._name

    @property
    def device(self) -> str:
        return self._device

    @property
    def host(self) -> str:
        return self._host

    @property
    def latest_time(self) -> datetime.datetime:
        return self._latest_time

    def to_dict(self) -> Dict[str, Any]:
        return {"uid": self.uid,
                "name": self.name,
                "device": self.device,
                "host": self.host,
                "latest_time": self.latest_time.timestamp()}

    @staticmethod
    def from_dict(entity_dict: Dict[str, Any]):
        return LastlogEntry(entity_dict["uid"],
                            entity_dict["name"],
                            entity_dict["device"],
                            entity_dict["host"],
                            entity_dict["latest_time"])


def parse_lastlog_file(file_location: str = "/var/log/lastlog", passwd_file: str = "/etc/passwd") -> List[LastlogEntry]:
    """
    Parses the given lastlog file and returns a list of LastlogEntry objects.
    :param file_location: location of the lastlog file
    :param passwd_file: location of the passwd file to resolve users
    :return: List of LastlogEntry objects
    """
    result = []  # type: List[LastlogEntry]

    entry_format_str = "I32s256s"
    entry_size = struct.calcsize(entry_format_str)
    entry_format = struct.Struct(entry_format_str)

    system_users = {}
    for system_user in get_system_users(passwd_file):
        system_users[system_user.uid] = system_user.name

    if not os.path.isfile(file_location):
        raise LastlogException("File '%s' does not exist" % file_location)

    with open(file_location, 'rb') as fp:
        try:
            uid = 0
            entry_raw = fp.read(entry_size)

            while entry_raw:
                timestamp, device, host = entry_format.unpack(entry_raw)
                if timestamp != 0 and uid in system_users:
                    result.append(LastlogEntry(uid,
                                               system_users[uid],
                                               "" if device[0] == 0 else device.decode("utf-8").replace("\x00", "").strip(),
                                               "" if host[0] == 0 else host.decode("utf-8").replace("\x00", "").strip(),
                                               timestamp))
                entry_raw = fp.read(entry_size)
                uid += 1
        except Exception as e:
            raise LastlogException("Unable to parse raw entry '%s'" % entry_raw) from e

    return result
