import re
from datetime import datetime
from .base import LogEntry

# syslog-style: "Mon DD HH:MM:SS hostname sshd[PID]: message"
_FAILED = re.compile(
    r"(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
)
_ACCEPTED = re.compile(
    r"(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port (\d+)"
)
_INVALID = re.compile(
    r"(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Invalid user (\S+) from ([\d.]+)"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,  "May": 5,  "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _ts(month: str, day: str, time: str, year: int = 2026) -> datetime:
    h, m, s = time.split(":")
    return datetime(year, _MONTHS.get(month, 1), int(day), int(h), int(m), int(s))


def parse_ssh_log(filepath: str) -> list[LogEntry]:
    entries: list[LogEntry] = []

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip()

            m = _FAILED.match(line)
            if m:
                entries.append(LogEntry(
                    timestamp=_ts(m[1], m[2], m[3]),
                    source_ip=m[5],
                    event_type="failed_login",
                    service="ssh",
                    username=m[4],
                    raw=line,
                    extra={"port": int(m[6])},
                ))
                continue

            m = _ACCEPTED.match(line)
            if m:
                entries.append(LogEntry(
                    timestamp=_ts(m[1], m[2], m[3]),
                    source_ip=m[5],
                    event_type="success_login",
                    service="ssh",
                    username=m[4],
                    raw=line,
                    extra={"port": int(m[6])},
                ))
                continue

            m = _INVALID.match(line)
            if m:
                entries.append(LogEntry(
                    timestamp=_ts(m[1], m[2], m[3]),
                    source_ip=m[5],
                    event_type="failed_login",
                    service="ssh",
                    username=m[4],
                    raw=line,
                    extra={},
                ))

    return entries
