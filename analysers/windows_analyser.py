import csv
from datetime import datetime
from .base import LogEntry

_EVENT_MAP = {
    4624: "success_login",
    4625: "failed_login",
    4634: "logoff",
    4648: "explicit_logon",
    4672: "admin_logon",
    4720: "account_created",
    4722: "account_enabled",
    4724: "password_reset",
    4740: "account_lockout",
    4776: "credential_validation",
    4778: "session_reconnect",
    4779: "session_disconnect",
}

_TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %H:%M:%S")


def _ts(raw: str) -> datetime:
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    return datetime.now()


def parse_windows_log(filepath: str) -> list[LogEntry]:
    entries: list[LogEntry] = []

    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                event_id = int(row.get("EventID", 0))
            except ValueError:
                continue

            etype = _EVENT_MAP.get(event_id, "unknown")

            ip = row.get("IpAddress", "-").strip()
            if ip in ("-", "", "LOCAL", "::1", "127.0.0.1"):
                ip = "127.0.0.1"

            username = (
                row.get("TargetUserName") or row.get("SubjectUserName") or ""
            ).strip()

            entries.append(LogEntry(
                timestamp=_ts(row.get("TimeCreated", "")),
                source_ip=ip,
                event_type=etype,
                service="windows",
                username=username,
                raw=str(dict(row)),
                extra={
                    "event_id": event_id,
                    "logon_type": row.get("LogonType", ""),
                    "workstation": row.get("WorkstationName", ""),
                    "description": row.get("Description", ""),
                    "level": row.get("Level", ""),
                },
            ))

    return entries
