from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class LogEntry:
    timestamp: datetime
    source_ip: str
    event_type: str       # failed_login | success_login | request | suspicious_request | ...
    service: str          # ssh | apache | windows
    username: Optional[str] = None
    raw: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "event_type": self.event_type,
            "service": self.service,
            "username": self.username,
            "extra": self.extra,
        }


@dataclass
class Alert:
    severity: str         # critical | high | medium | low
    category: str         # brute_force | scan | unusual_ip
    source_ip: str
    description: str
    count: int
    first_seen: datetime
    last_seen: datetime
    entries: list = field(default_factory=list)

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "source_ip": self.source_ip,
            "description": self.description,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "sample_entries": [e.to_dict() for e in self.entries[:5]],
        }
