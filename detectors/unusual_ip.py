import ipaddress
from collections import defaultdict
from analysers.base import Alert

# RFC 5737 documentation ranges — always flag in a real environment
_ALWAYS_FLAG = [
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
]

# Private / loopback / link-local — considered "internal"
_INTERNAL = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_internal(ip_obj) -> bool:
    return any(ip_obj in net for net in _INTERNAL)


def _always_flag(ip_obj) -> bool:
    return any(ip_obj in net for net in _ALWAYS_FLAG)


def detect_unusual_ip(entries, known_bad_cidrs: list[str] | None = None) -> list[Alert]:
    """
    Flag events from:
      1. IPs in known-bad CIDR ranges (configurable)
      2. IPs in RFC 5737 documentation ranges (203.0.113.x etc.)
      3. Any non-internal IP that performs failed_login or suspicious_request
    """
    extra_bad: list[ipaddress.IPv4Network] = []
    for cidr in (known_bad_cidrs or []):
        try:
            extra_bad.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass

    # Group all events by IP
    by_ip: dict[str, list] = defaultdict(list)
    for entry in entries:
        by_ip[entry.source_ip].append(entry)

    alerts: list[Alert] = []
    seen_ips: set[str] = set()

    for ip_str, events in by_ip.items():
        if ip_str in seen_ips:
            continue

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        reason = None
        severity = "low"

        # 1. User-supplied known-bad CIDRs
        for net in extra_bad:
            if ip_obj in net:
                reason = f"IP in configured known-bad range {net}"
                severity = "high"
                break

        # 2. Documentation ranges (should never appear in prod)
        if reason is None and _always_flag(ip_obj):
            reason = "IP in RFC 5737 documentation/test range — suspicious in production"
            severity = "medium"

        # 3. External IP with hostile-looking activity
        if reason is None and not _is_internal(ip_obj):
            hostile = [
                e for e in events
                if e.event_type in ("failed_login", "suspicious_request", "account_lockout")
            ]
            if hostile:
                reason = f"External IP with {len(hostile)} hostile event(s)"
                severity = "medium" if len(hostile) < 5 else "high"

        if reason is None:
            continue

        seen_ips.add(ip_str)
        alerts.append(Alert(
            severity=severity,
            category="unusual_ip",
            source_ip=ip_str,
            description=f"{ip_str}: {reason}",
            count=len(events),
            first_seen=min(e.timestamp for e in events),
            last_seen=max(e.timestamp for e in events),
            entries=events,
        ))

    alerts.sort(key=lambda a: ["critical", "high", "medium", "low"].index(a.severity))
    return alerts
