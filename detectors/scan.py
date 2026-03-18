from collections import defaultdict
from datetime import timedelta
from analysers.base import Alert


def detect_scan(
    entries,
    threshold: int = 10,
    window_secs: int = 120,
) -> list[Alert]:
    """
    Detect scanning behaviour: an IP that generates >= threshold
    distinct error responses (4xx) or requests to distinct paths
    within window_secs seconds.

    This covers both web directory enumeration and tool-based scanning
    (Nikto, DirBuster, sqlmap) as seen in Apache/Nginx logs.
    """
    by_ip: dict[str, list] = defaultdict(list)
    for entry in entries:
        if entry.service in ("apache", "nginx"):
            by_ip[entry.source_ip].append(entry)

    alerts: list[Alert] = []

    for ip, events in by_ip.items():
        events.sort(key=lambda e: e.timestamp)

        best: list = []
        left = 0

        for right in range(len(events)):
            while (
                events[right].timestamp - events[left].timestamp
                > timedelta(seconds=window_secs)
            ):
                left += 1

            window = events[left : right + 1]

            # Count distinct paths in this window
            paths = {e.extra.get("path", "") for e in window}
            if len(paths) > len({e.extra.get("path", "") for e in best}):
                best = window

        distinct_paths = len({e.extra.get("path", "") for e in best})
        if distinct_paths < threshold:
            continue

        # Check for known scanner user-agents
        uas = {e.extra.get("user_agent", "") for e in best}
        scanner_ua = next(
            (ua for ua in uas
             if any(s in ua.lower() for s in ("nikto", "dirbuster", "gobuster",
                                               "sqlmap", "wfuzz", "nuclei"))),
            None,
        )

        if distinct_paths >= 30:
            severity = "high"
        elif scanner_ua:
            severity = "high"
        else:
            severity = "medium"

        tool_hint = f" (tool: {scanner_ua})" if scanner_ua else ""
        alerts.append(Alert(
            severity=severity,
            category="scan",
            source_ip=ip,
            description=(
                f"{len(best)} requests to {distinct_paths} distinct paths "
                f"from {ip} within {window_secs}s{tool_hint}"
            ),
            count=distinct_paths,
            first_seen=best[0].timestamp,
            last_seen=best[-1].timestamp,
            entries=best,
        ))

    alerts.sort(key=lambda a: ["critical", "high", "medium", "low"].index(a.severity))
    return alerts
