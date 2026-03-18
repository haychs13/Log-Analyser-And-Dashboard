from collections import defaultdict
from datetime import timedelta
from analysers.base import Alert


def detect_brute_force(
    entries,
    threshold: int = 5,
    window_secs: int = 60,
) -> list[Alert]:
    """
    Raise an alert for each IP that produces >= threshold failed logins
    within any window_secs-second sliding window.
    One alert per IP — the window with the highest failure count is reported.
    """
    # Collect failed-login events keyed by source IP
    by_ip: dict[str, list] = defaultdict(list)
    for entry in entries:
        if entry.event_type in ("failed_login", "invalid_user"):
            by_ip[entry.source_ip].append(entry)

    alerts: list[Alert] = []

    for ip, events in by_ip.items():
        events.sort(key=lambda e: e.timestamp)

        best: list = []
        left = 0

        for right in range(len(events)):
            # Shrink window from the left until it fits within window_secs
            while (
                events[right].timestamp - events[left].timestamp
                > timedelta(seconds=window_secs)
            ):
                left += 1

            window = events[left : right + 1]
            if len(window) > len(best):
                best = window

        count = len(best)
        if count < threshold:
            continue

        if count >= 20:
            severity = "critical"
        elif count >= 10:
            severity = "high"
        else:
            severity = "medium"

        alerts.append(Alert(
            severity=severity,
            category="brute_force",
            source_ip=ip,
            description=(
                f"{count} failed login attempt(s) from {ip} "
                f"within {window_secs}s"
            ),
            count=count,
            first_seen=best[0].timestamp,
            last_seen=best[-1].timestamp,
            entries=best,
        ))

    # Most severe first
    alerts.sort(key=lambda a: ["critical", "high", "medium", "low"].index(a.severity))
    return alerts
