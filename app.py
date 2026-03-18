"""
Cybersecurity Log Analyser & Dashboard
Run:  python app.py
Open: http://127.0.0.1:5000
"""

import os
from collections import Counter, defaultdict
from datetime import datetime

from flask import Flask, jsonify, render_template, redirect, url_for

import config
from analysers import parse_ssh_log, parse_apache_log, parse_windows_log
from detectors import detect_brute_force, detect_scan, detect_unusual_ip

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# ── Analysis cache (re-computed on each /api/analyze call or startup) ──────

_cache: dict = {}


def _run_analysis() -> dict:
    """Parse all log files and run every detector. Returns aggregated results."""
    all_entries = []
    parse_errors = []

    parsers = {
        "ssh":     parse_ssh_log,
        "apache":  parse_apache_log,
        "windows": parse_windows_log,
    }

    entries_by_source: dict[str, list] = {}

    for source, parser in parsers.items():
        path = config.LOG_FILES.get(source)
        if not path or not os.path.isfile(path):
            continue
        try:
            parsed = parser(path)
            entries_by_source[source] = parsed
            all_entries.extend(parsed)
        except Exception as exc:
            parse_errors.append(f"{source}: {exc}")

    # ── Detection ──────────────────────────────────────────────────────────
    alerts = []
    alerts += detect_brute_force(
        all_entries,
        threshold=config.BRUTE_FORCE_THRESHOLD,
        window_secs=config.BRUTE_FORCE_WINDOW_SECS,
    )
    alerts += detect_scan(
        all_entries,
        threshold=config.SCAN_THRESHOLD,
        window_secs=config.SCAN_WINDOW_SECS,
    )
    alerts += detect_unusual_ip(all_entries, known_bad_cidrs=config.KNOWN_BAD_CIDRS)

    # ── Aggregated stats ───────────────────────────────────────────────────
    event_type_counts = Counter(e.event_type for e in all_entries)
    source_counts     = Counter(e.service    for e in all_entries)
    ip_counts         = Counter(e.source_ip  for e in all_entries)

    # Events per hour (for line chart)
    by_hour: dict[str, int] = defaultdict(int)
    for e in all_entries:
        label = e.timestamp.strftime("%H:00")
        by_hour[label] += 1
    hours_sorted = sorted(by_hour.keys())

    # Severity counts
    sev_counts = Counter(a.severity for a in alerts)

    return {
        "total_events":    len(all_entries),
        "unique_ips":      len(ip_counts),
        "total_alerts":    len(alerts),
        "critical_alerts": sev_counts.get("critical", 0),
        "high_alerts":     sev_counts.get("high", 0),
        "medium_alerts":   sev_counts.get("medium", 0),
        "low_alerts":      sev_counts.get("low", 0),
        "event_type_counts": dict(event_type_counts),
        "source_counts":     dict(source_counts),
        "top_ips":           ip_counts.most_common(10),
        "hours":             hours_sorted,
        "events_per_hour":   [by_hour[h] for h in hours_sorted],
        "alerts":            alerts,
        "parse_errors":      parse_errors,
        "analysed_at":       datetime.now().isoformat(),
    }


def _get_cache() -> dict:
    global _cache
    if not _cache:
        _cache = _run_analysis()
    return _cache


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    data = _get_cache()
    return render_template("dashboard.html", data=data)


@app.route("/alerts")
def alerts_page():
    data = _get_cache()
    return render_template("alerts.html", data=data)


@app.route("/api/stats")
def api_stats():
    data = _get_cache()
    return jsonify({
        "total_events":      data["total_events"],
        "unique_ips":        data["unique_ips"],
        "total_alerts":      data["total_alerts"],
        "critical_alerts":   data["critical_alerts"],
        "event_type_counts": data["event_type_counts"],
        "source_counts":     data["source_counts"],
        "top_ips":           data["top_ips"],
        "hours":             data["hours"],
        "events_per_hour":   data["events_per_hour"],
        "analysed_at":       data["analysed_at"],
    })


@app.route("/api/alerts")
def api_alerts():
    data = _get_cache()
    return jsonify([a.to_dict() for a in data["alerts"]])


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    global _cache
    _cache = _run_analysis()
    return jsonify({
        "status": "ok",
        "total_events": _cache["total_events"],
        "total_alerts": _cache["total_alerts"],
        "analysed_at":  _cache["analysed_at"],
    })


if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
