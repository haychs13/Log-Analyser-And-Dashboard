import os

# Directory containing log files (relative to project root)
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")

# Log files to analyse (set to None to skip a source)
LOG_FILES = {
    "ssh":     os.path.join(LOG_DIR, "sample_ssh.log"),
    "apache":  os.path.join(LOG_DIR, "sample_apache.log"),
    "windows": os.path.join(LOG_DIR, "sample_windows.log"),
}

# ── Brute-force detection ──────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD   = 5    # minimum failures to trigger an alert
BRUTE_FORCE_WINDOW_SECS = 60   # time window in seconds

# ── Scan detection ─────────────────────────────────────────────────────────
SCAN_THRESHOLD   = 10   # minimum distinct paths to trigger an alert
SCAN_WINDOW_SECS = 120  # time window in seconds

# ── Unusual-IP detection ───────────────────────────────────────────────────
# Extra CIDR ranges to always flag (e.g. known threat-intel feeds)
KNOWN_BAD_CIDRS: list[str] = [
    # "185.220.101.0/24",  # example: Tor exit nodes range
]

# ── Flask ──────────────────────────────────────────────────────────────────
DEBUG = True
HOST  = "127.0.0.1"
PORT  = 5000
SECRET_KEY = "change-me-in-production"
