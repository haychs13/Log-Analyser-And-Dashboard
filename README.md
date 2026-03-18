# Log Analyser and Dashboard 

A Python/Flask web application that parses common log formats, detects suspicious
security activity, and presents findings in a live dark-themed dashboard.

## Features

| Feature | Detail |
|---|---|
| **Log parsers** | SSH (`auth.log`), Apache/Nginx (Combined Log Format), Windows Event Log (CSV) |
| **Threat detection** | Brute-force login attacks, web scanner / directory enumeration, unusual/external IPs |
| **Dashboard** | Events over time, top IPs, event-type breakdown, log-source breakdown |
| **Alerts page** | Filterable by severity with expandable log-entry details |
| **Sample data** | Realistic logs included — works out of the box, no real server needed |

## Quick Start
```bash
# 1. Clone / enter the project
git clone https://github.com/haychs13/Log-Analyser-And-Dashboard.git
cd Log-Analyser-And-Dashboard

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

## Project Structure
```
Log-Analyser-And-Dashboard/
├── app.py                  Flask entry point & routes
├── config.py               Detection thresholds & settings
├── requirements.txt
│
├── logs/                   Sample log files
│   ├── sample_ssh.log      SSH auth.log format
│   ├── sample_apache.log   Apache Combined Log Format
│   └── sample_windows.log  Windows Event Log CSV export
│
├── analysers/              Log parsers
│   ├── base.py             LogEntry & Alert dataclasses
│   ├── ssh_analyser.py
│   ├── apache_analyser.py
│   └── windows_analyser.py
│
├── detectors/              Threat detection rules
│   ├── brute_force.py      Failed-login burst detection
│   ├── scan.py             Web scanner / dir-enum detection
│   └── unusual_ip.py       External & known-bad IP flagging
│
├── templates/              Jinja2 HTML templates
│   ├── base.html
│   ├── dashboard.html
│   └── alerts.html
│
└── static/
    └── css/style.css
```

## Detection Rules

### Brute Force
Triggers when ≥ **5** failed logins arrive from the same IP within **60 seconds**.
- 5–9 failures → **Medium**
- 10–19 failures → **High**
- ≥ 20 failures → **Critical**

### Web Scan / Directory Enumeration
Triggers when the same IP requests ≥ **10** distinct paths within **120 seconds**,
or when a known scanner user-agent (Nikto, sqlmap, DirBuster…) is detected.

### Unusual IP
Flags events from:
- IPs in user-configured known-bad CIDR ranges (`config.py → KNOWN_BAD_CIDRS`)
- RFC 5737 documentation ranges (203.0.113.x, 198.51.100.x, 192.0.2.x)
- External IPs with failed-login or suspicious-request activity

## Using Your Own Logs

Edit `config.py` and point the `LOG_FILES` paths to your real log files:
```python
LOG_FILES = {
    "ssh":     "/var/log/auth.log",
    "apache":  "/var/log/apache2/access.log",
    "windows": "/path/to/exported_events.csv",
}
```

Click **Re-analyse** in the navbar to reload without restarting the server.

## Tuning Thresholds

All detection thresholds live in `config.py`:
```python
BRUTE_FORCE_THRESHOLD   = 5    # failures before alerting
BRUTE_FORCE_WINDOW_SECS = 60
SCAN_THRESHOLD          = 10   # distinct paths before alerting
SCAN_WINDOW_SECS        = 120
KNOWN_BAD_CIDRS         = []   # add your threat-intel CIDRs here
```
