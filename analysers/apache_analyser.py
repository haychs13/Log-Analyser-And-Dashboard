import re
from datetime import datetime
from .base import LogEntry

# Combined Log Format
_LOG = re.compile(
    r'([\d.]+)\s+'                      # client IP
    r'\S+\s+\S+\s+'                     # ident, authuser
    r'\[([^\]]+)\]\s+'                  # [time]
    r'"(\S+)\s+(\S+)\s+[^"]+"\s+'       # "METHOD path PROTO"
    r'(\d+)\s+'                         # status
    r'(\S+)'                            # bytes
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?'    # "referer" "user-agent"
)

_SUSP_UA = {"sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei",
            "dirbuster", "gobuster", "wfuzz", "hydra", "metasploit"}

_SUSP_PATH = re.compile(
    r"\.\./|etc/passwd|etc/shadow|cmd\.exe|UNION.{0,20}SELECT|"
    r"<script|javascript:|/phpmyadmin|/\.git|/\.env|"
    r"DROP\s+TABLE|SLEEP\s*\(|eval\(",
    re.IGNORECASE,
)


def _ts(raw: str) -> datetime:
    return datetime.strptime(raw[:20], "%d/%b/%Y:%H:%M:%S")


def parse_apache_log(filepath: str) -> list[LogEntry]:
    entries: list[LogEntry] = []

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip()
            m = _LOG.match(line)
            if not m:
                continue

            ip, ts_raw, method, path, status_s, size, referer, ua = (
                m[1], m[2], m[3], m[4], m[5], m[6], m[7] or "", m[8] or ""
            )
            status = int(status_s)
            ua_low = ua.lower()

            bad_ua   = any(s in ua_low for s in _SUSP_UA)
            bad_path = bool(_SUSP_PATH.search(path))

            if bad_ua or bad_path:
                etype = "suspicious_request"
            elif status in (401, 403):
                etype = "failed_login"
            elif status >= 400:
                etype = "error_request"
            else:
                etype = "request"

            entries.append(LogEntry(
                timestamp=_ts(ts_raw),
                source_ip=ip,
                event_type=etype,
                service="apache",
                username=None,
                raw=line,
                extra={
                    "method": method,
                    "path": path,
                    "status": status,
                    "size": size,
                    "user_agent": ua,
                    "suspicious_ua": bad_ua,
                    "suspicious_path": bad_path,
                },
            ))

    return entries
