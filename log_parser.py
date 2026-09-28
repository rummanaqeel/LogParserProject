#!/usr/bin/env python3
"""
Log Parser & SOC Triage Simulator
=================================

Parses Linux authentication logs, sudo/cron activity, and web access logs,
then emits structured alerts in the field schema used by SIEM alert queues
(timestamp, event_type, source_ip, user, severity, detail).

Detection coverage
------------------
  1. SSH brute force        - repeated failed password attempts per source IP
  2. Off-hours SSH access   - successful logins outside defined business hours
  3. Sudo privilege misuse  - failed sudo authentication and root command execution
  4. Cron activity          - scheduled-task executions, flagged against a baseline
  5. HTTP request anomalies - 4xx/5xx clustering per source IP (recon / brute force)

Usage
-----
  python3 log_parser.py auth.log    --type auth
  python3 log_parser.py access.log  --type access
  python3 log_parser.py syslog      --type system
  python3 log_parser.py auth.log    --type auth --format json
  python3 log_parser.py auth.log    --type auth --threshold 2 --min-severity HIGH
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Iterable, Iterator

# --------------------------------------------------------------------------- #
# Log line patterns
# --------------------------------------------------------------------------- #

SSH_FAILED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s\S+\ssshd\[\d+\]:\s"
    r"Failed password for (?:invalid user )?(?P<user>\S+)\sfrom\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_ACCEPTED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s\S+\ssshd\[\d+\]:\s"
    r"Accepted (?:password|publickey) for (?P<user>\S+)\sfrom\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SUDO_FAILURE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s\S+\ssudo:\s+(?P<user>\S+)\s:\s"
    r"(?:\d+ incorrect password attempts?|authentication failure)"
)
SUDO_COMMAND = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s\S+\ssudo:\s+(?P<user>\S+)\s:.*?"
    r"USER=(?P<target>\S+)\s+;\s+COMMAND=(?P<cmd>.+)$"
)
CRON_CMD = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s\S+\sCRON\[\d+\]:\s"
    r"\((?P<user>\S+)\)\sCMD\s\((?P<cmd>.+)\)$"
)
HTTP_ACCESS = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s\S+\s\S+\s\[(?P<ts>[^\]]+)\]\s"
    r'"(?P<method>\w+)\s(?P<path>\S+)[^"]*"\s(?P<status>\d{3})'
)

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Commands that are expected in this environment's crontab. Anything outside
# this baseline is surfaced for analyst review rather than silently ignored.
CRON_BASELINE = {"/usr/bin/certbot renew", "/usr/local/bin/backup.sh"}


@dataclass
class Alert:
    """One structured detection, shaped to a SIEM alert-queue record."""

    timestamp: str
    event_type: str
    severity: str
    source_ip: str
    user: str
    detail: str

    def as_row(self) -> str:
        return (
            f"{self.timestamp:<21} {self.severity:<8} {self.event_type:<22} "
            f"{self.source_ip:<15} {self.user:<12} {self.detail}"
        )


def _hour(ts: str) -> int | None:
    """Extract the hour from a syslog-style timestamp (e.g. 'Dec 30 22:14:05')."""
    try:
        return datetime.strptime(ts.split()[-1], "%H:%M:%S").hour
    except (ValueError, IndexError):
        return None


# --------------------------------------------------------------------------- #
# Detections
# --------------------------------------------------------------------------- #

def detect_ssh_bruteforce(lines: Iterable[str], threshold: int) -> Iterator[Alert]:
    """Flag source IPs exceeding `threshold` failed SSH password attempts."""
    attempts: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for line in lines:
        if m := SSH_FAILED.search(line):
            attempts[m["ip"]].append((m["ts"], m["user"]))

    for ip, events in attempts.items():
        if len(events) >= threshold:
            users = sorted({u for _, u in events})
            yield Alert(
                timestamp=events[0][0],
                event_type="ssh_brute_force",
                severity="HIGH",
                source_ip=ip,
                user=",".join(users[:3]),
                detail=f"{len(events)} failed password attempts across {len(users)} account(s)",
            )


def detect_offhours_access(
    lines: Iterable[str], start_hour: int, end_hour: int
) -> Iterator[Alert]:
    """Flag successful SSH logins outside the defined business-hours window."""
    for line in lines:
        if m := SSH_ACCEPTED.search(line):
            hour = _hour(m["ts"])
            if hour is not None and not (start_hour <= hour < end_hour):
                yield Alert(
                    timestamp=m["ts"],
                    event_type="offhours_ssh_login",
                    severity="MEDIUM",
                    source_ip=m["ip"],
                    user=m["user"],
                    detail=f"successful login at {hour:02d}:00, outside {start_hour:02d}:00-{end_hour:02d}:00",
                )


def detect_sudo_activity(lines: Iterable[str]) -> Iterator[Alert]:
    """Flag failed sudo authentication and privileged command execution."""
    for line in lines:
        if m := SUDO_FAILURE.search(line):
            yield Alert(
                timestamp=m["ts"],
                event_type="sudo_auth_failure",
                severity="HIGH",
                source_ip="-",
                user=m["user"],
                detail="failed sudo authentication - possible privilege escalation attempt",
            )
        elif m := SUDO_COMMAND.search(line):
            severity = "MEDIUM" if m["target"] == "root" else "INFO"
            yield Alert(
                timestamp=m["ts"],
                event_type="sudo_command",
                severity=severity,
                source_ip="-",
                user=m["user"],
                detail=f"ran as {m['target']}: {m['cmd']}",
            )


def detect_cron_activity(lines: Iterable[str]) -> Iterator[Alert]:
    """Flag cron executions that fall outside the known-good baseline."""
    for line in lines:
        if m := CRON_CMD.search(line):
            known = m["cmd"].strip() in CRON_BASELINE
            yield Alert(
                timestamp=m["ts"],
                event_type="cron_execution" if known else "cron_unexpected",
                severity="INFO" if known else "HIGH",
                source_ip="-",
                user=m["user"],
                detail=("baseline task: " if known else "NOT in cron baseline: ") + m["cmd"],
            )


def detect_http_anomalies(lines: Iterable[str], threshold: int) -> Iterator[Alert]:
    """Flag per-IP clustering of 4xx/5xx responses, and individual 403/500s."""
    errors: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for line in lines:
        if m := HTTP_ACCESS.search(line):
            if int(m["status"]) >= 400:
                errors[m["ip"]].append((m["ts"].split()[0], m["status"], m["path"]))

    for ip, events in errors.items():
        if len(events) >= threshold:
            yield Alert(
                timestamp=events[0][0],
                event_type="http_error_cluster",
                severity="HIGH",
                source_ip=ip,
                user="-",
                detail=f"{len(events)} error responses - probable enumeration or credential stuffing",
            )
        else:
            for ts, status, path in events:
                yield Alert(
                    timestamp=ts,
                    event_type="http_client_error",
                    severity="MEDIUM" if status in {"401", "403"} else "LOW",
                    source_ip=ip,
                    user="-",
                    detail=f"HTTP {status} on {path}",
                )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

DISPATCH = {
    "auth": lambda lines, a: [
        *detect_ssh_bruteforce(lines, a.threshold),
        *detect_offhours_access(lines, a.business_start, a.business_end),
        *detect_sudo_activity(lines),
    ],
    "system": lambda lines, a: [*detect_cron_activity(lines), *detect_sudo_activity(lines)],
    "access": lambda lines, a: [*detect_http_anomalies(lines, a.threshold)],
}


def main() -> int:
    p = argparse.ArgumentParser(
        description="Log Parser & SOC Triage Simulator - structured alerting for Linux and web logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("log_file", help="path to the log file to analyse")
    p.add_argument(
        "--type", required=True, choices=sorted(DISPATCH),
        help="auth (sshd/sudo) | system (cron/sudo) | access (HTTP)",
    )
    p.add_argument("--threshold", type=int, default=3, help="events per IP before clustering as one alert (default: 3)")
    p.add_argument("--business-start", type=int, default=8, metavar="H", help="business hours start, 24h (default: 8)")
    p.add_argument("--business-end", type=int, default=20, metavar="H", help="business hours end, 24h (default: 20)")
    p.add_argument("--format", choices=["table", "json"], default="table", help="output format (default: table)")
    p.add_argument("--min-severity", choices=sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get),
                   default="INFO", help="suppress alerts below this severity (default: INFO)")
    args = p.parse_args()

    try:
        with open(args.log_file, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print(f"error: cannot read {args.log_file}: {exc}", file=sys.stderr)
        return 2

    alerts = DISPATCH[args.type](lines, args)
    floor = SEVERITY_ORDER[args.min_severity]
    alerts = [a for a in alerts if SEVERITY_ORDER[a.severity] >= floor]
    alerts.sort(key=lambda a: -SEVERITY_ORDER[a.severity])

    if args.format == "json":
        print(json.dumps([asdict(a) for a in alerts], indent=2))
    else:
        if not alerts:
            print(f"No alerts at or above {args.min_severity} in {args.log_file}.")
            return 0
        print(f"{'TIMESTAMP':<21} {'SEVERITY':<8} {'EVENT_TYPE':<22} {'SOURCE_IP':<15} {'USER':<12} DETAIL")
        print("-" * 118)
        for a in alerts:
            print(a.as_row())
        counts = defaultdict(int)
        for a in alerts:
            counts[a.severity] += 1
        summary = "  ".join(f"{s}={counts[s]}" for s in sorted(counts, key=SEVERITY_ORDER.get, reverse=True))
        print("-" * 118)
        print(f"{len(alerts)} alert(s) from {len(lines)} log lines   {summary}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
