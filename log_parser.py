import re
from collections import defaultdict
from datetime import datetime
import argparse

# Regex patterns for common logs
AUTH_PATTERN = r'(\w+ \d+ \d+:\d+:\d+) \w+ sshd\[\d+\]: Failed password for (invalid user )?(\w+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
ACCESS_PATTERN = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) .+\] "\w+ .+ HTTP/1.1" (\d{3})'


def parse_log_line(line, pattern):
    match = re.match(pattern, line)
    if match:
        return match.groups()
    return None


def analyze_auth_logs(log_file, threshold=3):
    failed_logins = defaultdict(int)
    with open(log_file, 'r') as f:
        for line in f:
            parsed = parse_log_line(line, AUTH_PATTERN)
            if parsed:
                timestamp, _, user, ip = parsed
                failed_logins[ip] += 1

    alerts = [f"Alert: IP {ip} has {count} failed logins" for ip, count in failed_logins.items() if count >= threshold]
    return alerts


def analyze_access_logs(log_file, status_threshold=400):
    suspicious_requests = []
    with open(log_file, 'r') as f:
        for line in f:
            parsed = parse_log_line(line, ACCESS_PATTERN)
            if parsed:
                ip, timestamp, status = parsed[:3]
                if int(status) >= status_threshold:
                    suspicious_requests.append(f"Suspicious: IP {ip} at {timestamp} with status {status}")

    return suspicious_requests


def main():
    parser = argparse.ArgumentParser(description="Basic Log Parser & Alert Tool")
    parser.add_argument("log_file", help="Path to log file")
    parser.add_argument("--type", choices=["auth", "access"], required=True, help="Log type: auth or access")
    parser.add_argument("--threshold", type=int, default=3, help="Alert threshold")

    args = parser.parse_args()

    if args.type == "auth":
        alerts = analyze_auth_logs(args.log_file, args.threshold)
    elif args.type == "access":
        alerts = analyze_access_logs(args.log_file, args.threshold)

    for alert in alerts:
        print(alert)

    if alerts:
        print("Alerts generated—simulate email/SNS notification here.")


if __name__ == "__main__":
    main()