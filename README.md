# 📘 Log Parser & Suspicious Activity Detector

A **Python-based CLI tool** that parses **access** and **authentication** logs to detect suspicious activity, such as repeated failed logins, unauthorized access attempts, and abnormal request patterns.  
Simulates alerting mechanisms (email/SNS) without actually sending notifications, making it safe for demonstration and testing.

---

## 📂 Project Structure



LogParserProject/
├── log_parser.py
├── access_sample.log
├── auth_sample.log
├── README.md
└── requirements.txt (if any)


> **Note:** Ensure your `.log` files do **not** have trailing colons (`auth_sample.log:` → rename to `auth_sample.log`) to avoid FileNotFound errors.

---

## ⚡ Features

- Parses **access** and **auth** logs
- Flags **suspicious activity** based on failed login attempts, forbidden access, or abnormal request patterns
- Configurable **threshold** for detection sensitivity
- CLI-based — runs entirely in the terminal
- Simulated alert notifications for SOC workflows

---

## 🖥 Usage Examples

### 1️⃣ Show help / usage
```bash
python log_parser.py -h


Output:

usage: log_parser.py [-h] --type {auth,access} [--threshold THRESHOLD] log_file

Basic Log Parser & Alert Tool

positional arguments:
  log_file              Path to log file

options:
  -h, --help            show this help message and exit
  --type {auth,access}  Log type: auth or access
  --threshold THRESHOLD
                        Alert threshold

2️⃣ Analyze Access Logs
python log_parser.py access_sample.log --type access


Output example:

Suspicious: IP 192.168.1.103 at 30/Dec/2025:10:05:00 with status 200
Suspicious: IP 192.168.1.104 at 30/Dec/2025:10:05:05 with status 401
Suspicious: IP 192.168.1.105 at 30/Dec/2025:10:05:10 with status 403
Alerts generated—simulate email/SNS notification here.

3️⃣ Analyze Auth Logs
python log_parser.py auth_sample.log --type auth


Output example:

Alert: IP 192.168.1.200 has 3 failed logins
Alerts generated—simulate email/SNS notification here.

4️⃣ Auth Logs with Threshold
python log_parser.py auth_sample.log --type auth --threshold 2


Output example:

Alert: IP 192.168.1.100 has 2 failed logins
Alert: IP 192.168.1.200 has 3 failed logins
Alerts generated—simulate email/SNS notification here.


Note: The --threshold flag allows you to control how sensitive the tool is in flagging repeated login failures.
