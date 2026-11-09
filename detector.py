import re
import csv
import ipaddress
from datetime import datetime, timedelta
from collections import Counter
from pathlib import Path    

LOG_FILE = Path("auth.log")
REPORT_FILE = Path("security_report.csv")
THRESHOLD = 5
TIME_WINDOW_MINUTES = 5
HIGH_SEVERITY_THRESHOLD = 10

IP_PATTERN = re.compile(
    r"(?:\d{1,3}\.){3}\d{1,3}"
)

failed_attempts = Counter()
failed_events = {}

if not LOG_FILE.exists():
    print("Error: auth.log was not found.")
    print("Keep auth.log in the same folder as detector.py.")
    raise SystemExit(1)

with LOG_FILE.open("r", encoding="utf-8") as file:
    for line in file:
        if "Failed password" not in line:
            continue
        timestamp_text = line[:15]

        try:
            event_time = datetime.strptime(
                "2026 " + timestamp_text,
                "%Y %b %d %H:%M:%S"
            )
        except ValueError:
            continue

        match = IP_PATTERN.search(line)
        if match:
            candidate_ip = match.group()
            try:
                validated_ip = ipaddress.ip_address(candidate_ip)
            except ValueError:
                continue

            if isinstance(validated_ip, ipaddress.IPv4Address):
                ip_address = str(validated_ip)

                failed_attempts[ip_address] += 1

                if ip_address not in failed_events:
                    failed_events[ip_address] = []

                failed_events[ip_address].append(event_time)

print("SSH BRUTE-FORCE DETECTION REPORT")
print("-" * 35)
print("Total failed login attempts:", sum(failed_attempts.values()))

suspicious_ips = {}
max_attempts_by_ip = {}

for ip, timestamps in failed_events.items():
    timestamps.sort()

    left = 0
    max_attempts = 0

    for right, current_time in enumerate(timestamps):
        while current_time - timestamps[left] > timedelta(minutes=TIME_WINDOW_MINUTES):
            left += 1

        attempts_in_window = right - left + 1

        max_attempts = max(max_attempts, attempts_in_window)
        max_attempts_by_ip[ip] = max_attempts

    if max_attempts >= THRESHOLD:
        suspicious_ips[ip] = {
            "total_attempts": failed_attempts[ip],
            "max_attempts_in_5_minutes": max_attempts
        }

if suspicious_ips:
    print("\nPotentially suspicious IP addresses:")

    for ip, details in suspicious_ips.items():
        print(f"\nIP Address: {ip}")
        print(f"Total failed attempts: {details['total_attempts']}")
        print(
            "Maximum attempts within 5 minutes:",
            details["max_attempts_in_5_minutes"]
        )
else:
    print("\nNo IP addresses reached the threshold.")

with REPORT_FILE.open(
    "w", newline="", encoding="utf-8"
) as file:
    writer = csv.writer(file)

    writer.writerow([
            "IP Address",
            "Total Failed Attempts",
            "Max Attempts in 5 Minutes",
            "Status",
            "Severity"
    ])

    for ip, count in failed_attempts.most_common():
        max_attempts = max_attempts_by_ip[ip]

        status = (
            "Potentially Suspicious"
            if max_attempts >= THRESHOLD
            else "Below Threshold"
        )
        if max_attempts >= HIGH_SEVERITY_THRESHOLD:
            severity = "High"
        elif max_attempts >= THRESHOLD:
            severity = "Medium"
        else:
            severity = "Low"

        writer.writerow([
            ip,
            count,
            max_attempts,
            status,
            severity
        ])

print(f"\nReport saved to: {REPORT_FILE}")