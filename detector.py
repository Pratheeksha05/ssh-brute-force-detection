import re
import csv
from collections import Counter
from pathlib import Path

LOG_FILE = Path("auth.log")
REPORT_FILE = Path("security_report.csv")
THRESHOLD = 5

IP_PATTERN = re.compile(
    r"(?:\d{1,3}\.){3}\d{1,3}"
)

failed_attempts = Counter()

if not LOG_FILE.exists():
    print("Error: auth.log was not found.")
    print("Keep auth.log in the same folder as detector.py.")
    raise SystemExit(1)

with LOG_FILE.open("r", encoding="utf-8") as file:
    for line in file:
        if "Failed password" not in line:
            continue

        match = IP_PATTERN.search(line)
        if match:
            ip_address = match.group()
            failed_attempts[ip_address] += 1

print("SSH BRUTE-FORCE DETECTION REPORT")
print("-" * 35)
print("Total failed login attempts:", sum(failed_attempts.values()))

suspicious_ips = {
    ip: count
    for ip, count in failed_attempts.items()
    if count >= THRESHOLD
}

if suspicious_ips:
    print("\nPotentially suspicious IP addresses:")
    for ip, count in suspicious_ips.items():
        print(f"{ip} - {count} failed attempts")
else:
    print("\nNo IP addresses exceeded the threshold.")

with REPORT_FILE.open(
    "w", newline="", encoding="utf-8"
) as file:
    writer = csv.writer(file)
    writer.writerow(["IP Address", "Failed Attempts", "Status"])
        
    for ip, count in failed_attempts.most_common():
        status = (
            "Potentially Suspicious"
            if count >= THRESHOLD
            else "Below Threshold"
        )
        writer.writerow([ip, count, status])

print(f"\nReport saved to: {REPORT_FILE}")