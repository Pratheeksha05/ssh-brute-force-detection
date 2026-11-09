# SSH Brute-Force Attack Detection and Log Analysis Using Python

## 1. Project Overview

This project is a Python-based cybersecurity tool designed to analyze SSH authentication logs and identify potentially suspicious IP addresses based on repeated failed login attempts.

The tool reads a sample authentication log file, extracts IP addresses associated with failed login attempts, validates the extracted IP addresses, and analyzes failed login activity within a configurable time window.

It identifies IP addresses that reach a predefined detection threshold, assigns severity levels based on the maximum number of failed attempts within the time window, and generates a CSV security report.

The project also includes automated unit tests to verify the detection logic and handle common edge cases.

## 2. Objectives

- Analyze SSH authentication logs.
- Detect repeated failed login attempts.
- Extract source IP addresses.
- Validate extracted IPv4 addresses.
- Count failed login attempts for each IP address.
- Detect repeated failures within a defined time window.
- Calculate the maximum number of failed attempts within that time window.
- Classify potentially suspicious activity using severity levels.
- Generate a CSV security report.
- Verify the detection logic using automated tests.

## 3. Technologies Used

- Python 3
- Visual Studio Code
- Regular Expressions (`re` module)
- CSV module
- Collections module (`Counter`)
- IP Address Validation (`ipaddress` module)
- Date and Time Handling (`datetime` module)
- Unit Testing (`unittest` module)
- Temporary Files and Subprocesses for automated testing

## 4. Project Structure

```text
SSH-Brute-Force-Detection/
│
├── detector.py
├── test_detector.py
├── auth.log
├── security_report.csv
└── README.md
```

**File descriptions:**

- `detector.py` – Main Python script that analyzes SSH authentication logs and detects potentially suspicious login activity.
- `test_detector.py` – Automated unit tests that verify the detection logic and expected behavior.
- `auth.log` – Sample SSH authentication log containing fictional login events.
- `security_report.csv` – Generated report containing failed login counts, detection status, and severity levels.
- `README.md` – Project documentation.

## 5. How It Works

1. The program checks whether the authentication log file exists.
2. It reads the authentication log file line by line.
3. It searches for entries containing `Failed password`.
4. It extracts candidate IP addresses using a regular expression.
5. It validates extracted IP addresses using Python's built-in `ipaddress` module.
6. Invalid IP addresses are skipped to prevent incorrect entries from affecting the detection results.
7. It extracts timestamps from failed login events.
8. It counts failed login attempts for each IP address using Python's `Counter`.
9. It stores timestamps associated with each IP address.
10. It sorts the timestamps and uses a sliding-window technique to calculate the maximum number of failed attempts within any five-minute period.
11. It flags IP addresses that reach or exceed the configured detection threshold.
12. It assigns severity levels based on the maximum number of failed attempts within the five-minute window.
13. It exports the analysis results to a CSV security report.

## 6. Detection Logic

The project uses time-based detection to identify repeated failed SSH login attempts.

**Detection configuration:**

- Time window: 5 minutes
- Detection threshold: 5 failed login attempts
- High severity threshold: 10 failed login attempts within the time window

An IP address is classified as **Potentially Suspicious** when it generates 5 or more failed login attempts within any five-minute period.

An IP address with fewer than 5 failed login attempts within the same time window is classified as **Below Threshold**.

**Severity classification:**

| Maximum Failed Attempts Within 5 Minutes | Severity |
|---|---|
| 0–4 | Low |
| 5–9 | Medium |
| 10 or more | High |

These thresholds are configurable, educational project settings and are not universal cybersecurity standards.

**Sliding-window detection:**

The program uses a sliding-window technique to examine timestamps for each IP address. This allows it to detect repeated failed login attempts occurring close together, rather than simply counting all failures in the entire log file.

For example, five failed login attempts within a few seconds can trigger detection, while five attempts spread across eight minutes will not meet the five-attempts-within-five-minutes threshold.

## 7. Sample Results

The following results are based on the original sample authentication log.

**Terminal output:**

```text
SSH BRUTE-FORCE DETECTION REPORT
-----------------------------------
Total failed login attempts: 7

Potentially suspicious IP addresses:

IP Address: 192.0.2.10
Total failed attempts: 5
Maximum attempts within 5 minutes: 5
```

**Generated CSV report:**

| IP Address | Total Failed Attempts | Max Attempts in 5 Minutes | Status | Severity |
|---|---:|---:|---|---|
| 192.0.2.10 | 5 | 5 | Potentially Suspicious | Medium |
| 192.0.2.20 | 2 | 2 | Below Threshold | Low |

The successful login from `192.0.2.30` is excluded from failed-login analysis.

## 8. How to Run

1. Install Python 3.
2. Open the project folder in Visual Studio Code.
3. Open the terminal in the project folder.
4. Run the detection program:

```bash
python detector.py
```

5. View the generated `security_report.csv` file.

**To run automated tests:**

Execute the following command in the project terminal:

```bash
python -m unittest -v
```

The test suite verifies the detection logic and displays the results of each test.

## 9. Testing

The project includes automated unit tests using Python's built-in `unittest` framework.

The following scenarios were tested:

- **Brute-force detection:** Verifies that an IP address with 5 failed login attempts within five minutes is detected.
- **Time-window validation:** Verifies that attempts spread across eight minutes do not trigger the five-attempts-within-five-minutes threshold.
- **Successful login exclusion:** Verifies that successful login events are not included in failed-login counts.
- **Invalid IP handling:** Verifies that invalid IP addresses are ignored and do not affect detection results.

**Test execution command:**

```bash
python -m unittest -v
```

**Test result:**

```text
Ran 4 tests

OK
```

All four automated tests passed successfully.

## 10. Limitations

- This is an educational cybersecurity log-analysis tool.
- It analyzes a local sample authentication log file rather than monitoring a live SSH server.
- A flagged IP address indicates potentially suspicious activity and is not proof of a malicious attack.
- The detection thresholds are configurable project settings and may require tuning in real environments.
- The sample log timestamps do not contain a year, so the current implementation assumes the year 2026 when parsing these sample timestamps.
- The program currently focuses on IPv4 addresses and failed SSH password authentication events.
- The tool does not automatically block IP addresses or take action against detected activity.

## 11. Future Improvements

- Support additional authentication log formats.
- Add support for IPv6 addresses.
- Generate graphical reports and visualizations.
- Integrate with real-time log monitoring systems.
- Add email or dashboard alerts for potentially suspicious activity.
- Improve detection using more advanced behavioral analysis.
- Integrate with security monitoring platforms such as SIEM tools.

## 12. Disclaimer

This project uses fictional sample authentication logs and documentation-only IP addresses for educational cybersecurity purposes.

It is intended for learning Python, log analysis, basic threat detection, and cybersecurity concepts. It should not be considered a production-ready intrusion detection system.
