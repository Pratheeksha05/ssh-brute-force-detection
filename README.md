# SSH Brute-Force Attack Detection and Log Analysis Using Python

## 1. Project Overview

This project is a Python-based cybersecurity tool designed to analyze SSH authentication logs and identify potentially suspicious IP addresses based on repeated failed login attempts.

The tool reads a sample authentication log file, extracts IP addresses associated with failed login attempts, counts the failures, and identifies IP addresses that reach a predefined threshold.

## 2. Objectives

- Analyze SSH authentication logs.
- Detect repeated failed login attempts.
- Extract source IP addresses.
- Count failed login attempts for each IP address.
- Flag potentially suspicious IP addresses.
- Generate a CSV security report.

## 3. Technologies Used

- Python 3
- Visual Studio Code
- Regular Expressions
- CSV module
- Collections module

## 4. Project Structure

```text
SSH-Brute-Force-Detection/
│
├── detector.py
├── auth.log
├── security_report.csv
└── README.md
```

## 5. How It Works

1. The program reads the authentication log file.
2. It searches for entries containing "Failed password".
3. It extracts the associated IP addresses.
4. It counts failed login attempts using Python's Counter.
5. It compares the counts against a threshold of 5.
6. It flags IP addresses that meet or exceed the threshold.
7. It exports the results to a CSV report.

## 6. Detection Logic

The configured detection threshold is 5 failed login attempts.

An IP address with 5 or more failed attempts is classified as "Potentially Suspicious".

An IP address with fewer than 5 failed attempts is classified as "Below Threshold".

## 7. Sample Results

| IP Address | Failed Attempts | Status |
|---|---:|---|
| 192.0.2.10 | 5 | Potentially Suspicious |
| 192.0.2.20 | 2 | Below Threshold |

## 8. How to Run

1. Install Python 3.
2. Open the project folder in Visual Studio Code.
3. Open the terminal in the project folder.
4. Run:

```bash
python detector.py
```

5. View the generated `security_report.csv` file.

## 9. Testing

The project was tested with sample SSH authentication logs.

- An IP address with 5 failed attempts was successfully flagged.
- An IP address with 3 failed attempts was not flagged.
- A successful login event was excluded from failed-login counts.

## 10. Limitations

- This is a basic educational log-analysis tool.
- It analyzes a local sample log file rather than monitoring a live SSH server.
- A flagged IP address is not proof of a malicious attack.
- The detection threshold is configurable and may require tuning in real environments.

## 11. Future Improvements

- Validate extracted IP addresses.
- Add timestamps to security reports.
- Improve detection using time-based thresholds.
- Add graphical reports and visualizations.
- Integrate with real-time log monitoring systems.

## 12. Disclaimer

This project uses fictional sample authentication logs and documentation-only IP addresses for educational cybersecurity purposes.