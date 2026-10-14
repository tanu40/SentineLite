# 🛡️ SentinelLite — Lightweight SOC Detection Engine

**A Python-based security monitoring project for analyzing Windows Sysmon telemetry, detecting suspicious activity, and generating structured security alerts.**

SentinelLite is a hands-on cybersecurity project designed to demonstrate core Security Operations Center (SOC) workflows, including log analysis, rule-based detection, security alert generation, and investigation guidance.

The project is being developed and tested in a controlled virtual lab using Windows 10, Kali Linux, VMware Workstation, and Python.

---

## 📌 Project Overview

Security analysts investigate endpoint and network telemetry to identify suspicious activity, understand potential threats, and support incident response.

SentinelLite implements a lightweight detection pipeline that processes exported Windows Sysmon XML events, evaluates configurable JSON detection rules, and generates structured JSON reports.

The project also includes a separate parser for Windows Defender Firewall logs, allowing firewall records to be examined for network activity.

**Primary objective:** Build a practical, lightweight SOC analysis tool that demonstrates log parsing, detection engineering, alert enrichment, and security investigation fundamentals.

## ✨ Key Features

### 1. Windows Sysmon Log Parser
- Parses exported Sysmon XML logs.
- Extracts event IDs, timestamps, computer names, and event data.
- Converts raw XML events into structured Python records.
- Supports analysis of actual Windows endpoint telemetry.

### 2. Rule-Based Detection Engine
- Loads detection rules from JSON files.
- Evaluates event data against configured detection conditions.
- Identifies selected indicators of potentially suspicious process activity.
- Supports suspicious PowerShell activity detection.

### 3. Security Alert Generation
Generated alerts can include:

- Rule ID and detection name
- Severity
- Sysmon event ID
- Timestamp and computer name
- Process image and command line
- Parent process
- Matched indicator
- MITRE ATT&CK technique and name
- Investigation guidance

### 4. JSON Alert Reporting
- Generates structured JSON reports.
- Records the total number of generated alerts.
- Preserves detection details for review and documentation.
- Supports a repeatable analysis workflow.

### 5. Windows Firewall Log Parser
- Parses Windows Defender Firewall text logs.
- Extracts source and destination IP addresses.
- Extracts source and destination ports.
- Identifies recorded actions and protocols.
- Produces structured records for further analysis.

### 6. Controlled Network Reconnaissance Lab
- Uses Kali Linux to perform a limited Nmap scan against a Windows virtual machine.
- Collects Windows Firewall telemetry.
- Demonstrates how network activity can be investigated using host-side logs.

**Note:** Automated port-scan detection and correlation between firewall records and endpoint events are planned improvements, not completed features.

---

## 🏗️ Architecture

### Endpoint Detection Pipeline

```text
       Windows Sysmon XML
                |
                v
         Event Parser
                |
                v
       Detection Engine <---- JSON Detection Rules
                |
                v
         Alert Reporter
                |
                v
          JSON Report
```

### Firewall Log Analysis Pipeline

```text
 Windows Defender Firewall Log
                |
                v
         Firewall Parser
                |
                v
      Structured Network Events
                |
                v
       Future Detection Module
```

The Sysmon and firewall parsers are separate components because they process different log formats.

---

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| Python | Log parsing, detection logic, and reporting |
| Microsoft Sysmon | Windows endpoint telemetry |
| Windows Defender Firewall | Network connection logging |
| Kali Linux | Controlled security testing |
| Nmap | Network reconnaissance |
| VMware Workstation | Isolated virtual lab environment |
| JSON | Detection rules and alert reports |
| XML | Exported Sysmon event format |
| MITRE ATT&CK | Adversary technique classification |

**Dependencies:** The current implementation uses Python standard-library modules and does not require third-party Python packages.

---

## 📂 Project Structure

```text
SentinelLite/
├── README.md
├── .gitignore
├── requirements.txt
│
├── src/
│   ├── main.py
│   ├── event_parser.py
│   ├── detector.py
│   ├── reporter.py
│   └── firewall_parser.py
│
├── rules/
│   ├── suspicious_process.json
│   └── suspicious_powershell.json
│
├── samples/
│   └── sample_events.xml
│
├── reports/
│
├── docs/
│   └── screenshots/
│
└── tests/
```

This structure describes the intended repository layout. Some folders, such as `reports/`, `docs/screenshots/`, and `tests/`, may initially be empty or contain only selected files.

---

## ⚙️ Setup and Installation

### Requirements

- Python 3.10 or later recommended
- Windows Sysmon XML export for endpoint analysis
- Windows Defender Firewall log for firewall parsing
- Git and GitHub for repository access

### Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/SentinelLite.git
cd SentinelLite
```

Replace `YOUR_USERNAME` with your GitHub username.

No third-party Python packages are currently required.

---

## 🚀 Usage

### 1. Analyze Sysmon XML Events

Run the detection engine from the repository root:

```bash
python src/main.py --input samples/sample_events.xml
```

To specify an output directory:

```bash
python src/main.py --input samples/sample_events.xml --output reports
```

The engine performs the following operations:

1. Parses the supplied Sysmon XML file.
2. Loads the configured detection rules.
3. Evaluates parsed events against those rules.
4. Generates a JSON alert report.
5. Displays the analysis summary and report location.

**Input requirement:** Supply an XML file containing exported Sysmon events in the format supported by the parser.

### 2. Parse Windows Firewall Logs

Run:

```bash
python src/firewall_parser.py path/to/pfirewall.log
```

Replace `path/to/pfirewall.log` with the path to your firewall log file.

The parser displays the number of records parsed and sample network events, including source IPs, destination IPs, ports, protocols, and recorded actions.

**Important:** The firewall parser currently extracts and structures records. It does not yet automatically detect port scans.

---

## 🔎 Detection Rules

### Suspicious PowerShell Activity

**Rule ID:** `SL002`

**Severity:** MEDIUM

**MITRE ATT&CK technique:** [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)

This rule identifies selected indicators of potentially suspicious PowerShell execution, including encoded-command indicators.

PowerShell is a legitimate Windows administration tool, but attackers can also abuse it to execute commands and conceal activity.

The presence of an encoded command alone does not establish malicious intent. Analysts should examine the command, parent process, user context, surrounding events, and other available evidence.

### Suspicious Process Activity

The project also includes a JSON rule for selected suspicious process indicators.

Detection behavior depends on the conditions configured in the rule file. The rules are intended for educational and lab use and should be validated before use in operational environments.

---

## 🧪 Lab Testing and Validation

The following results were observed during development.

| Test | Observed Result |
|---|---|
| Initial Sysmon XML test | 3 events parsed |
| Initial detection test | 2 alerts generated |
| Real Sysmon telemetry analysis | 1 event parsed |
| Real telemetry detection test | 1 alert generated |
| Firewall log parsing | 87 records parsed |
| Kali-to-Windows reconnaissance | Windows lab host discovered |
| Firewall port-scan detection | Not yet implemented |

### Test 1: Sysmon XML Analysis

The detection engine successfully parsed a real Sysmon event and generated a structured JSON alert.

The alert contained process information, the matching detection rule, severity, MITRE ATT&CK mapping, and investigation guidance.

### Test 2: Encoded PowerShell Detection

A Sysmon process-creation event contained the following command:

```powershell
powershell.exe -NoProfile -EncodedCommand RwBlAHQALQBEAGEAdABlAA==
```

The encoded command decoded to:

```powershell
Get-Date
```

This command is benign and displays the current date and time.

The detection rule successfully identified the encoded-command indicator. However, this result validated the detection mechanism rather than confirming a real attack.

This demonstrates an important SOC principle: **an alert is an investigative lead, not proof of malicious activity.**

### Test 3: Windows Firewall Log Parsing

Windows Defender Firewall logging was enabled in the Windows lab VM.

The firewall parser successfully processed **87 records** and extracted structured network fields.

These records included ordinary Windows network traffic. Further analysis is required to establish which entries correspond to the Nmap scan.

### Test 4: Kali Linux Network Reconnaissance

A limited Nmap TCP scan was performed from Kali Linux against the Windows virtual machine on a private VMware network.

The target was reachable, but the scanned ports were reported as filtered.

This result is consistent with network filtering, although the scan alone does not establish which services are running or prove that the host is secure.

The lab demonstrates controlled reconnaissance and collection of network telemetry. Automated identification of the scan from firewall logs remains future work.

---

## 📸 Screenshots and Evidence

Screenshots will be added to the repository as the project documentation develops.

Planned evidence includes:

- Project directory structure
- Detection engine implementation
- Windows Sysmon Operational logs
- Parsed Sysmon event details
- Real Sysmon analysis output
- JSON detection report
- Kali Linux Nmap scan output
- Windows Firewall logs
- Firewall parser code and output

Screenshots should demonstrate actual execution and observed results rather than simulated or fabricated alerts.

---

## ⚠️ Current Limitations

- Detection coverage is limited to the configured rules.
- Encoded PowerShell detection can generate false positives.
- Firewall logs are parsed separately from Sysmon events.
- Automated port-scan detection is not yet implemented.
- Cross-source event correlation is not yet implemented.
- The current engine analyzes exported logs rather than continuously monitoring a live endpoint.
- The project has not been validated for production SOC deployment.
- Automated unit-test coverage is still to be developed.

---

## 🛣️ Future Improvements

Planned improvements include:

- Detect potential port scanning using firewall connection records.
- Correlate endpoint and network telemetry.
- Add unit tests for parsers and detection rules.
- Expand detection coverage for suspicious processes and command execution.
- Improve severity scoring and false-positive handling.
- Add sanitized example alerts and investigation case reports.
- Improve detection documentation and validation.
- Explore near-real-time log monitoring.

---

## 🔐 Security and Privacy

SentinelLite is intended for educational use and authorized security testing.

- Test only on systems you own or have permission to assess.
- Do not publish credentials, personal information, or sensitive system details.
- Review exported security logs before committing them to a public repository.
- Avoid uploading raw telemetry when it contains unnecessary host or user information.
- Treat detection alerts as leads that require investigation.

---

## 👩‍💻 Author

**Tanushka Kumbhar**

Cybersecurity interests: SOC analysis, threat intelligence, detection engineering, log analysis, and incident response.

---

## ⭐ Project Status

**Status:** In development

SentinelLite currently supports Sysmon XML parsing, JSON-based detection rules, structured alert reporting, and Windows Firewall log parsing.

Further work will focus on network reconnaissance detection, event correlation, expanded testing, and improved investigation workflows.
