# SentinelLite — Lightweight SOC Detection Engine

SentinelLite is a lightweight, Python-based security detection project that simulates core Security Operations Center (SOC) workflows.

It parses Sysmon event logs, evaluates events against configurable JSON detection rules, identifies suspicious activity, and generates structured JSON alert reports.

## Features

- Sysmon XML event log parsing
- JSON-based detection rules
- Suspicious command execution detection
- Suspicious PowerShell activity detection
- MITRE ATT&CK technique mapping
- Automated JSON alert report generation
- Investigation guidance for detected activity
- Lightweight implementation using Python's standard library

## Architecture

    Sysmon Event Logs
           |
           v
       Event Parser
           |
           v
     Detection Engine <--- JSON Detection Rules
           |
           v
      Alert Generation
           |
           v
    JSON Investigation Report

## Detection Rules

| Rule ID | Detection | Severity | MITRE ATT&CK |
|---|---|---|---|
| SL001 | Suspicious System Discovery Command | LOW | T1082 |
| SL002 | Suspicious PowerShell Activity | MEDIUM | T1059.001 |

A rule match is an indicator for investigation, not proof of malicious activity.

## Project Structure

    SentinelLite/
    ├── rules/
    │   ├── suspicious_process.json
    │   └── suspicious_powershell.json
    ├── samples/
    │   └── sample_events.xml
    ├── src/
    │   ├── event_parser.py
    │   ├── detector.py
    │   ├── reporter.py
    │   └── main.py
    └── reports/

## Requirements

- Python 3
- Sysmon XML event logs
- No third-party Python packages required

## Usage

Run the detection engine from the `src` directory:

    python main.py --input ../samples/sample_events.xml

To specify an output directory:

    python main.py --input ../samples/sample_events.xml --output ../reports

The engine parses events, checks them against the configured rules, and generates a JSON alert report.

## Detection Workflow

1. Export Sysmon events in XML format.
2. Provide the XML file as input.
3. Parse event metadata and event data.
4. Evaluate events against JSON detection rules.
5. Map matching detections to MITRE ATT&CK.
6. Generate a JSON report for investigation.

## Limitations

- Current detections use selected command-line indicators.
- Detection matches require contextual investigation.
- Detection coverage depends on the configured rules.
- This project is not a replacement for a production SIEM.

## Future Improvements

- Add more Sysmon detection rules.
- Improve severity summaries and report formatting.
- Add automated detection tests.
- Integrate controlled attack simulations from an authorized lab.
- Document investigation steps and false-positive considerations.

## Disclaimer

This project is intended for educational and defensive security purposes. Use it only in authorized environments.

## Author

Tanushka Kumbhar
