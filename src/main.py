import argparse
import json
import sys
from pathlib import Path

from event_parser import parse_sysmon_xml
from detector import analyze_events
from reporter import generate_report


def main():
    parser = argparse.ArgumentParser(
        description="SentinelLite SOC Detection Engine"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to an exported Sysmon XML file"
    )

    parser.add_argument(
        "--output",
        default="reports",
        help="Directory where alert reports will be saved"
    )

    args = parser.parse_args()

    input_file = Path(args.input)

    if not input_file.is_file():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)

    print("=" * 50)
    print(" SentinelLite | SOC Detection Engine")
    print("=" * 50)

    print("\n[1/3] Parsing Sysmon events...")
    events = parse_sysmon_xml(input_file)

    if not events:
        print("No events were parsed. Check the input XML file.")
        sys.exit(1)

    print(f"Events parsed: {len(events)}")

    print("\n[2/3] Analyzing events...")
    alerts = analyze_events(events)
    print(f"Alerts generated: {len(alerts)}")

    print("\n[3/3] Generating report...")
    report_file = generate_report(alerts, args.output)

    print("\nAnalysis complete.")
    print(f"Report location: {report_file.resolve()}")


if __name__ == "__main__":
    main()