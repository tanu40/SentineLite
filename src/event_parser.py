import xml.etree.ElementTree as ET
from pathlib import Path
import sys


def parse_sysmon_xml(file_path):
    """Parse exported Sysmon XML events into structured records."""
    events = []

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Handle XML namespaces by matching local tag names.
        for event in root.iter():
            if event.tag.split("}")[-1] != "Event":
                continue

            system = None

            for child in event:
                if child.tag.split("}")[-1] == "System":
                    system = child
                    break

            if system is None:
                continue

            event_id = None
            timestamp = ""
            computer = ""
            event_data = {}

            for element in system.iter():
                tag = element.tag.split("}")[-1]

                if tag == "EventID" and element.text:
                    try:
                        event_id = int(element.text)
                    except ValueError:
                        pass

                elif tag == "TimeCreated":
                    timestamp = element.get("SystemTime", "")

                elif tag == "Computer":
                    computer = element.text or ""

            for element in event.iter():
                if element.tag.split("}")[-1] == "Data":
                    name = element.get("Name")
                    if name:
                        event_data[name] = element.text or ""

            events.append({
                "event_id": event_id,
                "timestamp": timestamp,
                "computer": computer,
                "data": event_data
            })

    except (ET.ParseError, OSError) as error:
        print(f"Error reading Sysmon XML: {error}")

    return events


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python event_parser.py <sysmon-export.xml>")
        raise SystemExit(1)

    records = parse_sysmon_xml(sys.argv[1])
    print(f"Events parsed: {len(records)}")

    for record in records[:5]:
        print(
            f"Event ID: {record['event_id']} | "
            f"Time: {record['timestamp']} | "
            f"Computer: {record['computer']}"
        )
        print(f"  Image: {record['data'].get('Image', '')}")
        print(
            f"  CommandLine: "
            f"{record['data'].get('CommandLine', '')}"
        )
