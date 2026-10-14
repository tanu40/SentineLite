from pathlib import Path


def parse_firewall_log(file_path):
    """Parse Windows Defender Firewall text logs."""
    events = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            fields = []

            for line in file:
                line = line.strip()

                if not line:
                    continue

                if line.startswith("#Fields:"):
                    fields = line.split()[1:]
                    continue

                if line.startswith("#") or not fields:
                    continue

                values = line.split()

                if len(values) != len(fields):
                    continue

                event = dict(zip(fields, values))

                events.append({
                    "date": event.get("date", ""),
                    "time": event.get("time", ""),
                    "action": event.get("action", "").upper(),
                    "protocol": event.get("protocol", "").upper(),
                    "src_ip": event.get("src-ip", ""),
                    "dst_ip": event.get("dst-ip", ""),
                    "src_port": event.get("src-port", ""),
                    "dst_port": event.get("dst-port", ""),
                    "size": event.get("size", ""),
                    "tcp_flags": event.get("tcpflags", ""),
                    "raw": event
                })

    except OSError as error:
        print(f"Error reading firewall log: {error}")

    return events


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python firewall_parser.py <pfirewall.log>")
        raise SystemExit(1)

    records = parse_firewall_log(sys.argv[1])

    print(f"Firewall events parsed: {len(records)}")

    for record in records[:10]:
        print(
            f"{record['date']} {record['time']} | "
            f"{record['action']} | "
            f"{record['src_ip']}:{record['src_port']} -> "
            f"{record['dst_ip']}:{record['dst_port']} | "
            f"{record['protocol']}"
        )