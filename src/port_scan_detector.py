from collections import defaultdict
from datetime import datetime, timedelta


def detect_port_scans(
    events,
    port_threshold=5,
    time_window_seconds=60
):
    """
    Detect possible TCP port scans using Windows Firewall events.

    An alert is generated when one source IP attempts connections
    to at least `port_threshold` distinct destination ports on the
    same destination IP within the configured time window.

    DROP events are included because blocked attempts can still
    provide useful evidence of reconnaissance.
    """
    grouped_events = defaultdict(list)

    for event in events:
        if event.get("protocol", "").upper() != "TCP":
            continue

        action = event.get("action", "").upper()
        if action not in {"ALLOW", "DROP"}:
            continue

        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dst_ip", "")
        dst_port = event.get("dst_port", "")

        if not src_ip or not dst_ip:
            continue

        try:
            port = int(dst_port)
        except (ValueError, TypeError):
            continue

        if not 1 <= port <= 65535:
            continue

        timestamp_text = (
            f"{event.get('date', '')} {event.get('time', '')}"
        )

        try:
            timestamp = datetime.strptime(
                timestamp_text, "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            continue

        grouped_events[(src_ip, dst_ip)].append({
            "timestamp": timestamp,
            "dst_port": port,
            "action": action,
        })

    alerts = []

    for (src_ip, dst_ip), records in grouped_events.items():
        records.sort(key=lambda item: item["timestamp"])

        left = 0
        for right, current in enumerate(records):
            while (
                current["timestamp"] - records[left]["timestamp"]
                > timedelta(seconds=time_window_seconds)
            ):
                left += 1

            window = records[left:right + 1]
            unique_ports = sorted({
                item["dst_port"] for item in window
            })

            if len(unique_ports) >= port_threshold:
                alerts.append({
                    "rule_id": "SL003",
                    "rule_name": "Potential TCP Port Scan",
                    "severity": "MEDIUM",
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "destination_ports": unique_ports,
                    "unique_ports": len(unique_ports),
                    "time_window_seconds": time_window_seconds,
                    "first_seen": window[0]["timestamp"].isoformat(),
                    "last_seen": current["timestamp"].isoformat(),
                    "firewall_actions": sorted({
                        item["action"] for item in window
                    }),
                    "reason": (
                        f"Source {src_ip} contacted {len(unique_ports)} "
                        f"distinct TCP destination ports on {dst_ip} "
                        f"within {time_window_seconds} seconds."
                    ),
                    "mitre_attack": "T1046",
                    "mitre_technique_name": "Network Service Discovery",
                    "investigation_guidance": (
                        "Verify the source host and authorized activity. "
                        "Review destination ports, firewall actions, and "
                        "related events before classifying the activity."
                    ),
                })
                break

    return alerts


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print(
            "Usage: python port_scan_detector.py <pfirewall.log>"
        )
        raise SystemExit(1)

    from firewall_parser import parse_firewall_log

    records = parse_firewall_log(sys.argv[1])
    alerts = detect_port_scans(records)

    print(f"Firewall events parsed: {len(records)}")
    print(f"Port-scan alerts generated: {len(alerts)}")

    print(json.dumps(alerts, indent=2))