import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "src")
)

from port_scan_detector import detect_port_scans


class TestPortScanDetector(unittest.TestCase):

    def make_event(self, timestamp, port, src_ip="192.168.35.128"):
        return {
            "date": timestamp.strftime("%Y-%m-%d"),
            "time": timestamp.strftime("%H:%M:%S"),
            "action": "DROP",
            "protocol": "TCP",
            "src_ip": src_ip,
            "dst_ip": "192.168.35.129",
            "src_port": "50000",
            "dst_port": str(port),
        }

    def test_detects_five_distinct_ports(self):
        start = datetime(2026, 10, 24, 10, 0, 0)
        events = [
            self.make_event(start + timedelta(seconds=i), port)
            for i, port in enumerate([21, 22, 23, 80, 443])
        ]

        alerts = detect_port_scans(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "SL003")
        self.assertEqual(alerts[0]["unique_ports"], 5)

    def test_ignores_fewer_than_five_distinct_ports(self):
        start = datetime(2026, 10, 24, 10, 0, 0)
        events = [
            self.make_event(start + timedelta(seconds=i), port)
            for i, port in enumerate([135, 139, 445])
        ]

        alerts = detect_port_scans(events)

        self.assertEqual(alerts, [])

    def test_ignores_events_outside_time_window(self):
        start = datetime(2026, 10, 24, 10, 0, 0)
        ports = [21, 22, 23, 80, 443]

        events = [
            self.make_event(start + timedelta(seconds=i * 20), port)
            for i, port in enumerate(ports)
        ]

        alerts = detect_port_scans(events)

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)