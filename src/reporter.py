import json
from datetime import datetime
from pathlib import Path


def generate_report(alerts, output_dir="reports"):
    """Save detection alerts as a JSON investigation report."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    report = {
        "project": "SentinelLite",
        "generated_at": datetime.now().astimezone().isoformat(),
        "total_alerts": len(alerts),
        "alerts": alerts,
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = output_path / f"alert_report_{timestamp}.json"

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"Report saved to: {report_file.resolve()}")
    print(f"Total alerts: {len(alerts)}")

    return report_file