import json
import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = PROJECT_ROOT / "rules"


def load_rules(rules_dir=DEFAULT_RULES_DIR):
    """Load detection rules from JSON files."""

    rules = []
    rules_path = Path(rules_dir)

    if not rules_path.is_dir():
        raise FileNotFoundError(
            f"Detection rules directory not found: {rules_path}"
        )

    for rule_file in sorted(rules_path.glob("*.json")):
        try:
            with rule_file.open("r", encoding="utf-8") as file:
                rule = json.load(file)

            if not isinstance(rule, dict):
                print(f"Skipping invalid rule file: {rule_file.name}")
                continue

            rules.append(rule)

        except (json.JSONDecodeError, OSError) as error:
            print(f"Could not load {rule_file.name}: {error}")

    print(f"Detection rules loaded: {len(rules)}")
    return rules


def match_rule(event, rule):
    """Check whether a Sysmon event matches a detection rule."""

    if event.get("event_id") != rule.get("event_id"):
        return None

    data = event.get("data", {})
    field = rule.get("field", "CommandLine")
    field_value = data.get(field, "")

    if not field_value:
        return None

    # Apply process restrictions when the rule defines them.
    process_indicators = rule.get("process_indicators", [])

    if process_indicators:
        image = data.get("Image", "").lower()
        parent_image = data.get("ParentImage", "").lower()

        process_matches = any(
            indicator.lower() in image
            or indicator.lower() in parent_image
            for indicator in process_indicators
        )

        if not process_matches:
            return None

    # Match the field against the rule's patterns.
    for pattern in rule.get("patterns", []):
        if re.search(pattern, field_value, re.IGNORECASE):
            return pattern

    return None


def detect_suspicious_activity(event, rules=None):
    """Analyze one Sysmon event against the loaded detection rules."""

    if rules is None:
        rules = load_rules()

    alerts = []
    data = event.get("data", {})

    for rule in rules:
        matched_pattern = match_rule(event, rule)

        if matched_pattern is None:
            continue

        mitre = rule.get("mitre_attack", {})

        alerts.append({
            "rule_id": rule.get("rule_id", "UNKNOWN"),
            "rule_name": rule.get("name", "Unnamed Detection Rule"),
            "severity": rule.get("severity", "LOW"),
            "event_id": event.get("event_id"),
            "timestamp": event.get("timestamp", ""),
            "computer": event.get("computer", ""),
            "process": data.get("Image", ""),
            "parent_process": data.get("ParentImage", ""),
            "command_line": data.get("CommandLine", ""),
            "matched_pattern": matched_pattern,
            "reason": rule.get("description", ""),
            "mitre_attack": mitre.get("technique_id", "N/A"),
            "mitre_technique_name": mitre.get("technique_name", ""),
            "investigation_guidance": rule.get(
                "investigation_guidance", ""
            ),
        })

    return alerts


def analyze_events(events, rules_dir=DEFAULT_RULES_DIR):
    """Analyze multiple events using JSON-based detection rules."""

    rules = load_rules(rules_dir)
    all_alerts = []

    for event in events:
        all_alerts.extend(
            detect_suspicious_activity(event, rules)
        )

    return all_alerts