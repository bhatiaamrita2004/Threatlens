"""Run all Phase 2 rules over event files and print the alerts.

Usage (from the repo root):
    python3 detection-engine/pipeline.py                 # every file in data/raw
    python3 detection-engine/pipeline.py data/raw/scenario_brute_force.json
    python3 detection-engine/pipeline.py --json alerts.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import paths  # noqa: F401
from alert import Alert
from events import SecurityEvent
from rules import brute_force, event_burst, port_scan, privilege_change
from validation import load_events

RULES = [brute_force.detect, port_scan.detect, event_burst.detect, privilege_change.detect]


def run_rules(events: list[SecurityEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in RULES:
        alerts.extend(rule(events))
    return sorted(alerts, key=lambda a: a.timestamp)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run detection rules on event JSON files.")
    parser.add_argument("files", nargs="*", type=Path)
    parser.add_argument("--json", type=Path, help="also write all alerts to this file")
    args = parser.parse_args()

    files = args.files or sorted(paths.RAW_DATA_DIR.glob("*.json"))
    all_alerts: list[dict] = []

    for file in files:
        events, problems = load_events(file)
        alerts = run_rules(events)
        print(f"\n== {file.name}: {len(events)} valid events, {len(problems)} problems, {len(alerts)} alerts")
        for problem in problems:
            print(f"   problem: {problem}")
        for alert in alerts:
            print(f"   [{alert.severity}] {alert.rule_name} @ {alert.timestamp.isoformat()}: {alert.reason}")
            print(f"           evidence: {len(alert.evidence_event_ids)} events")
        all_alerts.extend({"file": file.name, **a.to_dict()} for a in alerts)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(all_alerts, indent=2), encoding="utf-8")
        print(f"\nWrote {len(all_alerts)} alerts to {args.json}")


if __name__ == "__main__":
    main()