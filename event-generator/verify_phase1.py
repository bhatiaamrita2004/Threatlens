"""Check the Phase 1 completion criteria.

Done when: commands generate valid JSON files with event IDs, timestamps,
user/source fields, event type, status, and scenario metadata.

Usage (from the repo root, after generating the data):
    python3 event-generator/verify_phase1.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

from config import RAW_DATA_DIR
from events import EVENT_TYPES, STATUSES

REQUIRED_FIELDS = {
    "event_id", "timestamp", "user_id", "source_ip",
    "event_type", "status", "metadata",
}

# file name -> expected number of events (None = any count > 0)
EXPECTED_FILES = {
    "normal_events.json": None,
    "scenario_brute_force.json": 12,
    "scenario_port_scan.json": 100,
    "scenario_unusual_login.json": 1,
}


def check_event(event: dict, where: str) -> list[str]:
    problems = []
    missing = REQUIRED_FIELDS - event.keys()
    if missing:
        problems.append(f"{where}: missing fields {sorted(missing)}")
    if event.get("event_type") not in EVENT_TYPES:
        problems.append(f"{where}: invalid event_type {event.get('event_type')!r}")
    if event.get("status") not in STATUSES:
        problems.append(f"{where}: invalid status {event.get('status')!r}")
    try:
        ts = datetime.fromisoformat(event.get("timestamp", ""))
        if ts.tzinfo is None:
            problems.append(f"{where}: timestamp has no timezone")
    except (TypeError, ValueError):
        problems.append(f"{where}: timestamp is not ISO-8601")
    metadata = event.get("metadata") or {}
    if "scenario" not in metadata:
        problems.append(f"{where}: metadata has no scenario")
    return problems


def check_file(path: Path, expected_count: int | None) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path.name}: not readable as JSON ({exc})"]
    if not isinstance(data, list):
        return [f"{path.name}: top level is not a JSON array"]

    problems = []
    if expected_count is None and not data:
        problems.append(f"{path.name}: no events")
    elif expected_count is not None and len(data) != expected_count:
        problems.append(f"{path.name}: expected {expected_count} events, found {len(data)}")

    ids = [e.get("event_id") for e in data]
    if len(ids) != len(set(ids)):
        problems.append(f"{path.name}: duplicate event_id values")

    for i, event in enumerate(data):
        problems.extend(check_event(event, f"{path.name}[{i}]"))
    return problems


def main() -> int:
    all_problems: list[str] = []
    for name, expected in EXPECTED_FILES.items():
        path = RAW_DATA_DIR / name
        if not path.exists():
            all_problems.append(f"{name}: missing (run the generator first)")
            continue
        problems = check_file(path, expected)
        status = "OK" if not problems else "FAIL"
        print(f"[{status}] {name}")
        all_problems.extend(problems)

    if all_problems:
        print("\nProblems found:")
        for p in all_problems:
            print(f"  - {p}")
        return 1
    print("\nPhase 1 completion check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())