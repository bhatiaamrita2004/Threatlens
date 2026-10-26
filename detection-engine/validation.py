"""Load and validate event JSON files (Phase 2).

Invalid records are skipped and reported, so one bad record does not stop
the whole file from being checked.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import paths  # noqa: F401  (sets up sys.path)
from events import SecurityEvent

REQUIRED_FIELDS = {
    "event_id", "timestamp", "user_id", "source_ip",
    "event_type", "status", "metadata",
}


def load_events(path: Path) -> tuple[list[SecurityEvent], list[str]]:
    """Return (valid_events, problems) for one JSON file."""
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], [f"{path.name}: cannot read JSON ({exc})"]

    if not isinstance(raw, list):
        return [], [f"{path.name}: top level must be a JSON array"]

    events: list[SecurityEvent] = []
    problems: list[str] = []
    for index, record in enumerate(raw):
        event, problem = _parse_record(record, f"{path.name}[{index}]")
        if problem:
            problems.append(problem)
        else:
            events.append(event)
    return events, problems


def _parse_record(record, where: str) -> tuple[SecurityEvent | None, str | None]:
    if not isinstance(record, dict):
        return None, f"{where}: record is not an object"

    missing = REQUIRED_FIELDS - record.keys()
    if missing:
        return None, f"{where}: missing fields {sorted(missing)}"

    for field_name in ("event_id", "user_id", "source_ip"):
        value = record[field_name]
        if not isinstance(value, str) or not value.strip():
            return None, f"{where}: {field_name} must be a non-empty string"

    try:
        timestamp = datetime.fromisoformat(record["timestamp"])
    except (TypeError, ValueError):
        return None, f"{where}: timestamp is not ISO-8601 ({record['timestamp']!r})"

    fields = {k: v for k, v in record.items() if k != "timestamp"}
    try:
        return SecurityEvent(timestamp=timestamp, **fields), None
    except (TypeError, ValueError) as exc:
        return None, f"{where}: {exc}"