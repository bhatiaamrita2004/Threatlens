"""Generate normal synthetic security events and save them as JSON.

Usage (from the repo root):
    python event-generator/generator.py --count 500
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import CLIENT_IPS, COMMON_PORTS, INTERNAL_IPS, LOCATIONS, RAW_DATA_DIR, SEED, USERS
from events import SecurityEvent

DEFAULT_START = datetime(2026, 10, 1, tzinfo=timezone.utc)


def generate_normal_events(
    count: int,
    seed: int = SEED,
    start: datetime = DEFAULT_START,
    window_hours: int = 24,
) -> list[SecurityEvent]:
    """Create `count` benign events spread over `window_hours`.

    Failed logins are rare and random, so a normal dataset should not
    contain bursts that look like brute-force activity.
    """
    rng = random.Random(seed)
    events: list[SecurityEvent] = []

    for _ in range(count):
        timestamp = start + timedelta(seconds=rng.uniform(0, window_hours * 3600))
        user = rng.choice(USERS)
        location = rng.choice(LOCATIONS)
        roll = rng.random()

        if roll < 0.70:
            event = SecurityEvent(
                user_id=user,
                source_ip=rng.choice(CLIENT_IPS),
                event_type="LOGIN_SUCCESS",
                status="SUCCESS",
                timestamp=timestamp,
                location=location,
            )
        elif roll < 0.73:
            event = SecurityEvent(
                user_id=user,
                source_ip=rng.choice(CLIENT_IPS),
                event_type="LOGIN_FAILED",
                status="FAILURE",
                timestamp=timestamp,
                location=location,
            )
        else:
            event = SecurityEvent(
                user_id=user,
                source_ip=rng.choice(CLIENT_IPS),
                event_type="CONNECTION_ATTEMPT",
                status="SUCCESS",
                timestamp=timestamp,
                location=location,
                destination_ip=rng.choice(INTERNAL_IPS),
                destination_port=rng.choice(COMMON_PORTS),
                protocol="TCP",
            )
        events.append(event)

    events.sort(key=lambda e: e.timestamp)
    return events


def write_events(events: list[SecurityEvent], path: Path) -> None:
    """Save events as a JSON array."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump([e.to_dict() for e in events], f, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate normal synthetic events.")
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--out", type=Path, default=RAW_DATA_DIR / "normal_events.json")
    args = parser.parse_args()

    events = generate_normal_events(args.count, seed=args.seed)
    write_events(events, args.out)
    print(f"Wrote {len(events)} normal events to {args.out}")


if __name__ == "__main__":
    main()