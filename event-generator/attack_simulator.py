"""Synthetic attack-like scenarios for ThreatLens (Phase 1).

These are simulated patterns for testing detection logic. They are not
real attacks, and every event is labelled synthetic in its metadata.

Usage (from the repo root):
    python event-generator/attack_simulator.py
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import ATTACKER_IP, INTERNAL_IPS, RAW_DATA_DIR
from events import SecurityEvent
from generator import write_events

DEFAULT_START = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _meta(scenario: str, **extra) -> dict:
    return {"synthetic": True, "scenario": scenario, **extra}


def brute_force_events(
    user_id: str = "U105",
    attempts: int = 12,
    start: datetime = DEFAULT_START,
    interval_seconds: int = 5,
) -> list[SecurityEvent]:
    """Repeated failed logins for one account from one source, in a short window."""
    events = [
        SecurityEvent(
            user_id=user_id,
            source_ip=ATTACKER_IP,
            event_type="LOGIN_FAILED",
            status="FAILURE",
            timestamp=start + timedelta(seconds=i * interval_seconds),
            location="remote-vpn",
            metadata=_meta("brute_force", attempt=i + 1),
        )
        for i in range(attempts)
    ]
    return events


def port_scan_events(
    source_ip: str = ATTACKER_IP,
    target_ip: str = INTERNAL_IPS[0],
    ports: range = range(20, 120),
    start: datetime = DEFAULT_START,
    interval_ms: int = 200,
) -> list[SecurityEvent]:
    """One source touching many destination ports in a short period."""
    return [
        SecurityEvent(
            user_id="U000",  # no real account is involved in a scan
            source_ip=source_ip,
            event_type="CONNECTION_ATTEMPT",
            status="FAILURE",  # most closed ports refuse the connection
            timestamp=start + timedelta(milliseconds=i * interval_ms),
            location="remote-vpn",
            destination_ip=target_ip,
            destination_port=port,
            protocol="TCP",
            metadata=_meta("port_scan"),
        )
        for i, port in enumerate(ports)
    ]


def unusual_login_events(
    user_id: str = "U110",
    start: datetime = datetime(2026, 10, 1, 3, 17, tzinfo=timezone.utc),
) -> list[SecurityEvent]:
    """A successful login from a new source at an unusual hour."""
    return [
        SecurityEvent(
            user_id=user_id,
            source_ip=ATTACKER_IP,
            event_type="LOGIN_SUCCESS",
            status="SUCCESS",
            timestamp=start,
            location="unknown-region",
            metadata=_meta("unusual_login", note="new source and off-hours"),
        )
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Write synthetic attack scenarios.")
    parser.add_argument("--out-dir", type=Path, default=RAW_DATA_DIR)
    args = parser.parse_args()

    scenarios = {
        "scenario_brute_force.json": brute_force_events(),
        "scenario_port_scan.json": port_scan_events(),
        "scenario_unusual_login.json": unusual_login_events(),
    }
    for name, events in scenarios.items():
        write_events(events, args.out_dir / name)
        print(f"Wrote {len(events)} events to {args.out_dir / name}")


if __name__ == "__main__":
    main()