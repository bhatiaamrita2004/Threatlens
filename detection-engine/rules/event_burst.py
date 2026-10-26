"""Rule: unusually many events from one source in a short window."""

from __future__ import annotations

import paths  # noqa: F401
from alert import Alert
from events import SecurityEvent
from window import find_bursts

RULE_NAME = "event_burst"
BURST_THRESHOLD = 30   # events from one source needed to start a burst
WINDOW_SECONDS = 60


def detect(
    events: list[SecurityEvent],
    threshold: int = BURST_THRESHOLD,
    window_seconds: float = WINDOW_SECONDS,
) -> list[Alert]:
    alerts: list[Alert] = []
    bursts = find_bursts(
        events,
        group_key=lambda e: e.source_ip,
        metric=len,
        threshold=threshold,
        window_seconds=window_seconds,
    )
    for source_ip, run, peak in bursts:
        alerts.append(
            Alert(
                rule_name=RULE_NAME,
                severity="MEDIUM",
                timestamp=run[-1].timestamp,
                reason=f"{len(run)} events from {source_ip} within {window_seconds}s",
                user_id=None,
                source_ip=source_ip,
                evidence_event_ids=[e.event_id for e in run],
                details={
                    "event_types": sorted({e.event_type for e in run}),
                    "users": sorted({e.user_id for e in run}),
                    "threshold": threshold,
                    "window_seconds": window_seconds,
                    "peak_in_window": peak,
                },
            )
        )
    return alerts