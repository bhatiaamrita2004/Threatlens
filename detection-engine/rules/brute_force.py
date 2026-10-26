"""Rule: repeated failed logins for one account, or from one source, in a short window."""

from __future__ import annotations

import paths  # noqa: F401
from alert import Alert
from events import SecurityEvent
from window import find_bursts

RULE_NAME = "repeated_failed_logins"
THRESHOLD = 5          # failed logins needed to start a burst
WINDOW_SECONDS = 60
HIGH_AT = 10           # bursts this large are HIGH; smaller ones are MEDIUM


def detect(
    events: list[SecurityEvent],
    threshold: int = THRESHOLD,
    window_seconds: float = WINDOW_SECONDS,
) -> list[Alert]:
    failures = [e for e in events if e.event_type == "LOGIN_FAILED"]
    alerts: list[Alert] = []

    for key_name in ("user_id", "source_ip"):
        bursts = find_bursts(
            failures,
            group_key=lambda e, k=key_name: getattr(e, k),
            metric=len,
            threshold=threshold,
            window_seconds=window_seconds,
        )
        for key, run, peak in bursts:
            alerts.append(_alert(key_name, key, run, peak, threshold, window_seconds))
    return alerts


def _alert(key_name, key, run, peak, threshold, window_seconds) -> Alert:
    count = len(run)
    return Alert(
        rule_name=RULE_NAME,
        severity="HIGH" if count >= HIGH_AT else "MEDIUM",
        timestamp=run[-1].timestamp,
        reason=(
            f"{count} failed logins for {key_name} {key} "
            f"within {window_seconds}s bursts"
        ),
        user_id=key if key_name == "user_id" else None,
        source_ip=key if key_name == "source_ip" else None,
        evidence_event_ids=[e.event_id for e in run],
        details={
            "group_by": key_name,
            "threshold": threshold,
            "window_seconds": window_seconds,
            "peak_in_window": peak,
        },
    )