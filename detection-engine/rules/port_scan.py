"""Rule: one source contacts many distinct destination ports in a short window."""

from __future__ import annotations

import paths  # noqa: F401
from alert import Alert
from events import SecurityEvent
from window import find_bursts

RULE_NAME = "many_ports_one_source"
PORT_THRESHOLD = 20    # distinct ports needed to start a burst
WINDOW_SECONDS = 60
HIGH_AT = 50           # distinct ports at which the alert is HIGH


def detect(
    events: list[SecurityEvent],
    port_threshold: int = PORT_THRESHOLD,
    window_seconds: float = WINDOW_SECONDS,
) -> list[Alert]:
    attempts = [
        e for e in events
        if e.event_type == "CONNECTION_ATTEMPT" and e.destination_port is not None
    ]

    def distinct_ports(window_events: list[SecurityEvent]) -> int:
        return len({e.destination_port for e in window_events})

    alerts: list[Alert] = []
    bursts = find_bursts(
        attempts,
        group_key=lambda e: e.source_ip,
        metric=distinct_ports,
        threshold=port_threshold,
        window_seconds=window_seconds,
    )
    for source_ip, run, _peak in bursts:
        ports = sorted({e.destination_port for e in run})
        alerts.append(
            Alert(
                rule_name=RULE_NAME,
                severity="HIGH" if len(ports) >= HIGH_AT else "MEDIUM",
                timestamp=run[-1].timestamp,
                reason=(
                    f"{len(ports)} distinct destination ports probed by "
                    f"{source_ip} within {window_seconds}s"
                ),
                user_id=None,
                source_ip=source_ip,
                evidence_event_ids=[e.event_id for e in run],
                details={
                    "distinct_ports": len(ports),
                    "ports": ports,
                    "destination_ips": sorted({e.destination_ip for e in run}),
                    "threshold": port_threshold,
                    "window_seconds": window_seconds,
                },
            )
        )
    return alerts