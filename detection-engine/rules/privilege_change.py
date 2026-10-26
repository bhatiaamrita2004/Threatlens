"""Rule: a successful privilege change, with extra weight for sensitive roles."""

from __future__ import annotations

import paths  # noqa: F401
from alert import Alert
from events import SecurityEvent

RULE_NAME = "privilege_change"
SENSITIVE_ROLES = {"admin", "root", "domain_admin", "security_admin"}


def detect(events: list[SecurityEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        if event.event_type != "PRIVILEGE_CHANGE" or event.status != "SUCCESS":
            continue  # failed attempts are not changes; they are out of scope here

        role = str(event.metadata.get("role", "unknown")).lower()
        sensitive = role in SENSITIVE_ROLES
        alerts.append(
            Alert(
                rule_name=RULE_NAME,
                severity="HIGH" if sensitive else "LOW",
                timestamp=event.timestamp,
                reason=(
                    f"privilege change to role '{role}' for {event.user_id}"
                    + (" (sensitive role)" if sensitive else "")
                ),
                user_id=event.user_id,
                source_ip=event.source_ip,
                evidence_event_ids=[event.event_id],
                details={"role": role, "sensitive": sensitive},
            )
        )
    return alerts