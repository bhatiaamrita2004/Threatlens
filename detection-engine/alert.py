"""Alert record produced by every rule (Phase 2).

Each alert says which rule fired, how severe it is, when it happened, why it
fired, and which events support it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass
class Alert:
    rule_name: str
    severity: str
    timestamp: datetime  # time of the last supporting event
    reason: str
    user_id: str | None
    source_ip: str | None
    evidence_event_ids: list[str]
    details: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"Unknown severity: {self.severity}")
        if not self.evidence_event_ids:
            raise ValueError("an alert must reference at least one event")

    def to_dict(self) -> dict:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data