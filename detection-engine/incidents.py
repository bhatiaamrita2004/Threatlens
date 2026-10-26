"""Phase 6: group scored windows into incidents.

Two scored windows belong to the same incident when they are at most GAP_MINUTES
apart and either the same user is involved in both, or both share a source IP.
Linking is transitive (A linked to B and B linked to C puts A, B and C together),
so a multi-step attack becomes one incident rather than many fragments.

Only windows at MEDIUM or above (score >= MIN_SCORE) can join an incident.

Limitations:
- A shared IP (a NAT gateway or VPN exit, say) can merge unrelated users.
- An attacker who changes IP and user at the same time will split into several incidents.
- Pairwise comparison is O(n^2); fine for lab-sized data, not for millions of windows.
"""

from __future__ import annotations

import pandas as pd

import paths  # noqa: F401  (sets up sys.path)
from events import SecurityEvent
from feature_engineering import WINDOW, events_to_frame

GAP_MINUTES = 15
MIN_SCORE = 30   # MEDIUM and above


def _find(parent: list[int], i: int) -> int:
    while parent[i] != i:
        parent[i] = parent[parent[i]]
        i = parent[i]
    return i


def group_incidents(scored: pd.DataFrame, events: list[SecurityEvent]) -> list[dict]:
    members = scored[scored["score"] >= MIN_SCORE].reset_index(drop=True)
    if members.empty:
        return []

    frame = events_to_frame(events)
    frame["window_start"] = frame["timestamp"].dt.floor(WINDOW)
    ips_in = {key: set(group["source_ip"]) for key, group in frame.groupby(["user_id", "window_start"])}

    records = list(members.itertuples(index=False))
    gap = pd.Timedelta(minutes=GAP_MINUTES)
    parent = list(range(len(records)))

    for i, a in enumerate(records):
        ips_a = ips_in.get((a.entity_id, a.window_start), set())
        for j in range(i + 1, len(records)):
            b = records[j]
            if abs(a.window_start - b.window_start) > gap:
                continue
            ips_b = ips_in.get((b.entity_id, b.window_start), set())
            if a.entity_id == b.entity_id or ips_a & ips_b:
                parent[_find(parent, i)] = _find(parent, j)

    groups: dict[int, list] = {}
    for i in range(len(records)):
        groups.setdefault(_find(parent, i), []).append(records[i])

    incidents = []
    for group in groups.values():
        ordered = sorted(group, key=lambda r: r.window_start)
        top = max(group, key=lambda r: r.score)
        ips: set[str] = set()
        for r in ordered:
            ips |= ips_in.get((r.entity_id, r.window_start), set())
        incidents.append({
            "users": sorted({r.entity_id for r in ordered}),
            "source_ips": sorted(ips),
            "first_window": ordered[0].window_start.isoformat(),
            "last_window": ordered[-1].window_start.isoformat(),
            "window_count": len(ordered),
            "max_score": int(top.score),
            "band": top.band,
            "rules": sorted({rule for r in ordered for rule in r.rules}),
            "top_explanation": top.explanation,
        })

    incidents.sort(key=lambda x: -x["max_score"])
    for n, incident in enumerate(incidents, start=1):
        incident["incident_id"] = f"INC-{n:03d}"
    return incidents