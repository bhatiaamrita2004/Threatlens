"""Phase 6: combine rule, ML and baseline evidence into one threat score per user-window.

Score (0-100) = rule points + ML points + baseline points + corroboration points, capped at 100.

- rule points: the highest severity among the rule alerts that cover the window
  (LOW 15, MEDIUM 35, HIGH 60, CRITICAL 80)
- ML points: 10 if the Phase 5 model flags the window as unusual
- baseline points: 10 if the Phase 4 baseline flags the window
- corroboration: +10 if two or more different kinds of evidence agree

Bands: LOW 0-29, MEDIUM 30-59, HIGH 60-79, CRITICAL 80-100.

These weights are a judgement, not learned from data. They are written here so
they can be argued with and changed. Changing them changes every score, so
re-run the Phase 5 evaluation after any change.

Every score comes with an explanation that lists each source and its points,
so an analyst can see why a window scored what it did.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

import paths  # noqa: F401  (sets up sys.path)
from alert import SEVERITIES, Alert
from feature_engineering import WINDOW, events_to_frame
from events import SecurityEvent

RULE_POINTS = {"LOW": 15, "MEDIUM": 35, "HIGH": 60, "CRITICAL": 80}
ML_POINTS = 10
BASELINE_POINTS = 10
CORROBORATION_POINTS = 10
MAX_SCORE = 100
BANDS = [(80, "CRITICAL"), (60, "HIGH"), (30, "MEDIUM"), (0, "LOW")]


def band_for(score: int) -> str:
    for floor, name in BANDS:
        if score >= floor:
            return name
    return "LOW"


@dataclass
class Evidence:
    rules: list[str] = field(default_factory=list)   # rule names that fired in this window
    top_severity: str | None = None                  # highest severity among those rule alerts
    ml_flag: bool = False
    ml_score: float | None = None
    baseline_flag: bool = False
    baseline_reasons: str = ""


@dataclass
class ScoreResult:
    score: int
    band: str
    points: dict[str, int]
    explanation: list[str]


def score_evidence(ev: Evidence) -> ScoreResult:
    points: dict[str, int] = {}
    explanation: list[str] = []

    if ev.top_severity:
        points["rules"] = RULE_POINTS[ev.top_severity]
        explanation.append(
            f"rules fired: {', '.join(sorted(set(ev.rules)))} "
            f"(highest severity {ev.top_severity}, +{points['rules']})"
        )
    if ev.ml_flag:
        points["ml"] = ML_POINTS
        explanation.append(
            f"ML model flags the window as unusual (score {ev.ml_score:.2f}, +{ML_POINTS})"
        )
    if ev.baseline_flag:
        points["baseline"] = BASELINE_POINTS
        detail = f": {ev.baseline_reasons}" if ev.baseline_reasons else ""
        explanation.append(f"far from this user's usual behaviour{detail} (+{BASELINE_POINTS})")

    kinds = sum([bool(ev.top_severity), ev.ml_flag, ev.baseline_flag])
    if kinds >= 2:
        points["corroboration"] = CORROBORATION_POINTS
        explanation.append(
            f"{kinds} different kinds of evidence agree (+{CORROBORATION_POINTS})"
        )

    score = min(MAX_SCORE, sum(points.values()))
    return ScoreResult(score=score, band=band_for(score), points=points, explanation=explanation)


def _top_severity(severities: list[str]) -> str | None:
    return max(severities, key=SEVERITIES.index) if severities else None


def build_scores(
    events: list[SecurityEvent],
    alerts: list[Alert],
    ml: pd.DataFrame,
    base_scored: pd.DataFrame,
) -> pd.DataFrame:
    """One row per user-window that has any evidence, with score, band and explanation.

    ml: output of anomaly_model.score_windows (Phase 5)
    base_scored: output of baseline.score_windows (Phase 4)
    """
    frame = events_to_frame(events)
    window_of = dict(zip(
        frame["event_id"],
        zip(frame["user_id"], frame["timestamp"].dt.floor(WINDOW)),
    ))

    # Each rule alert can cover several windows (a burst may cross a 5-minute boundary).
    rule_hits: dict[tuple, list[Alert]] = {}
    for alert in alerts:
        for key in {window_of[eid] for eid in alert.evidence_event_ids}:
            rule_hits.setdefault(key, []).append(alert)

    cells: dict[tuple, dict] = {}

    def cell(key: tuple) -> dict:
        return cells.setdefault(key, {
            "ml_flag": False, "ml_score": None, "baseline_flag": False,
            "baseline_reasons": "", "scenario": None, "label": None,
        })

    for rec in ml.itertuples(index=False):
        cell((rec.entity_id, rec.window_start)).update(
            ml_flag=bool(rec.ml_flag), ml_score=float(rec.ml_score),
            scenario=rec.scenario, label=rec.label,
        )
    for rec in base_scored.itertuples(index=False):
        cell((rec.entity_id, rec.window_start)).update(
            baseline_flag=bool(rec.flagged), baseline_reasons=rec.reasons,
        )
    for key in rule_hits:
        cell(key)

    if not cells:
        return pd.DataFrame(columns=["entity_id", "window_start", "score", "band", "rules",
                                     "ml_score", "ml_flag", "baseline_flag", "scenario",
                                     "label", "explanation", "points"])

    rows = []
    for key, c in cells.items():
        hits = rule_hits.get(key, [])
        rules = sorted({h.rule_name for h in hits})
        result = score_evidence(Evidence(
            rules=rules,
            top_severity=_top_severity([h.severity for h in hits]),
            ml_flag=c["ml_flag"],
            ml_score=c["ml_score"],
            baseline_flag=c["baseline_flag"],
            baseline_reasons=c["baseline_reasons"],
        ))
        rows.append({
            "entity_id": key[0],
            "window_start": key[1],
            "score": result.score,
            "band": result.band,
            "rules": rules,
            "ml_score": c["ml_score"],
            "ml_flag": c["ml_flag"],
            "baseline_flag": c["baseline_flag"],
            "scenario": c["scenario"],
            "label": c["label"],
            "explanation": "; ".join(result.explanation),
            "points": result.points,
        })

    return (pd.DataFrame(rows)
            .sort_values(["score", "entity_id"], ascending=[False, True])
            .reset_index(drop=True))