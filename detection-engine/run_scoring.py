"""Phase 6 runner: score user-windows and group them into incidents.

Uses the Phase 4 baseline and the Phase 5 model, so run anomaly_model.py first.

Usage (from the repo root):
    python3 detection-engine/run_scoring.py                          # normal later period + scenario files
    python3 detection-engine/run_scoring.py data/raw/scenario_port_scan.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

import paths  # noqa: F401  (sets up sys.path)
import anomaly_model
import baseline as baseline_model
from incidents import group_incidents
from pipeline import run_rules
from scoring import build_scores
from validation import load_events

SCENARIO_FILES = [
    "scenario_brute_force.json",
    "scenario_port_scan.json",
    "scenario_unusual_login.json",
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Score windows and group them into incidents.")
    parser.add_argument("files", nargs="*", type=Path, help="event files to score")
    parser.add_argument("--out-dir", type=Path, default=paths.REPO_ROOT / "data" / "processed")
    args = parser.parse_args()

    normal, _ = load_events(paths.RAW_DATA_DIR / "normal_events.json")
    history, later = anomaly_model.split_history(normal)
    baseline = baseline_model.fit_baseline(history)
    model = anomaly_model.load()

    if args.files:
        events = []
        for path in args.files:
            loaded, problems = load_events(path)
            for p in problems:
                print(f"  skipped: {p}")
            events += loaded
    else:
        events = list(later)
        for name in SCENARIO_FILES:
            loaded, _ = load_events(paths.RAW_DATA_DIR / name)
            events += loaded

    alerts = run_rules(events)
    ml = anomaly_model.score_windows(events, model)
    base_scored = baseline_model.score_windows(events, baseline)
    scored = build_scores(events, alerts, ml, base_scored)
    incidents = group_incidents(scored, events)

    print(f"Scored {len(scored)} user-windows from {len(events)} events.")
    print("Windows by band:")
    for band in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"  {band:<9} {int((scored['band'] == band).sum())}")

    print(f"\nIncidents: {len(incidents)}")
    for inc in incidents[:10]:
        print(f"  {inc['incident_id']} [{inc['band']} {inc['max_score']}] "
              f"users={inc['users']} ips={inc['source_ips']} "
              f"windows={inc['window_count']} rules={inc['rules']}")
        print(f"      why: {inc['top_explanation']}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    scores_path = args.out_dir / "threat_scores.csv"
    incidents_path = args.out_dir / "incidents.json"
    scored.assign(points=scored["points"].astype(str)).to_csv(scores_path, index=False)
    incidents_path.write_text(json.dumps(incidents, indent=2), encoding="utf-8")
    print(f"\nWrote window scores to {scores_path}")
    print(f"Wrote incidents to {incidents_path}")


if __name__ == "__main__":
    main()