"""Phase 5 evaluation: compare the ML model with the rules on a held-out test set.

Test set:
- Normal activity from the period the model did NOT train on (the last 6 hours).
- Freshly generated attacks with different random users, timings and port counts
  from the ones used when the Phase 1 files were made. Each attack is labelled.

Each user-window is labelled attack (1) or normal (0). Metrics:
- precision: of windows flagged, how many were attacks
- recall: of attack windows, how many were flagged
- F1: balance of precision and recall
- false positive rate (FPR): share of normal windows that were flagged

Caveat: the attacks come from the same simulator design, so this measures how
well the designed patterns are detected, not how well real attacks are caught.

Usage (from the repo root, after training):
    python3 detection-engine/anomaly_model.py
    python3 detection-engine/evaluate_detection.py
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

import paths  # noqa: F401  (sets up sys.path)
from attack_simulator import brute_force_events, port_scan_events, unusual_login_events
from config import ATTACKER_IP, INTERNAL_IPS, USERS
from events import SecurityEvent
from feature_engineering import build_features, events_to_frame
from anomaly_model import MODEL_PATH, load, score_windows, split_history
from pipeline import run_rules
from validation import load_events

TEST_SEED = 2026
N_BRUTE, N_SCAN, N_UNUSUAL = 30, 20, 20
TEST_START = datetime(2026, 10, 1, 18, 0, tzinfo=timezone.utc)   # after the training period
TEST_END = datetime(2026, 10, 1, 23, 30, tzinfo=timezone.utc)
WINDOW = "5min"


def make_test_attacks(seed: int = TEST_SEED) -> list[SecurityEvent]:
    rng = random.Random(seed)
    span = (TEST_END - TEST_START).total_seconds()

    def random_time() -> datetime:
        return TEST_START + timedelta(seconds=rng.uniform(0, span))

    events: list[SecurityEvent] = []
    for _ in range(N_BRUTE):
        events += brute_force_events(
            user_id=rng.choice(USERS),
            attempts=rng.randint(5, 20),
            start=random_time(),
            interval_seconds=rng.randint(2, 15),
        )
    for _ in range(N_SCAN):
        events += port_scan_events(
            source_ip=ATTACKER_IP,
            target_ip=rng.choice(INTERNAL_IPS),
            ports=rng.sample(range(1, 1025), rng.randint(20, 100)),
            start=random_time(),
            interval_ms=rng.randint(50, 500),
        )
    for _ in range(N_UNUSUAL):
        events += unusual_login_events(
            user_id=rng.choice(USERS),
            start=random_time(),
        )
    return events


def rule_flagged_windows(events: list[SecurityEvent]) -> set[tuple]:
    """(user_id, window_start) for every window that supports at least one rule alert."""
    frame = events_to_frame(events)
    window_of = dict(zip(
        frame["event_id"],
        zip(frame["user_id"], frame["timestamp"].dt.floor(WINDOW)),
    ))
    flagged = set()
    for alert in run_rules(events):
        for event_id in alert.evidence_event_ids:
            flagged.add(window_of[event_id])
    return flagged


def metrics(y_true: list[int], y_pred: list[bool]) -> dict:
    pairs = list(zip(y_true, y_pred))
    tp = sum(1 for t, p in pairs if t and p)
    fp = sum(1 for t, p in pairs if not t and p)
    fn = sum(1 for t, p in pairs if t and not p)
    tn = sum(1 for t, p in pairs if not t and not p)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "precision": round(precision, 3), "recall": round(recall, 3),
        "f1": round(f1, 3), "false_positive_rate": round(fpr, 3),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def evaluate(normal_later: list[SecurityEvent], attacks: list[SecurityEvent], model) -> pd.DataFrame:
    test_events = normal_later + attacks
    ml = score_windows(test_events, model)
    rule_windows = rule_flagged_windows(test_events)
    ml["rule_flag"] = [
        (u, w) in rule_windows for u, w in zip(ml["entity_id"], ml["window_start"])
    ]
    return ml


def iforest_reference(history: list[SecurityEvent], test_events: list[SecurityEvent]) -> list[bool]:
    """Phase 5 v1 (Isolation Forest), kept only as a reference row to show the change."""
    from sklearn.ensemble import IsolationForest
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from anomaly_model import ML_FEATURES, training_table

    model = make_pipeline(StandardScaler(), IsolationForest(
        n_estimators=200, contamination=0.01, random_state=42))
    model.fit(training_table(history)[ML_FEATURES].astype(float))
    feats = build_features(events_to_frame(test_events), "user_id")
    return (model.predict(feats[ML_FEATURES].astype(float)) == -1).tolist()


def print_report(ml: pd.DataFrame, reference: list[bool] | None = None) -> None:
    y = ml["label"].tolist()
    results = {
        "ML (LOF, current)": metrics(y, ml["ml_flag"].tolist()),
        "Rules (Phase 2)": metrics(y, ml["rule_flag"].tolist()),
        "Either (ML or rules)": metrics(y, (ml["ml_flag"] | ml["rule_flag"]).tolist()),
    }
    if reference is not None:
        results["ML (Isolation Forest v1, reference)"] = metrics(y, reference)
    table = pd.DataFrame(results).T
    print("Overall, per user-window:")
    print(table[["precision", "recall", "f1", "false_positive_rate", "tp", "fp", "fn", "tn"]].to_string())

    print("\nRecall by attack type (share of attack windows flagged):")
    for name in ["brute_force", "port_scan", "unusual_login"]:
        subset = ml[ml["scenario"].str.contains(name)]
        if subset.empty:
            continue
        ml_recall = subset["ml_flag"].mean()
        rule_recall = subset["rule_flag"].mean()
        print(f"  {name:<14} windows={len(subset):<4} ML={ml_recall:.0%}  rules={rule_recall:.0%}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate ML vs rules on held-out data.")
    parser.add_argument("--out", type=Path, default=paths.REPO_ROOT / "data" / "processed" / "ml_vs_rules_eval.csv")
    args = parser.parse_args()

    if not MODEL_PATH.exists():
        raise SystemExit(f"No trained model at {MODEL_PATH}. Run: python3 detection-engine/anomaly_model.py")
    model = load()

    normal, _ = load_events(paths.RAW_DATA_DIR / "normal_events.json")
    _, normal_later = split_history(normal)
    attacks = make_test_attacks()

    ml = evaluate(normal_later, attacks, model)
    history, _ = split_history(normal)
    reference = iforest_reference(history, normal_later + attacks)
    print(f"Test set: {len(normal_later)} normal events, {len(attacks)} attack events "
          f"({N_BRUTE} brute-force, {N_SCAN} port-scan, {N_UNUSUAL} unusual-login bursts)\n")
    print_report(ml, reference)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    ml.to_csv(args.out, index=False)
    print(f"\nWrote per-window results to {args.out}")


if __name__ == "__main__":
    main()