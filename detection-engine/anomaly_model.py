"""Phase 5: machine-learning anomaly detection with Local Outlier Factor (LOF).

Idea: learn what normal activity looks like from clean normal data, then score
each new window by how isolated it is from its nearest normal neighbours.
A window whose local density is much lower than its neighbours' gets a high score.

Why LOF instead of Isolation Forest (v1):
The normal training windows never hold more than 2 events. An Isolation Forest
can only split inside the range it saw, so every larger burst (12, 30, 168 events)
was scored like the most unusual normal window and was almost never flagged.
A distance-based model keeps growing with distance, so a burst far outside the
normal range gets a clearly higher score. On validation data (a separate normal
day and separate attack seeds), v1 reached 15% recall; LOF with n_neighbors=5
reached about 77% recall at 86% precision and under 1% false positives.
Duplicate training rows are removed first, because they make LOF unstable.

What it does NOT do: it does not know what an attack is. "Unusual" is not the
same as "malicious". The model only sees the numbers in the feature table.

Training uses only the normal history, with no attack labels. Scoring uses the
same feature columns as Phase 3.

Security note: the saved model is a pickled file (joblib). Only load model
files that you created yourself, because loading a pickle can run code.

Usage (from the repo root):
    python3 detection-engine/anomaly_model.py                       # train and save
    python3 detection-engine/anomaly_model.py --score data/raw/scenario_port_scan.json
"""

from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

import paths  # noqa: F401  (sets up sys.path)
from events import SecurityEvent
from feature_engineering import build_features, events_to_frame
from validation import load_events

MODEL_VERSION = "lof-v2"
MODEL_DIR = paths.REPO_ROOT / "ml-service" / "models"
MODEL_PATH = MODEL_DIR / f"{MODEL_VERSION}.joblib"
META_PATH = MODEL_DIR / f"{MODEL_VERSION}.json"

SEED = 42
N_NEIGHBORS = 5             # chosen on validation data (F1 flat for k=2-5), not on the test set
CONTAMINATION = 0.01        # assumed share of unusual windows in the training data
HISTORY_HOURS = 18          # the first part of the normal data is used for training

# Columns from Phase 3 that the model uses. Left out on purpose:
# - avg_login_hour: often empty (NaN) and needs special handling
# - restricted_access_count: always 0 in the current data, so it carries no information
ML_FEATURES = [
    "event_count",
    "failed_login_count",
    "login_success_count",
    "failure_ratio",
    "offhours_login_count",
    "connection_count",
    "unique_ports",
    "unique_source_ips",
    "unique_locations",
    "request_count",
    "privilege_change_count",
]

LIMITATIONS = [
    "Trained on one synthetic day of normal data; it has not seen real enterprise traffic.",
    "Scores show how unusual a window is, not whether it is malicious.",
    "The contamination value is an assumption that sets the cut-off; it is not learned from attacks.",
    "Normal training windows hold only a handful of distinct patterns (see distinct_training_patterns), so density estimates are rough.",
    "n_neighbors was picked on validation data, where F1 was flat for k = 2 to 5.",
    "Unusual logins (new hour or location) are invisible to count features; the rules and baseline cover them.",
    "Evaluation uses synthetic attacks from the same simulator design, so it measures the designed patterns only.",
]


def split_history(normal: list[SecurityEvent], hours: int = HISTORY_HOURS):
    """Return (history_for_training, later_events_for_testing)."""
    cut = min(e.timestamp for e in normal) + timedelta(hours=hours)
    return [e for e in normal if e.timestamp < cut], [e for e in normal if e.timestamp >= cut]


def build_model(n_neighbors: int = N_NEIGHBORS) -> Pipeline:
    return Pipeline([
        ("log", FunctionTransformer(np.log1p)),   # compress large counts so one burst does not dominate
        ("scale", StandardScaler()),
        ("lof", LocalOutlierFactor(
            n_neighbors=n_neighbors,
            novelty=True,                          # lets us score windows the model has not seen
            contamination=CONTAMINATION,
        )),
    ])


def training_table(events: list[SecurityEvent]) -> pd.DataFrame:
    """User-windows that contain at least one event. Labels are not used."""
    feats = build_features(events_to_frame(events), "user_id")
    return feats[feats["event_count"] > 0].reset_index(drop=True)


def train(history: list[SecurityEvent]) -> tuple[Pipeline, dict]:
    table = training_table(history)
    if table.empty:
        raise ValueError("no active windows in the training history")

    # Duplicate rows make LOF's density estimate divide by near-zero distances,
    # which gives huge, meaningless scores. Keep each distinct pattern once.
    patterns = table[ML_FEATURES].astype(float).drop_duplicates().reset_index(drop=True)
    k = min(N_NEIGHBORS, len(patterns) - 1)     # LOF needs fewer neighbours than samples

    model = build_model(n_neighbors=k)
    model.fit(patterns)

    meta = {
        "model_version": MODEL_VERSION,
        "algorithm": "LocalOutlierFactor (novelty mode), inside a log1p + StandardScaler pipeline",
        "features": ML_FEATURES,
        "n_neighbors": k,
        "contamination": CONTAMINATION,
        "training_windows": int(len(table)),
        "distinct_training_patterns": int(len(patterns)),
        "training_data": f"normal_events.json, first {HISTORY_HOURS} hours, no attack labels",
        "sklearn_version": sklearn.__version__,
        "limitations": LIMITATIONS,
    }
    return model, meta


def save(model: Pipeline, meta: dict,
         model_path: Path = MODEL_PATH, meta_path: Path = META_PATH) -> None:
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")


def load(model_path: Path = MODEL_PATH) -> Pipeline:
    return joblib.load(model_path)


def score_windows(events: list[SecurityEvent], model: Pipeline) -> pd.DataFrame:
    """One row per user-window: ml_score (higher = more unusual) and ml_flag."""
    feats = build_features(events_to_frame(events), "user_id")
    X = feats[ML_FEATURES].astype(float)
    out = feats[["entity_type", "entity_id", "window_start", "scenario", "label"]].copy()
    out["ml_score"] = (-model.score_samples(X)).round(4)   # score_samples: higher = more normal
    out["ml_flag"] = model.predict(X) == -1                 # -1 means anomaly
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Train or run the anomaly model (LOF).")
    parser.add_argument("--score", type=Path, help="score one event file with the saved model")
    args = parser.parse_args()

    if args.score:
        model = load()
        events, problems = load_events(args.score)
        for p in problems:
            print(f"  skipped: {p}")
        result = score_windows(events, model)
        flagged = result[result["ml_flag"]].sort_values("ml_score", ascending=False)
        print(f"{args.score.name}: {len(result)} windows, {len(flagged)} flagged")
        print(flagged[["entity_id", "window_start", "ml_score"]].head(10).to_string(index=False))
        return

    normal, problems = load_events(paths.RAW_DATA_DIR / "normal_events.json")
    for p in problems:
        print(f"  skipped: {p}")
    history, _ = split_history(normal)
    model, meta = train(history)
    save(model, meta)
    print(f"Trained {MODEL_VERSION} on {meta['training_windows']} active windows.")
    print(f"Saved model to {MODEL_PATH}")
    print(f"Saved metadata to {META_PATH}")


if __name__ == "__main__":
    main()