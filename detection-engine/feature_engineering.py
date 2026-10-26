"""Phase 3: turn raw events into per-entity time-window features.

One row = one entity (a user or a source IP) in one 5-minute UTC window.

Features use only fields a real analyst would see in logs. The synthetic
`scenario` label is kept only for evaluation. It is never a feature, because
using it would leak the answer into the model.

Usage (from the repo root):
    python3 detection-engine/feature_engineering.py
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

import numpy as np
import pandas as pd

import paths  # noqa: F401  (sets up sys.path)
from events import SecurityEvent
from validation import load_events

WINDOW = "5min"
OFF_HOURS_UTC = [0, 1, 2, 3, 4, 5]   # 00:00-05:59 UTC
SEED = 42

KEY_COLUMNS = ["entity_type", "entity_id", "window_start"]
LABEL_COLUMNS = ["scenario", "label"]

FEATURE_DEFINITIONS = {
    "event_count": "All events for this entity in the window.",
    "failed_login_count": "LOGIN_FAILED events in the window.",
    "login_success_count": "LOGIN_SUCCESS events in the window.",
    "failure_ratio": (
        "failed_login_count / (failed_login_count + login_success_count). "
        "0.0 when there are no login events."
    ),
    "offhours_login_count": "Login events (success or failure) between 00:00 and 05:59 UTC.",
    "avg_login_hour": (
        "Mean UTC hour of the login events in the window. Empty when there are no logins. "
        "A plain mean does not handle midnight wrap-around, so treat it as a rough signal."
    ),
    "connection_count": "CONNECTION_ATTEMPT events in the window.",
    "unique_ports": "Distinct destination_port values in the window. Null ports are ignored.",
    "unique_source_ips": (
        "Distinct source_ip values in the window. For user rows, this counts the addresses "
        "the user logged in from."
    ),
    "unique_locations": "Distinct location labels in the window.",
    "request_count": "API_REQUEST events in the window.",
    "privilege_change_count": "PRIVILEGE_CHANGE events in the window.",
    "restricted_access_count": (
        "RESOURCE_ACCESS events with metadata.restricted = true. The current synthetic data "
        "has none, so this is 0 until such events are generated."
    ),
}


def events_to_frame(events: list[SecurityEvent]) -> pd.DataFrame:
    """Flatten events into a sorted DataFrame with one row per event."""
    columns = [
        "event_id", "timestamp", "user_id", "source_ip", "event_type",
        "location", "destination_port", "scenario", "restricted",
    ]
    rows = [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp,
            "user_id": e.user_id,
            "source_ip": e.source_ip,
            "event_type": e.event_type,
            "location": e.location,
            "destination_port": e.destination_port,
            "scenario": e.metadata.get("scenario", "normal"),
            "restricted": bool(e.metadata.get("restricted", False)),
        }
        for e in events
    ]
    df = pd.DataFrame(rows, columns=columns)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df.sort_values(["timestamp", "event_id"]).reset_index(drop=True)


def build_features(df: pd.DataFrame, entity: str, window: str = WINDOW) -> pd.DataFrame:
    """Build one feature row per (entity, window). `entity` is 'user_id' or 'source_ip'."""
    et = df["event_type"]
    is_login = et.isin(["LOGIN_SUCCESS", "LOGIN_FAILED"])
    hour = df["timestamp"].dt.hour

    work = pd.DataFrame({
        "entity_id": df[entity],
        "window_start": df["timestamp"].dt.floor(window),
        "is_failed": (et == "LOGIN_FAILED").astype(int),
        "is_success": (et == "LOGIN_SUCCESS").astype(int),
        "is_offhours": (is_login & hour.isin(OFF_HOURS_UTC)).astype(int),
        "login_hour": hour.where(is_login),
        "is_connection": (et == "CONNECTION_ATTEMPT").astype(int),
        "is_request": (et == "API_REQUEST").astype(int),
        "is_privilege": (et == "PRIVILEGE_CHANGE").astype(int),
        "is_restricted": ((et == "RESOURCE_ACCESS") & df["restricted"]).astype(int),
        "destination_port": df["destination_port"],
        "source_ip": df["source_ip"],
        "location": df["location"],
        "scenario": df["scenario"],
        "is_attack": (df["scenario"] != "normal").astype(int),
    })

    feats = work.groupby(["entity_id", "window_start"], sort=True).agg(
        event_count=("is_failed", "size"),
        failed_login_count=("is_failed", "sum"),
        login_success_count=("is_success", "sum"),
        offhours_login_count=("is_offhours", "sum"),
        avg_login_hour=("login_hour", "mean"),
        connection_count=("is_connection", "sum"),
        unique_ports=("destination_port", "nunique"),
        unique_source_ips=("source_ip", "nunique"),
        unique_locations=("location", "nunique"),
        request_count=("is_request", "sum"),
        privilege_change_count=("is_privilege", "sum"),
        restricted_access_count=("is_restricted", "sum"),
        scenario=("scenario", lambda s: "|".join(sorted(set(s)))),
        label=("is_attack", "max"),
    ).reset_index()

    logins = feats["failed_login_count"] + feats["login_success_count"]
    feats["failure_ratio"] = (feats["failed_login_count"] / logins.replace(0, np.nan)).fillna(0.0)
    feats["label"] = feats["label"].astype(int)
    feats.insert(0, "entity_type", entity)

    return feats[KEY_COLUMNS + list(FEATURE_DEFINITIONS) + ["scenario", "label"]]


def build_all(events: list[SecurityEvent]) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (user_window_features, ip_window_features)."""
    df = events_to_frame(events)
    return build_features(df, "user_id"), build_features(df, "source_ip")


def split_by_entity(
    features: pd.DataFrame, test_fraction: float = 0.3, seed: int = SEED
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split so each entity's windows are all in train or all in test.

    Splitting by window would leak one user's behaviour into both sets.
    The split is deterministic for a given seed.
    """
    keys = sorted(set(zip(features["entity_type"], features["entity_id"])))
    random.Random(seed).shuffle(keys)
    n_test = max(1, round(len(keys) * test_fraction))
    test_keys = set(keys[:n_test])

    in_test = pd.Series(
        [key in test_keys for key in zip(features["entity_type"], features["entity_id"])],
        index=features.index,
    )
    train = features[~in_test].reset_index(drop=True)
    test = features[in_test].reset_index(drop=True)
    return train, test


def load_all_events(folder: Path) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    for path in sorted(folder.glob("*.json")):
        loaded, problems = load_events(path)
        for problem in problems:
            print(f"  skipped: {problem}")
        events.extend(loaded)
    return events


def write_definitions(path: Path) -> None:
    lines = [
        "# Feature definitions",
        "",
        "Generated by `detection-engine/feature_engineering.py`.",
        "",
        "One row = one entity (a user, or a source IP) in one 5-minute UTC window.",
        "",
        "| Column | Meaning |",
        "|---|---|",
    ]
    lines += [f"| `{name}` | {text} |" for name, text in FEATURE_DEFINITIONS.items()]
    lines += [
        "",
        "Key columns: `entity_type`, `entity_id`, `window_start`.",
        "",
        "Label columns (evaluation only, never features): `scenario` lists the synthetic "
        "scenario labels in the window, and `label` is 1 if any event in it is synthetic "
        "attack data.",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build per-entity window features.")
    parser.add_argument("--out-dir", type=Path, default=paths.REPO_ROOT / "data" / "processed")
    parser.add_argument("--docs", type=Path, default=paths.REPO_ROOT / "docs" / "feature-definitions.md")
    args = parser.parse_args()

    events = load_all_events(paths.RAW_DATA_DIR)
    user_feats, ip_feats = build_all(events)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    user_feats.to_csv(args.out_dir / "user_window_features.csv", index=False)
    ip_feats.to_csv(args.out_dir / "ip_window_features.csv", index=False)
    write_definitions(args.docs)

    print(f"Read {len(events)} events from {paths.RAW_DATA_DIR}")
    for name, feats in (("user", user_feats), ("source IP", ip_feats)):
        print(f"{name} windows: {len(feats)} rows, {int(feats['label'].sum())} labelled attack windows")
    print(f"Wrote features to {args.out_dir}")
    print(f"Wrote column definitions to {args.docs}")


if __name__ == "__main__":
    main()