"""Phase 4: per-user behavioural baselines.

For each user, learn what "usual" looks like from a history period:
typical activity per 5-minute window, usual source IPs and locations, and
usual login hours. Then compare new windows against that baseline.

A deviation is a signal to investigate, not proof of an attack.

Known limitations:
- The baseline comes from one synthetic day, so it is rough.
- Silent windows count as zero. Without this, a user who logs in once a day
  would look as if they always log in.
- Login-hour novelty is weak with little history, because most hours look usual.
- Users with no history (for example the port-scan placeholder U000) are
  reported as "no history", not as normal.

Usage (from the repo root):
    python3 detection-engine/baseline.py
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

import paths  # noqa: F401  (sets up sys.path)
from events import SecurityEvent
from feature_engineering import build_features, events_to_frame
from validation import load_events

WINDOW = "5min"
HISTORY_HOURS = 18           # first part of the normal data is used to learn
Z_THRESHOLD = 3.0            # how far above usual a value must be to flag
MIN_STD = 1.0                # floor for std, so tiny histories do not explode z-scores
LOGIN_TYPES = ["LOGIN_SUCCESS", "LOGIN_FAILED"]

BASELINE_FEATURES = [
    "event_count",
    "failed_login_count",
    "offhours_login_count",
    "connection_count",
    "unique_ports",
    "unique_source_ips",
    "unique_locations",
    "request_count",
]
NOVELTY_COLUMNS = ["new_ip_events", "new_location_events", "new_hour_logins"]


@dataclass
class Baseline:
    stats: pd.DataFrame                  # index entity_id; <feature>_mean, <feature>_std
    known_ips: dict[str, set[str]]
    known_locations: dict[str, set[str]]
    usual_login_hours: dict[str, set[int]]
    history_start: pd.Timestamp
    history_end: pd.Timestamp

    @property
    def users(self) -> set[str]:
        return set(self.stats.index)


def _fill_silent_windows(feats: pd.DataFrame, users: list[str],
                         start: pd.Timestamp, end: pd.Timestamp) -> pd.DataFrame:
    """One row per user per 5-minute window across the history, zeros where nothing happened."""
    windows = pd.date_range(start, end, freq=WINDOW)
    index = pd.MultiIndex.from_product([users, windows], names=["entity_id", "window_start"])
    wide = feats.set_index(["entity_id", "window_start"])[BASELINE_FEATURES]
    return wide.reindex(index, fill_value=0).reset_index()


def fit_baseline(history: list[SecurityEvent]) -> Baseline:
    """Learn each user's usual behaviour from the history events."""
    if not history:
        raise ValueError("history is empty; cannot learn a baseline")

    df = events_to_frame(history)
    start = df["timestamp"].min().floor(WINDOW)
    end = df["timestamp"].max().floor(WINDOW)

    feats = build_features(df, "user_id")
    grid = _fill_silent_windows(feats, sorted(df["user_id"].unique()), start, end)

    stats = {}
    for f in BASELINE_FEATURES:
        stats[f"{f}_mean"] = grid.groupby("entity_id")[f].mean()
        stats[f"{f}_std"] = grid.groupby("entity_id")[f].std(ddof=0)

    logins = df[df["event_type"].isin(LOGIN_TYPES)]
    return Baseline(
        stats=pd.DataFrame(stats),
        known_ips={u: set(g) for u, g in df.groupby("user_id")["source_ip"]},
        known_locations={u: set(g) for u, g in df.groupby("user_id")["location"]},
        usual_login_hours={
            u: set(g.dt.hour) for u, g in logins.groupby("user_id")["timestamp"]
        },
        history_start=start,
        history_end=end,
    )


def _novelty(df: pd.DataFrame, baseline: Baseline) -> pd.DataFrame:
    """Count events per user-window that use an IP, location or login hour not seen before."""
    known_ip = {(u, ip) for u, ips in baseline.known_ips.items() for ip in ips}
    known_loc = {(u, loc) for u, locs in baseline.known_locations.items() for loc in locs}
    known_hour = {(u, h) for u, hs in baseline.usual_login_hours.items() for h in hs}

    is_login = df["event_type"].isin(LOGIN_TYPES).tolist()
    hours = df["timestamp"].dt.hour.tolist()
    users = df["user_id"].tolist()

    flags = pd.DataFrame({
        "entity_id": users,
        "window_start": df["timestamp"].dt.floor(WINDOW).reset_index(drop=True),
        "new_ip": [(u, ip) not in known_ip for u, ip in zip(users, df["source_ip"])],
        "new_location": [(u, loc) not in known_loc for u, loc in zip(users, df["location"])],
        "new_hour": [login and (u, h) not in known_hour
                     for login, u, h in zip(is_login, users, hours)],
    })
    return flags.groupby(["entity_id", "window_start"], as_index=False).agg(
        new_ip_events=("new_ip", "sum"),
        new_location_events=("new_location", "sum"),
        new_hour_logins=("new_hour", "sum"),
    )


def _reasons(row: pd.Series) -> list[str]:
    reasons = []
    if row["entity_id"] not in row["_users"]:
        reasons.append("no history for this user (usual values assumed 0)")
    for f in BASELINE_FEATURES:
        if row[f"{f}_z"] >= Z_THRESHOLD:
            reasons.append(
                f"{f} = {row[f]} (usual {row[f + '_usual']:.2f}, z = {row[f + '_z']:.1f})"
            )
    if row["new_ip_events"]:
        reasons.append(f"{row['new_ip_events']} event(s) from an IP this user has not used before")
    if row["new_location_events"]:
        reasons.append(f"{row['new_location_events']} event(s) from a location this user has not used before")
    if row["new_hour_logins"]:
        reasons.append(f"{row['new_hour_logins']} login(s) at an hour this user does not usually log in")
    return reasons


def score_windows(events: list[SecurityEvent], baseline: Baseline) -> pd.DataFrame:
    """Compare each user-window in `events` with the baseline."""
    df = events_to_frame(events)
    feats = build_features(df, "user_id")
    scored = feats.merge(_novelty(df, baseline), on=["entity_id", "window_start"], how="left")
    scored[NOVELTY_COLUMNS] = scored[NOVELTY_COLUMNS].fillna(0).astype(int)

    for f in BASELINE_FEATURES:
        usual = scored["entity_id"].map(baseline.stats[f"{f}_mean"]).fillna(0.0)
        std = scored["entity_id"].map(baseline.stats[f"{f}_std"]).fillna(0.0)
        scored[f"{f}_usual"] = usual.round(3)
        scored[f"{f}_z"] = ((scored[f] - usual) / np.maximum(std, MIN_STD)).round(2)

    scored["has_baseline"] = scored["entity_id"].isin(baseline.users)
    scored["_users"] = [baseline.users] * len(scored)
    scored["reasons"] = scored.apply(lambda r: "; ".join(_reasons(r)), axis=1)
    scored = scored.drop(columns="_users")

    # A window is flagged if a count is well above usual, or if it has BOTH an
    # unfamiliar IP and an unfamiliar location. A new IP alone is not enough:
    # in the synthetic data every event picks a random IP, so a new IP on its
    # own would flag almost every window. It is still listed in the reasons.
    z_flag = np.column_stack([scored[f"{f}_z"] >= Z_THRESHOLD for f in BASELINE_FEATURES]).any(axis=1)
    new_place_and_ip = ((scored["new_ip_events"] > 0) & (scored["new_location_events"] > 0)).to_numpy()
    scored["flagged"] = z_flag | new_place_and_ip
    return scored


def summarise(scored: pd.DataFrame) -> pd.DataFrame:
    """Flagged windows per scenario label (scenario is evaluation-only, not a feature)."""
    return scored.groupby("scenario").agg(
        windows=("flagged", "size"),
        flagged=("flagged", "sum"),
    ).reset_index()


def main() -> None:
    parser = argparse.ArgumentParser(description="Score windows against per-user baselines.")
    parser.add_argument("--out", type=Path, default=paths.REPO_ROOT / "data" / "processed" / "baseline_scores.csv")
    args = parser.parse_args()

    normal, problems = load_events(paths.RAW_DATA_DIR / "normal_events.json")
    if problems:
        print("normal file problems:", problems[:3])
    cut = min(e.timestamp for e in normal) + pd.Timedelta(hours=HISTORY_HOURS)
    history = [e for e in normal if e.timestamp < cut]
    later_normal = [e for e in normal if e.timestamp >= cut]

    baseline = fit_baseline(history)
    print(f"Baseline learned from {len(history)} events, {len(baseline.users)} users "
          f"({baseline.history_start} to {baseline.history_end})")

    outputs = []
    normal_scored = score_windows(later_normal, baseline)
    normal_scored["source"] = "normal_later_period"
    outputs.append(normal_scored)

    for name in ["scenario_brute_force.json", "scenario_port_scan.json", "scenario_unusual_login.json"]:
        events, _ = load_events(paths.RAW_DATA_DIR / name)
        scored = score_windows(events, baseline)
        scored["source"] = name
        outputs.append(scored)

    all_scored = pd.concat(outputs, ignore_index=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    all_scored.to_csv(args.out, index=False)

    print("\nFlagged windows by source:")
    for source, group in all_scored.groupby("source"):
        print(f"  {source}: {int(group['flagged'].sum())} of {len(group)} windows flagged")
        for _, row in group[group["flagged"]].head(3).iterrows():
            print(f"    {row['entity_id']} @ {row['window_start']}: {row['reasons']}")
    print(f"\nWrote scores to {args.out}")


if __name__ == "__main__":
    main()