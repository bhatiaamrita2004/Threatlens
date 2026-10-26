"""Phase 3 tests: feature values, documentation, reproducibility, and split safety.

Run from the repo root:
    python3 -m unittest discover -s detection-engine/tests -v
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # detection-engine/
import paths  # noqa: F401,E402
from events import SecurityEvent  # noqa: E402
from feature_engineering import (  # noqa: E402
    FEATURE_DEFINITIONS,
    KEY_COLUMNS,
    LABEL_COLUMNS,
    build_all,
    build_features,
    events_to_frame,
    split_by_entity,
)
from validation import load_events  # noqa: E402

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def ev(event_type, status, seconds=0, user="U105", ip="203.0.113.50",
       port=None, location="remote-vpn", scenario="normal", **meta):
    return SecurityEvent(
        user_id=user, source_ip=ip, event_type=event_type, status=status,
        timestamp=T0 + timedelta(seconds=seconds), location=location,
        destination_port=port, destination_ip="192.0.2.10" if port else None,
        protocol="TCP" if port else None,
        metadata={"synthetic": True, "scenario": scenario, **meta},
    )


def row(features, **where):
    mask = True
    for column, value in where.items():
        mask = mask & (features[column] == value)
    matches = features[mask]
    assert len(matches) == 1, f"expected one row for {where}, found {len(matches)}"
    return matches.iloc[0]


class FeatureValueTests(unittest.TestCase):
    def test_brute_force_window_counts_and_label(self):
        events = [ev("LOGIN_FAILED", "FAILURE", i * 5, scenario="brute_force") for i in range(12)]
        user_feats = build_features(events_to_frame(events), "user_id")
        r = row(user_feats, entity_id="U105")
        self.assertEqual(r["failed_login_count"], 12)
        self.assertEqual(r["event_count"], 12)
        self.assertEqual(r["label"], 1)
        self.assertEqual(r["scenario"], "brute_force")

    def test_failure_ratio(self):
        only_failures = [ev("LOGIN_FAILED", "FAILURE", 0)]
        mixed = [ev("LOGIN_FAILED", "FAILURE", 0), ev("LOGIN_SUCCESS", "SUCCESS", 10)]
        no_logins = [ev("CONNECTION_ATTEMPT", "SUCCESS", 0, port=443)]
        self.assertEqual(row(build_features(events_to_frame(only_failures), "user_id"),
                             entity_id="U105")["failure_ratio"], 1.0)
        self.assertEqual(row(build_features(events_to_frame(mixed), "user_id"),
                             entity_id="U105")["failure_ratio"], 0.5)
        self.assertEqual(row(build_features(events_to_frame(no_logins), "user_id"),
                             entity_id="U105")["failure_ratio"], 0.0)

    def test_unique_ports_counts_distinct_ports(self):
        events = [ev("CONNECTION_ATTEMPT", "FAILURE", i * 0.2, ip="203.0.113.50", port=20 + i,
                     user="U000", scenario="port_scan") for i in range(100)]
        ip_feats = build_features(events_to_frame(events), "source_ip")
        self.assertEqual(row(ip_feats, entity_id="203.0.113.50")["unique_ports"], 100)

    def test_null_ports_are_ignored(self):
        events = [ev("LOGIN_FAILED", "FAILURE", 0)]  # no destination port
        feats = build_features(events_to_frame(events), "user_id")
        self.assertEqual(row(feats, entity_id="U105")["unique_ports"], 0)

    def test_offhours_login_and_hour(self):
        night = SecurityEvent(
            user_id="U110", source_ip="203.0.113.50", event_type="LOGIN_SUCCESS",
            status="SUCCESS", timestamp=datetime(2026, 10, 1, 3, 17, tzinfo=timezone.utc),
            location="unknown-region",
        )
        r = row(build_features(events_to_frame([night]), "user_id"), entity_id="U110")
        self.assertEqual(r["offhours_login_count"], 1)
        self.assertEqual(r["avg_login_hour"], 3.0)

    def test_events_in_different_windows_make_separate_rows(self):
        events = [ev("LOGIN_FAILED", "FAILURE", 0), ev("LOGIN_FAILED", "FAILURE", 6 * 60)]
        feats = build_features(events_to_frame(events), "user_id")
        self.assertEqual(len(feats[feats["entity_id"] == "U105"]), 2)

    def test_restricted_access_is_zero_without_restricted_events(self):
        events = [ev("RESOURCE_ACCESS", "SUCCESS", 0)]
        feats = build_features(events_to_frame(events), "user_id")
        self.assertEqual(row(feats, entity_id="U105")["restricted_access_count"], 0)


class DocumentationAndSafetyTests(unittest.TestCase):
    def test_every_feature_column_is_documented(self):
        events = [ev("LOGIN_FAILED", "FAILURE", 0)]
        feats = build_features(events_to_frame(events), "user_id")
        feature_cols = set(feats.columns) - set(KEY_COLUMNS) - set(LABEL_COLUMNS)
        self.assertEqual(feature_cols, set(FEATURE_DEFINITIONS))

    def test_labels_are_not_features(self):
        for label_col in LABEL_COLUMNS:
            self.assertNotIn(label_col, FEATURE_DEFINITIONS)

    def test_split_keeps_each_entity_on_one_side(self):
        events = [ev("LOGIN_FAILED", "FAILURE", i * 400, user=f"U{100 + i}") for i in range(20)]
        feats, _ = build_all(events)
        train, test = split_by_entity(feats, test_fraction=0.3, seed=7)
        train_keys = set(zip(train["entity_type"], train["entity_id"]))
        test_keys = set(zip(test["entity_type"], test["entity_id"]))
        self.assertEqual(train_keys & test_keys, set())
        self.assertEqual(len(train) + len(test), len(feats))

    def test_split_is_deterministic(self):
        events = [ev("LOGIN_FAILED", "FAILURE", i * 400, user=f"U{100 + i}") for i in range(20)]
        feats, _ = build_all(events)
        first = split_by_entity(feats, seed=7)
        second = split_by_entity(feats, seed=7)
        self.assertTrue(first[0].equals(second[0]))
        self.assertTrue(first[1].equals(second[1]))


class DatasetTests(unittest.TestCase):
    def _normal_events(self):
        path = paths.RAW_DATA_DIR / "normal_events.json"
        if not path.exists():
            self.skipTest("normal_events.json not generated; run Phase 1 first")
        events, _problems = load_events(path)
        return events

    def test_reproducible_on_the_same_input(self):
        events = self._normal_events()
        first_user, first_ip = build_all(events)
        second_user, second_ip = build_all(events)
        self.assertTrue(first_user.equals(second_user))
        self.assertTrue(first_ip.equals(second_ip))

    def test_normal_data_has_no_attack_labels(self):
        user_feats, ip_feats = build_all(self._normal_events())
        self.assertEqual(int(user_feats["label"].sum()), 0)
        self.assertEqual(int(ip_feats["label"].sum()), 0)

    def test_normal_users_have_no_failure_bursts(self):
        user_feats, _ = build_all(self._normal_events())
        self.assertLess(user_feats["failed_login_count"].max(), 5)


if __name__ == "__main__":
    unittest.main()