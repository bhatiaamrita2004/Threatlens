"""Phase 5 tests: the Isolation Forest trains, scores, saves and reloads, and the metrics are right.

Run from the repo root:
    python3 -m unittest discover -s detection-engine/tests -v
"""

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # detection-engine/
import paths  # noqa: F401,E402
from anomaly_model import (  # noqa: E402
    LIMITATIONS,
    ML_FEATURES,
    load,
    save,
    score_windows,
    split_history,
    train,
)
from evaluate_detection import metrics  # noqa: E402
from generator import generate_normal_events  # noqa: E402
from events import SecurityEvent  # noqa: E402
from validation import load_events  # noqa: E402

T0 = datetime(2026, 10, 1, 0, 0, tzinfo=timezone.utc)


def burst(user, count, start_minutes, event_type="LOGIN_FAILED", status="FAILURE"):
    return [
        SecurityEvent(
            user_id=user, source_ip="203.0.113.50", event_type=event_type, status=status,
            timestamp=T0 + timedelta(minutes=start_minutes, seconds=i * 3),
            location="remote-vpn", metadata={"synthetic": True, "scenario": "brute_force"},
        )
        for i in range(count)
    ]


class TrainingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Deterministic normal data built in code, so these tests do not need Phase 1 files.
        cls.history = generate_normal_events(1500, seed=7, window_hours=18)
        cls.model, cls.meta = train(cls.history)

    def test_metadata_lists_features_and_limitations(self):
        self.assertEqual(self.meta["features"], ML_FEATURES)
        self.assertEqual(self.meta["limitations"], LIMITATIONS)
        self.assertGreater(self.meta["training_windows"], 0)

    def test_training_is_reproducible(self):
        _, meta_again = train(self.history)
        self.assertEqual(meta_again["training_windows"], self.meta["training_windows"])
        a = score_windows(self.history[:200], self.model)["ml_score"]
        model_b, _ = train(self.history)
        b = score_windows(self.history[:200], model_b)["ml_score"]
        self.assertTrue(a.equals(b))

    def test_burst_of_failures_scores_higher_and_is_flagged(self):
        normal_scores = score_windows(self.history[:300], self.model)
        attack_scores = score_windows(burst("U105", 30, 0), self.model)
        row = attack_scores.iloc[0]
        self.assertTrue(bool(row["ml_flag"]))
        self.assertGreater(row["ml_score"], normal_scores["ml_score"].median())

    def test_save_and_load_gives_the_same_scores(self):
        with tempfile.TemporaryDirectory() as tmp:
            model_path = Path(tmp) / "m.joblib"
            meta_path = Path(tmp) / "m.json"
            save(self.model, self.meta, model_path, meta_path)
            reloaded = load(model_path)
            saved_meta = json.loads(meta_path.read_text(encoding="utf-8"))
            self.assertEqual(saved_meta["model_version"], self.meta["model_version"])
            before = score_windows(self.history[:100], self.model)["ml_score"]
            after = score_windows(self.history[:100], reloaded)["ml_score"]
            self.assertTrue(before.equals(after))

    def test_split_history_uses_the_first_hours_only(self):
        history, later = split_history(self.history, hours=6)
        cut = min(e.timestamp for e in self.history) + timedelta(hours=6)
        self.assertTrue(all(e.timestamp < cut for e in history))
        self.assertTrue(all(e.timestamp >= cut for e in later))
        self.assertEqual(len(history) + len(later), len(self.history))


class MetricTests(unittest.TestCase):
    def test_precision_recall_f1_and_fpr(self):
        # truth:      attack, attack, normal, normal
        # prediction: flagged, normal, flagged, normal
        m = metrics([1, 1, 0, 0], [True, False, True, False])
        self.assertEqual(m["tp"], 1)
        self.assertEqual(m["fp"], 1)
        self.assertEqual(m["fn"], 1)
        self.assertEqual(m["tn"], 1)
        self.assertEqual(m["precision"], 0.5)
        self.assertEqual(m["recall"], 0.5)
        self.assertEqual(m["f1"], 0.5)
        self.assertEqual(m["false_positive_rate"], 0.5)

    def test_no_predicted_positives_gives_zero_precision_without_error(self):
        m = metrics([1, 0], [False, False])
        self.assertEqual(m["precision"], 0.0)
        self.assertEqual(m["recall"], 0.0)


class DatasetTests(unittest.TestCase):
    def test_model_flags_the_brute_force_scenario_file(self):
        # Regression test for the v1 Isolation Forest, which could not flag bursts
        # larger than any training window (the normal training data never exceeded 2 events).
        path = paths.RAW_DATA_DIR / "scenario_brute_force.json"
        normal_path = paths.RAW_DATA_DIR / "normal_events.json"
        if not (path.exists() and normal_path.exists()):
            self.skipTest("Phase 1 data not generated")
        normal, _ = load_events(normal_path)
        history, _ = split_history(normal)
        model, _ = train(history)
        events, _ = load_events(path)
        scored = score_windows(events, model)
        self.assertTrue(scored["ml_flag"].any())


if __name__ == "__main__":
    unittest.main()