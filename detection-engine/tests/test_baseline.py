"""Phase 4 tests: baselines learn usual behaviour and flag clear departures from it.

Run from the repo root:
    python3 -m unittest discover -s detection-engine/tests -v
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # detection-engine/
import paths  # noqa: F401,E402
from baseline import fit_baseline, score_windows  # noqa: E402
from events import SecurityEvent  # noqa: E402
from validation import load_events  # noqa: E402

T0 = datetime(2026, 10, 1, 0, 0, tzinfo=timezone.utc)


def login(hours, minutes=0, user="U200", ip="198.51.100.1", location="site-A",
          event_type="LOGIN_SUCCESS", status="SUCCESS", scenario="normal"):
    return SecurityEvent(
        user_id=user, source_ip=ip, event_type=event_type, status=status,
        timestamp=T0 + timedelta(hours=hours, minutes=minutes), location=location,
        metadata={"synthetic": True, "scenario": scenario},
    )


def usual_history():
    """U200 logs in once an hour for 10 hours, always from the same IP and location."""
    return [login(h) for h in range(10)]


class BaselineLearningTests(unittest.TestCase):
    def test_silent_windows_count_as_zero(self):
        baseline = fit_baseline(usual_history())
        # 10 hours of 5-minute windows = 109 windows; 10 of them contain an event.
        expected_mean = 10 / 109
        self.assertAlmostEqual(baseline.stats.loc["U200", "event_count_mean"], expected_mean, places=4)

    def test_usual_ips_locations_and_hours_are_recorded(self):
        baseline = fit_baseline(usual_history())
        self.assertEqual(baseline.known_ips["U200"], {"198.51.100.1"})
        self.assertEqual(baseline.known_locations["U200"], {"site-A"})
        self.assertEqual(baseline.usual_login_hours["U200"], set(range(10)))

    def test_empty_history_is_rejected(self):
        with self.assertRaises(ValueError):
            fit_baseline([])


class DeviationTests(unittest.TestCase):
    def setUp(self):
        self.baseline = fit_baseline(usual_history())

    def test_usual_login_is_not_flagged(self):
        scored = score_windows([login(3, minutes=2)], self.baseline)
        self.assertFalse(bool(scored.iloc[0]["flagged"]))
        self.assertEqual(scored.iloc[0]["reasons"], "")

    def test_burst_of_failures_from_new_ip_is_flagged_with_reasons(self):
        attack = [
            login(5, minutes=0, user="U200", ip="203.0.113.50", location="remote-vpn",
                  event_type="LOGIN_FAILED", status="FAILURE", scenario="brute_force")
            for _ in range(12)
        ]
        for i, event in enumerate(attack):
            event.timestamp = event.timestamp + timedelta(seconds=5 * i)
        scored = score_windows(attack, self.baseline)
        row = scored.iloc[0]
        self.assertTrue(bool(row["flagged"]))
        self.assertGreaterEqual(row["failed_login_count_z"], 3.0)
        self.assertIn("failed_login_count", row["reasons"])
        self.assertIn("IP this user has not used", row["reasons"])
        self.assertIn("location this user has not used", row["reasons"])

    def test_unknown_user_is_reported_as_no_history(self):
        scored = score_windows([login(3, user="U999")], self.baseline)
        row = scored.iloc[0]
        self.assertFalse(bool(row["has_baseline"]))
        self.assertIn("no history", row["reasons"])

    def test_scoring_is_deterministic(self):
        events = [login(5, minutes=i, ip="203.0.113.9") for i in range(4)]
        first = score_windows(events, self.baseline)
        second = score_windows(events, self.baseline)
        self.assertTrue(first.equals(second))


class DatasetTests(unittest.TestCase):
    def _load(self, name):
        path = paths.RAW_DATA_DIR / name
        if not path.exists():
            self.skipTest(f"{name} not generated; run Phase 1 first")
        events, _ = load_events(path)
        return events

    def test_brute_force_user_is_flagged_against_normal_history(self):
        normal = self._load("normal_events.json")
        cut = min(e.timestamp for e in normal) + timedelta(hours=18)
        baseline = fit_baseline([e for e in normal if e.timestamp < cut])
        scored = score_windows(self._load("scenario_brute_force.json"), baseline)
        self.assertTrue(scored["flagged"].any())
        self.assertIn("failed_login_count", " ".join(scored["reasons"]))

    def test_unusual_login_is_flagged_for_new_source_and_location(self):
        normal = self._load("normal_events.json")
        cut = min(e.timestamp for e in normal) + timedelta(hours=18)
        baseline = fit_baseline([e for e in normal if e.timestamp < cut])
        scored = score_windows(self._load("scenario_unusual_login.json"), baseline)
        row = scored.iloc[0]
        self.assertTrue(bool(row["flagged"]))
        self.assertIn("IP this user has not used", row["reasons"])
        self.assertIn("location this user has not used", row["reasons"])

    def test_false_positive_rate_on_later_normal_data_is_recorded(self):
        normal = self._load("normal_events.json")
        cut = min(e.timestamp for e in normal) + timedelta(hours=18)
        baseline = fit_baseline([e for e in normal if e.timestamp < cut])
        scored = score_windows([e for e in normal if e.timestamp >= cut], baseline)
        rate = scored["flagged"].mean()
        # Known limitation: the baseline is rough, so some normal windows are flagged.
        # The test documents the rate and guards against it getting much worse.
        self.assertLess(rate, 0.05, f"false positive rate on normal windows is {rate:.1%}")


if __name__ == "__main__":
    unittest.main()