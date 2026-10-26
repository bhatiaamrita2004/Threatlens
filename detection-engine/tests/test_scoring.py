"""Phase 6 tests: scores, bands, explanations and incident grouping.

Run from the repo root:
    python3 -m unittest discover -s detection-engine/tests -v
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # detection-engine/
import paths  # noqa: F401,E402
from anomaly_model import score_windows as ml_score_windows, train  # noqa: E402
from baseline import fit_baseline, score_windows as base_score_windows  # noqa: E402
from events import SecurityEvent  # noqa: E402
from generator import generate_normal_events  # noqa: E402
from incidents import group_incidents  # noqa: E402
from pipeline import run_rules  # noqa: E402
from scoring import Evidence, band_for, build_scores, score_evidence  # noqa: E402

T0 = datetime(2026, 10, 1, 0, 0, tzinfo=timezone.utc)


def failed(user, ip, minutes, seconds=0):
    return SecurityEvent(
        user_id=user, source_ip=ip, event_type="LOGIN_FAILED", status="FAILURE",
        timestamp=T0 + timedelta(minutes=minutes, seconds=seconds),
        location="remote-vpn", metadata={"synthetic": True, "scenario": "brute_force"},
    )


def scored_rows(*rows):
    """rows: (user, minutes, score) -> the shape build_scores returns."""
    data = []
    for user, minutes, score in rows:
        data.append({
            "entity_id": user,
            "window_start": pd.Timestamp(T0 + timedelta(minutes=minutes)).floor("5min"),
            "score": score,
            "band": band_for(score),
            "rules": ["repeated_failed_logins"] if score >= 60 else [],
            "explanation": f"score {score}",
        })
    return pd.DataFrame(data)


class BandTests(unittest.TestCase):
    def test_band_boundaries(self):
        self.assertEqual(band_for(0), "LOW")
        self.assertEqual(band_for(29), "LOW")
        self.assertEqual(band_for(30), "MEDIUM")
        self.assertEqual(band_for(59), "MEDIUM")
        self.assertEqual(band_for(60), "HIGH")
        self.assertEqual(band_for(79), "HIGH")
        self.assertEqual(band_for(80), "CRITICAL")
        self.assertEqual(band_for(100), "CRITICAL")


class ScoreTests(unittest.TestCase):
    def test_no_evidence_scores_zero(self):
        result = score_evidence(Evidence())
        self.assertEqual(result.score, 0)
        self.assertEqual(result.band, "LOW")
        self.assertEqual(result.explanation, [])

    def test_high_rule_alone_is_high_without_corroboration(self):
        result = score_evidence(Evidence(rules=["port_scan"], top_severity="HIGH"))
        self.assertEqual(result.score, 60)
        self.assertEqual(result.band, "HIGH")
        self.assertNotIn("corroboration", result.points)

    def test_rule_plus_ml_corroborates_to_critical(self):
        result = score_evidence(Evidence(
            rules=["repeated_failed_logins"], top_severity="HIGH", ml_flag=True, ml_score=1.8,
        ))
        self.assertEqual(result.points["corroboration"], 10)
        self.assertEqual(result.score, 80)
        self.assertEqual(result.band, "CRITICAL")

    def test_ml_and_baseline_together_are_medium_not_high(self):
        # Neither source is a rule, so the score stays below HIGH.
        result = score_evidence(Evidence(ml_flag=True, ml_score=1.5, baseline_flag=True,
                                         baseline_reasons="failed_login_count = 4"))
        self.assertEqual(result.score, 30)
        self.assertEqual(result.band, "MEDIUM")

    def test_single_weak_signal_is_low(self):
        result = score_evidence(Evidence(ml_flag=True, ml_score=1.2))
        self.assertEqual(result.score, 10)
        self.assertEqual(result.band, "LOW")

    def test_score_is_capped_at_100(self):
        result = score_evidence(Evidence(
            rules=["x"], top_severity="CRITICAL", ml_flag=True, ml_score=2.0, baseline_flag=True,
        ))
        self.assertEqual(result.score, 100)

    def test_explanation_names_each_source(self):
        result = score_evidence(Evidence(
            rules=["repeated_failed_logins"], top_severity="HIGH", ml_flag=True, ml_score=1.8,
            baseline_flag=True, baseline_reasons="failed_login_count = 12",
        ))
        text = "; ".join(result.explanation)
        self.assertIn("repeated_failed_logins", text)
        self.assertIn("ML model", text)
        self.assertIn("usual behaviour", text)
        self.assertIn("different kinds of evidence", text)


class IncidentTests(unittest.TestCase):
    def test_same_user_within_gap_is_one_incident(self):
        scored = scored_rows(("U1", 0, 60), ("U1", 10, 60))
        events = [failed("U1", "10.0.0.1", 0), failed("U1", "10.0.0.1", 10)]
        self.assertEqual(len(group_incidents(scored, events)), 1)

    def test_same_user_beyond_gap_is_two_incidents(self):
        scored = scored_rows(("U1", 0, 60), ("U1", 60, 60))
        events = [failed("U1", "10.0.0.1", 0), failed("U1", "10.0.0.1", 60)]
        self.assertEqual(len(group_incidents(scored, events)), 2)

    def test_different_users_sharing_an_ip_within_gap_are_one_incident(self):
        scored = scored_rows(("U1", 0, 60), ("U2", 5, 60))
        events = [failed("U1", "203.0.113.50", 0), failed("U2", "203.0.113.50", 5)]
        incidents = group_incidents(scored, events)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["users"], ["U1", "U2"])

    def test_different_users_and_ips_are_separate_incidents(self):
        scored = scored_rows(("U1", 0, 60), ("U2", 5, 60))
        events = [failed("U1", "10.0.0.1", 0), failed("U2", "10.0.0.2", 5)]
        self.assertEqual(len(group_incidents(scored, events)), 2)

    def test_low_scoring_windows_do_not_form_incidents(self):
        scored = scored_rows(("U1", 0, 10))
        events = [failed("U1", "10.0.0.1", 0)]
        self.assertEqual(group_incidents(scored, events), [])

    def test_incidents_are_ranked_by_score(self):
        scored = scored_rows(("U1", 0, 40), ("U2", 120, 85))
        events = [failed("U1", "10.0.0.1", 0), failed("U2", "10.0.0.2", 120)]
        incidents = group_incidents(scored, events)
        self.assertEqual(incidents[0]["max_score"], 85)
        self.assertEqual(incidents[0]["incident_id"], "INC-001")


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.history = generate_normal_events(1500, seed=7, window_hours=18)
        cls.model, _ = train(cls.history)
        cls.baseline = fit_baseline(cls.history)

    def _score(self, events):
        alerts = run_rules(events)
        ml = ml_score_windows(events, self.model)
        base = base_score_windows(events, self.baseline)
        return build_scores(events, alerts, ml, base), events

    def test_brute_force_burst_scores_high_and_becomes_an_incident(self):
        events = [failed("U105", "203.0.113.50", 0, seconds=i * 3) for i in range(30)]
        scored, events = self._score(events)
        top = scored.iloc[0]
        self.assertEqual(top["entity_id"], "U105")
        self.assertIn(top["band"], ("HIGH", "CRITICAL"))
        self.assertIn("repeated_failed_logins", top["explanation"])
        incidents = group_incidents(scored, events)
        self.assertGreaterEqual(len(incidents), 1)
        self.assertIn("repeated_failed_logins", incidents[0]["rules"])

    def test_normal_activity_never_reaches_high_without_a_rule(self):
        normal = generate_normal_events(600, seed=11, window_hours=6)
        scored, _ = self._score(normal)
        self.assertEqual(run_rules(normal), [])
        self.assertLess(scored["score"].max(), 60)


if __name__ == "__main__":
    unittest.main()