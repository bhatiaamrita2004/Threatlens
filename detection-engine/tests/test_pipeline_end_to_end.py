"""Phase 13 end-to-end tests: event files -> validation -> rules -> alerts.

Run from the repo root:
    python3 -m unittest discover -s detection-engine/tests -v

Known limitations are written as unittest.expectedFailure tests. They show as "expected
failures" (x) and do not break the run. When a limitation is fixed, the test reports an
"unexpected success", which is the signal to remove the decorator.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # detection-engine/
import paths  # noqa: F401,E402
from pipeline import run_rules  # noqa: E402
from validation import load_events  # noqa: E402

RAW = Path(__file__).resolve().parents[2] / "data" / "raw"
HIGH_OR_ABOVE = {"HIGH", "CRITICAL"}


def load(name):
    path = RAW / f"{name}.json"
    if not path.exists():
        raise unittest.SkipTest(f"{path} not found; run the generator first")
    return load_events(path)


class PipelineEndToEndTests(unittest.TestCase):

    def test_every_data_file_loads_without_validation_errors(self):
        for name in ("normal_events", "scenario_brute_force", "scenario_port_scan", "scenario_unusual_login"):
            with self.subTest(file=name):
                _, errors = load(name)
                self.assertEqual(errors, [])

    def test_normal_traffic_raises_no_high_or_critical_alert(self):
        events, _ = load("normal_events")
        high = [a.rule_name for a in run_rules(events) if a.severity in HIGH_OR_ABOVE]
        self.assertEqual(high, [], "false positives at HIGH or above")

    def test_brute_force_scenario_raises_repeated_failed_logins(self):
        events, _ = load("scenario_brute_force")
        alerts = run_rules(events)
        self.assertIn("repeated_failed_logins", {a.rule_name for a in alerts})
        self.assertTrue(all(a.severity in HIGH_OR_ABOVE for a in alerts if a.rule_name == "repeated_failed_logins"))

    def test_port_scan_scenario_raises_many_ports_one_source(self):
        events, _ = load("scenario_port_scan")
        self.assertIn("many_ports_one_source", {a.rule_name for a in run_rules(events)})

    def test_every_alert_cites_only_events_that_exist(self):
        for name in ("normal_events", "scenario_brute_force", "scenario_port_scan"):
            with self.subTest(file=name):
                events, _ = load(name)
                known = {e.event_id for e in events}
                for alert in run_rules(events):
                    self.assertTrue(alert.evidence_event_ids, alert.rule_name)
                    self.assertTrue(set(alert.evidence_event_ids) <= known, alert.rule_name)

    def test_rules_are_repeatable(self):
        events, _ = load("scenario_port_scan")

        def summary(alerts):
            return [(a.rule_name, a.severity, tuple(a.evidence_event_ids)) for a in alerts]

        self.assertEqual(summary(run_rules(events)), summary(run_rules(events)))

    @unittest.expectedFailure
    def test_unusual_login_scenario_is_detected_by_a_rule(self):
        # KNOWN LIMITATION: the one-event unusual-login scenario is not caught by any rule.
        # Only the baseline and ML layers can see it, and they are not part of run_rules().
        events, _ = load("scenario_unusual_login")
        self.assertTrue(run_rules(events))


if __name__ == "__main__":
    unittest.main()