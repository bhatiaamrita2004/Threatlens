"""Phase 2 tests: validation, each rule, and the labelled datasets.

Run from the repo root:
    python3 -m unittest discover -s detection-engine/tests -v
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # detection-engine/
import paths  # noqa: F401,E402  (adds event-generator as well)
from events import SecurityEvent  # noqa: E402
from pipeline import run_rules  # noqa: E402
from rules import brute_force, event_burst, port_scan, privilege_change  # noqa: E402
from validation import load_events  # noqa: E402

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def failed_login(i, seconds, user="U105", ip="203.0.113.50"):
    return SecurityEvent(
        user_id=user, source_ip=ip, event_type="LOGIN_FAILED", status="FAILURE",
        timestamp=T0 + timedelta(seconds=seconds), location="remote-vpn",
    )


def probe(port, seconds, ip="203.0.113.50"):
    return SecurityEvent(
        user_id="U000", source_ip=ip, event_type="CONNECTION_ATTEMPT", status="FAILURE",
        timestamp=T0 + timedelta(seconds=seconds), location="remote-vpn",
        destination_ip="192.0.2.10", destination_port=port, protocol="TCP",
    )


class ValidationTests(unittest.TestCase):
    def test_bad_records_are_reported_not_loaded(self):
        import json, tempfile
        good = {
            "event_id": "e1", "timestamp": "2026-10-01T12:00:00+00:00", "user_id": "U101",
            "source_ip": "198.51.100.1", "event_type": "LOGIN_SUCCESS", "status": "SUCCESS",
            "metadata": {"synthetic": True, "scenario": "normal"},
        }
        bad_type = {**good, "event_id": "e2", "event_type": "BOGUS"}
        no_tz = {**good, "event_id": "e3", "timestamp": "2026-10-01T12:00:00"}
        missing = {k: v for k, v in good.items() if k != "user_id"} | {"event_id": "e4"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.json"
            path.write_text(json.dumps([good, bad_type, no_tz, missing]), encoding="utf-8")
            events, problems = load_events(path)
        self.assertEqual(len(events), 1)
        self.assertEqual(len(problems), 3)


class BruteForceTests(unittest.TestCase):
    def test_five_failures_in_a_minute_alert(self):
        events = [failed_login(i, i * 5) for i in range(5)]
        user_alerts = [a for a in brute_force.detect(events) if a.user_id == "U105"]
        self.assertEqual(len(user_alerts), 1)
        self.assertEqual(len(user_alerts[0].evidence_event_ids), 5)
        self.assertEqual(user_alerts[0].severity, "MEDIUM")

    def test_four_failures_do_not_alert(self):
        events = [failed_login(i, i * 5) for i in range(4)]
        self.assertEqual(brute_force.detect(events), [])

    def test_failures_spread_out_do_not_alert(self):
        events = [failed_login(i, i * 120) for i in range(10)]  # 2 minutes apart
        self.assertEqual(brute_force.detect(events), [])

    def test_ten_or_more_failures_are_high(self):
        events = [failed_login(i, i * 5) for i in range(12)]
        user_alerts = [a for a in brute_force.detect(events) if a.user_id == "U105"]
        self.assertEqual(user_alerts[0].severity, "HIGH")
        self.assertEqual(len(user_alerts[0].evidence_event_ids), 12)


class PortScanTests(unittest.TestCase):
    def test_twenty_distinct_ports_alert(self):
        events = [probe(20 + i, i) for i in range(20)]
        alerts = port_scan.detect(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, "203.0.113.50")
        self.assertEqual(alerts[0].details["distinct_ports"], 20)

    def test_nineteen_distinct_ports_do_not_alert(self):
        events = [probe(20 + i, i) for i in range(19)]
        self.assertEqual(port_scan.detect(events), [])

    def test_same_port_repeated_does_not_alert(self):
        events = [probe(443, i) for i in range(100)]
        self.assertEqual(port_scan.detect(events), [])


class EventBurstTests(unittest.TestCase):
    def test_thirty_events_in_a_minute_alert(self):
        events = [probe(443, i * 1.5) for i in range(30)]
        alerts = event_burst.detect(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(alerts[0].evidence_event_ids), 30)

    def test_twenty_nine_events_do_not_alert(self):
        events = [probe(443, i * 1.5) for i in range(29)]
        self.assertEqual(event_burst.detect(events), [])


class PrivilegeChangeTests(unittest.TestCase):
    def _change(self, role, status="SUCCESS"):
        return SecurityEvent(
            user_id="U107", source_ip="198.51.100.9", event_type="PRIVILEGE_CHANGE",
            status=status, timestamp=T0, metadata={"synthetic": True, "role": role},
        )

    def test_sensitive_role_grant_is_high(self):
        alerts = privilege_change.detect([self._change("admin")])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_other_role_grant_is_low(self):
        alerts = privilege_change.detect([self._change("analyst")])
        self.assertEqual(alerts[0].severity, "LOW")

    def test_failed_change_is_ignored(self):
        self.assertEqual(privilege_change.detect([self._change("admin", "FAILURE")]), [])


class DatasetTests(unittest.TestCase):
    """Run the rules on the Phase 1 files. Skipped if the data was not generated."""

    def _alerts(self, name):
        path = paths.RAW_DATA_DIR / name
        if not path.exists():
            self.skipTest(f"{name} not generated; run Phase 1 first")
        events, _problems = load_events(path)
        return run_rules(events)

    def test_all_files_validate_cleanly(self):
        for name in ("normal_events.json", "scenario_brute_force.json",
                     "scenario_port_scan.json", "scenario_unusual_login.json"):
            path = paths.RAW_DATA_DIR / name
            if not path.exists():
                self.skipTest(f"{name} not generated")
            _, problems = load_events(path)
            self.assertEqual(problems, [], name)

    def test_brute_force_scenario_triggers_brute_force_rule(self):
        alerts = self._alerts("scenario_brute_force.json")
        rules = {a.rule_name for a in alerts}
        self.assertIn(brute_force.RULE_NAME, rules)
        self.assertTrue(any(a.user_id == "U105" and a.severity == "HIGH" for a in alerts))

    def test_port_scan_scenario_triggers_port_scan_rule(self):
        alerts = self._alerts("scenario_port_scan.json")
        scans = [a for a in alerts if a.rule_name == port_scan.RULE_NAME]
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].severity, "HIGH")

    def test_normal_data_triggers_no_detection_rules(self):
        alerts = self._alerts("normal_events.json")
        self.assertEqual(alerts, [], [f"{a.rule_name}: {a.reason}" for a in alerts])


if __name__ == "__main__":
    unittest.main()