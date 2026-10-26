"""Phase 13 tests for publish_detections.py: the mapping from detection output to backend payloads.

Run from the repo root:
    python3 -m unittest discover -s detection-engine/tests -v
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # detection-engine/
import publish_detections as pub  # noqa: E402


def raw_event(**overrides):
    base = {
        "event_id": "16ceeac5-ba1d-4954-a0c2-807f55d703c0",
        "user_id": "U105",
        "source_ip": "203.0.113.50",
        "event_type": "LOGIN_FAILED",
        "status": "FAILURE",
        "timestamp": "2026-10-01T12:00:00+00:00",
        "location": "remote-vpn",
        "destination_port": None,
        "metadata": {"synthetic": True, "scenario": "brute_force"},
    }
    base.update(overrides)
    return base


def raw_alert(**overrides):
    base = {
        "file": "scenario_brute_force.json",
        "rule_name": "repeated_failed_logins",
        "severity": "HIGH",
        "timestamp": "2026-10-01T12:00:55+00:00",
        "reason": "12 failed logins for user_id U105 within 60s bursts",
        "user_id": "U105",
        "source_ip": None,
        "evidence_event_ids": ["a", "b"],
        "details": {},
    }
    base.update(overrides)
    return base


class TimestampTests(unittest.TestCase):

    def test_offset_is_converted_to_utc_with_z(self):
        self.assertEqual(pub.iso_utc("2026-10-01T14:00:00+02:00"), "2026-10-01T12:00:00Z")

    def test_utc_offset_becomes_z(self):
        self.assertEqual(pub.iso_utc("2026-10-01T12:00:00+00:00"), "2026-10-01T12:00:00Z")

    def test_naive_timestamp_is_treated_as_utc(self):
        self.assertEqual(pub.iso_utc("2026-10-01T12:00:00"), "2026-10-01T12:00:00Z")


class EventMappingTests(unittest.TestCase):

    def test_snake_case_fields_become_camel_case(self):
        mapped = pub.to_event(raw_event())
        self.assertEqual(mapped["eventId"], "16ceeac5-ba1d-4954-a0c2-807f55d703c0")
        self.assertEqual(mapped["userId"], "U105")
        self.assertEqual(mapped["sourceIp"], "203.0.113.50")
        self.assertEqual(mapped["eventType"], "LOGIN_FAILED")
        self.assertEqual(mapped["occurredAt"], "2026-10-01T12:00:00Z")
        self.assertEqual(mapped["scenario"], "brute_force")

    def test_missing_user_and_ip_get_placeholders_so_the_backend_accepts_them(self):
        mapped = pub.to_event(raw_event(user_id=None, source_ip=None))
        self.assertEqual(mapped["userId"], "UNKNOWN")
        self.assertEqual(mapped["sourceIp"], "0.0.0.0")

    def test_missing_metadata_gives_no_scenario(self):
        self.assertIsNone(pub.to_event(raw_event(metadata=None))["scenario"])


class AlertMappingTests(unittest.TestCase):

    def test_alert_id_is_stable_across_runs(self):
        first = pub.to_alert(raw_alert(), None)["alertId"]
        second = pub.to_alert(raw_alert(), None)["alertId"]
        self.assertEqual(first, second)

    def test_different_alerts_get_different_ids(self):
        a = pub.to_alert(raw_alert(), None)["alertId"]
        b = pub.to_alert(raw_alert(timestamp="2026-10-01T13:00:00+00:00"), None)["alertId"]
        self.assertNotEqual(a, b)

    def test_score_defaults_from_severity_when_details_lack_one(self):
        self.assertEqual(pub.to_alert(raw_alert(severity="HIGH"), None)["score"], 75)

    def test_long_reason_is_truncated_to_the_backend_limit(self):
        mapped = pub.to_alert(raw_alert(reason="x" * 600), None)
        self.assertEqual(len(mapped["reason"]), 512)

    def test_band_matches_severity(self):
        mapped = pub.to_alert(raw_alert(severity="MEDIUM"), None)
        self.assertEqual(mapped["band"], "MEDIUM")


class IncidentLinkTests(unittest.TestCase):

    incidents = [{
        "incident_id": "INC-001",
        "users": ["U000", "U105"],
        "source_ips": ["203.0.113.50"],
        "rules": ["event_burst", "repeated_failed_logins"],
    }]

    def test_alert_links_when_rule_and_user_match(self):
        alert = raw_alert(rule_name="repeated_failed_logins", user_id="U105", source_ip=None)
        self.assertEqual(pub.link_alert_to_incident(alert, self.incidents), "INC-001")

    def test_alert_links_when_rule_and_source_ip_match(self):
        alert = raw_alert(rule_name="event_burst", user_id=None, source_ip="203.0.113.50")
        self.assertEqual(pub.link_alert_to_incident(alert, self.incidents), "INC-001")

    def test_alert_does_not_link_when_rule_is_not_in_the_incident(self):
        alert = raw_alert(rule_name="privilege_change", user_id="U105", source_ip=None)
        self.assertIsNone(pub.link_alert_to_incident(alert, self.incidents))

    def test_alert_does_not_link_when_actor_is_different(self):
        alert = raw_alert(rule_name="repeated_failed_logins", user_id="U999", source_ip="198.51.100.1")
        self.assertIsNone(pub.link_alert_to_incident(alert, self.incidents))


if __name__ == "__main__":
    unittest.main()