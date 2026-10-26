"""Phase 13 live check: talks to a running ThreatLens backend over HTTP.

These tests skip themselves when the backend is not running, so the normal test run stays
offline. Start the backend, publish the detection output, then run:

    THREATLENS_ANALYST_PASSWORD=analyst123 \
    python3 -m unittest detection-engine/tests/test_backend_live.py -v

Set THREATLENS_BACKEND to use a different address (default http://localhost:8080).
"""

import json
import os
import unittest
import urllib.error
import urllib.request

BASE = os.environ.get("THREATLENS_BACKEND", "http://localhost:8080")
PASSWORD = os.environ.get("THREATLENS_ANALYST_PASSWORD", "analyst123")


def call(method, path, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, None


class LiveBackendTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            # A 401 means the backend is up and wants a token, which is what we expect.
            call("GET", "/api/dashboard/summary")
        except urllib.error.URLError:
            raise unittest.SkipTest(f"backend not reachable at {BASE}")

        status, body = call("POST", "/api/auth/login", body={"username": "analyst", "password": PASSWORD})
        if status != 200:
            raise unittest.SkipTest(f"login failed with status {status}; check THREATLENS_ANALYST_PASSWORD")
        cls.token = body["token"]

    def test_dashboard_alert_count_matches_alert_list(self):
        _, summary = call("GET", "/api/dashboard/summary", self.token)
        _, page = call("GET", "/api/alerts?size=1", self.token)
        self.assertEqual(summary["totalAlerts"], page["totalItems"])

    def test_alerts_are_listed(self):
        _, page = call("GET", "/api/alerts?size=50", self.token)
        self.assertGreater(page["totalItems"], 0, "no alerts; run publish_detections.py first")

    def test_every_alert_detail_has_evidence_events(self):
        # Regression test for the empty evidence timeline seen in Phase 12.
        _, page = call("GET", "/api/alerts?size=50", self.token)
        for item in page["items"]:
            with self.subTest(alert=item["alertId"]):
                _, detail = call("GET", f"/api/alerts/{item['alertId']}", self.token)
                self.assertGreater(len(detail["evidenceEvents"]), 0)

    def test_a_known_event_can_be_fetched_by_id(self):
        # The first event in the brute-force scenario file, used by Phase 12 checks.
        status, body = call("GET", "/api/events/16ceeac5-ba1d-4954-a0c2-807f55d703c0", self.token)
        self.assertEqual(status, 200)
        self.assertEqual(body["userId"], "U105")


if __name__ == "__main__":
    unittest.main()