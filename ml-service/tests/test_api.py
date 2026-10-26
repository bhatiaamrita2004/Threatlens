"""Phase 7 tests: the ML service answers predictably and rejects bad input clearly.

Run from the repo root:
    python3 -m unittest discover -s ml-service/tests -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # ml-service/
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from app.main import DEFAULT_MODEL_DIR, DEFAULT_VERSION, create_app  # noqa: E402
from app.schemas import MODEL_FEATURE_FIELDS  # noqa: E402

NORMAL = {
    "event_count": 2, "failed_login_count": 0, "login_success_count": 2, "failure_ratio": 0.0,
    "offhours_login_count": 0, "connection_count": 0, "unique_ports": 0,
    "unique_source_ips": 1, "unique_locations": 1, "request_count": 0, "privilege_change_count": 0,
}
BURST = {
    "event_count": 30, "failed_login_count": 30, "login_success_count": 0, "failure_ratio": 1.0,
    "offhours_login_count": 0, "connection_count": 0, "unique_ports": 0,
    "unique_source_ips": 1, "unique_locations": 1, "request_count": 0, "privilege_change_count": 0,
}


def payload(*windows):
    return {"windows": list(windows)}


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = TestClient(cls.app)
        cls.client.__enter__()          # runs the startup code that loads the model

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def test_health_reports_the_loaded_model(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["model_loaded"])
        self.assertEqual(body["model_version"], DEFAULT_VERSION)

    def test_valid_payload_returns_predictions_in_order_with_ids(self):
        r = self.client.post("/predict", json=payload(
            {**NORMAL, "window_id": "w-1"}, {**BURST, "window_id": "w-2"}))
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["model_version"], DEFAULT_VERSION)
        self.assertEqual(body["count"], 2)
        self.assertEqual([p["window_id"] for p in body["predictions"]], ["w-1", "w-2"])
        for p in body["predictions"]:
            self.assertIsInstance(p["anomaly_score"], float)
            self.assertIsInstance(p["is_anomaly"], bool)
        self.assertIsInstance(body["threshold"], float)

    def test_burst_scores_higher_than_normal_and_is_flagged(self):
        body = self.client.post("/predict", json=payload(NORMAL, BURST)).json()
        normal, burst = body["predictions"]
        self.assertGreater(burst["anomaly_score"], normal["anomaly_score"])
        self.assertTrue(burst["is_anomaly"])
        self.assertFalse(normal["is_anomaly"])

    def test_missing_field_is_422_and_names_the_field(self):
        bad = {k: v for k, v in NORMAL.items() if k != "event_count"}
        r = self.client.post("/predict", json=payload(bad))
        self.assertEqual(r.status_code, 422)
        details = r.json()["details"]
        self.assertTrue(any(d["field"] == "windows.0.event_count" for d in details))

    def test_negative_count_is_rejected(self):
        r = self.client.post("/predict", json=payload({**NORMAL, "connection_count": -1}))
        self.assertEqual(r.status_code, 422)
        self.assertTrue(any("connection_count" in d["field"] for d in r.json()["details"]))

    def test_failure_ratio_above_one_is_rejected(self):
        r = self.client.post("/predict", json=payload({**NORMAL, "failure_ratio": 1.5}))
        self.assertEqual(r.status_code, 422)
        self.assertTrue(any("failure_ratio" in d["field"] for d in r.json()["details"]))

    def test_logins_cannot_exceed_events(self):
        r = self.client.post("/predict", json=payload({**NORMAL, "failed_login_count": 9, "login_success_count": 9}))
        self.assertEqual(r.status_code, 422)
        messages = " ".join(d["message"] for d in r.json()["details"])
        self.assertIn("cannot exceed event_count", messages)

    def test_unknown_field_is_rejected_not_ignored(self):
        r = self.client.post("/predict", json=payload({**NORMAL, "avg_login_hour": 3}))
        self.assertEqual(r.status_code, 422)

    def test_empty_batch_is_rejected(self):
        r = self.client.post("/predict", json={"windows": []})
        self.assertEqual(r.status_code, 422)

    def test_too_many_windows_is_rejected(self):
        r = self.client.post("/predict", json={"windows": [NORMAL] * 1001})
        self.assertEqual(r.status_code, 422)


class MissingModelTests(unittest.TestCase):
    def test_service_stays_up_and_reports_503_when_model_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = create_app(model_dir=Path(tmp), version="does-not-exist")
            with TestClient(app) as client:
                health = client.get("/health")
                self.assertEqual(health.status_code, 503)
                self.assertFalse(health.json()["model_loaded"])
                predict = client.post("/predict", json=payload(NORMAL))
                self.assertEqual(predict.status_code, 503)


class ContractTests(unittest.TestCase):
    def test_schema_matches_the_saved_model_features(self):
        meta_path = DEFAULT_MODEL_DIR / f"{DEFAULT_VERSION}.json"
        if not meta_path.exists():
            self.skipTest("model not trained yet")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        self.assertEqual(meta["features"], MODEL_FEATURE_FIELDS)


if __name__ == "__main__":
    unittest.main()