#!/usr/bin/env python3
"""Load detection output into the ThreatLens backend over REST.

Sends three things, in order, as the admin user:
  1. events    from data/raw/*.json        -> POST /api/events
  2. alerts    from data/processed/alerts.json    -> POST /api/alerts
  3. incidents from data/processed/incidents.json -> POST /api/incidents

Uses only the standard library. Re-running is safe: the backend skips items it already has.

Usage (from the repository root, with the backend running):
  python3 detection-engine/publish_detections.py --password admin123
"""

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, request

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"

# Fixed namespace, so the same alert always gets the same alertId on every run.
ALERT_NAMESPACE = uuid.UUID("6f1b8d52-0c1e-4c57-9a57-2f3f0b7e9a11")
SCORE_BY_SEVERITY = {"LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 90}
EVENT_TYPES = {
    "LOGIN_SUCCESS", "LOGIN_FAILED", "CONNECTION_ATTEMPT",
    "API_REQUEST", "PRIVILEGE_CHANGE", "RESOURCE_ACCESS",
}
EVENT_STATUSES = {"SUCCESS", "FAILURE", "INFO"}


def call(base, method, path, token=None, body=None):
    """Returns (status_code, parsed_json_or_text)."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = request.Request(base + path, data=data, method=method)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def iso_utc(value):
    """Converts an ISO timestamp to UTC with a trailing Z, as the backend expects."""
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def to_event(raw):
    """Maps a Phase 1 event (snake_case) to the backend's camelCase shape."""
    return {
        "eventId": raw["event_id"],
        # Events with no user or IP still need a value; the backend requires one.
        "userId": raw.get("user_id") or "UNKNOWN",
        "sourceIp": raw.get("source_ip") or "0.0.0.0",
        "eventType": raw["event_type"],
        "status": raw["status"],
        "occurredAt": iso_utc(raw["timestamp"]),
        "location": raw.get("location"),
        "destinationPort": raw.get("destination_port"),
        "scenario": (raw.get("metadata") or {}).get("scenario"),
    }


def to_alert(raw, incident_id):
    details = raw.get("details") or {}
    severity = raw["severity"]
    alert_key = "|".join(
        str(part) for part in (raw["rule_name"], raw["timestamp"], raw.get("user_id"), raw.get("source_ip"),
                               raw.get("file"))
    )
    return {
        "alertId": str(uuid.uuid5(ALERT_NAMESPACE, alert_key)),
        "ruleName": raw["rule_name"],
        "severity": severity,
        "score": int(details.get("score", SCORE_BY_SEVERITY.get(severity, 0))),
        "band": severity,
        "reason": raw["reason"][:512],
        "explanation": (details.get("explanation") or raw["reason"])[:2000],
        "userId": raw.get("user_id"),
        "sourceIp": raw.get("source_ip"),
        "occurredAt": iso_utc(raw["timestamp"]),
        "evidenceEventIds": raw["evidence_event_ids"],
        "incidentId": incident_id,
    }


def to_incident(raw):
    return {
        "incidentId": raw["incident_id"],
        "maxScore": raw["max_score"],
        "band": raw["band"],
        "firstSeen": iso_utc(raw["first_window"]),
        "lastSeen": iso_utc(raw["last_window"]),
        "windowCount": raw["window_count"],
        "explanation": (raw.get("top_explanation") or "")[:2000],
        "users": raw.get("users", []),
        "sourceIps": raw.get("source_ips", []),
        "rules": raw.get("rules", []),
    }


def link_alert_to_incident(alert_raw, incidents):
    """An alert joins the first incident that has its rule and its user or source IP."""
    for inc in incidents:
        same_actor = (alert_raw.get("user_id") in inc.get("users", [])
                      or alert_raw.get("source_ip") in inc.get("source_ips", []))
        if alert_raw["rule_name"] in inc.get("rules", []) and same_actor:
            return inc["incident_id"]
    return None


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", default="http://localhost:8080")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    status, login = call(args.backend, "POST", "/api/auth/login",
                         body={"username": args.username, "password": args.password})
    if status != 200:
        sys.exit(f"Login failed ({status}): {login}")
    token = login["token"]

    # 1. Events
    raw_events = []
    for path in sorted(RAW_DIR.glob("*.json")):
        raw_events.extend(load_json(path))
    events, skipped_local = [], 0
    for raw in raw_events:
        event = to_event(raw)
        if event["eventType"] in EVENT_TYPES and event["status"] in EVENT_STATUSES:
            events.append(event)
        else:
            skipped_local += 1
    inserted = 0
    for start in range(0, len(events), 500):
        status, body = call(args.backend, "POST", "/api/events", token, {"events": events[start:start + 500]})
        if status != 200:
            sys.exit(f"Event batch failed ({status}): {body}")
        inserted += body["inserted"]
    print(f"events:    sent={len(events)} inserted={inserted} skipped_locally={skipped_local}")

    # 2. Incidents (before alerts, so alerts can point at them)
    incidents = load_json(PROCESSED_DIR / "incidents.json")
    inc_created = 0
    for raw in incidents:
        status, body = call(args.backend, "POST", "/api/incidents", token, to_incident(raw))
        if status not in (200, 201):
            sys.exit(f"Incident {raw['incident_id']} failed ({status}): {body}")
        inc_created += 1 if status == 201 else 0
    print(f"incidents: sent={len(incidents)} created={inc_created}")

    # 3. Alerts
    alerts = load_json(PROCESSED_DIR / "alerts.json")
    alert_created = 0
    for raw in alerts:
        payload = to_alert(raw, link_alert_to_incident(raw, incidents))
        status, body = call(args.backend, "POST", "/api/alerts", token, payload)
        if status not in (200, 201):
            sys.exit(f"Alert {payload['alertId']} failed ({status}): {body}")
        alert_created += 1 if status == 201 else 0
    print(f"alerts:    sent={len(alerts)} created={alert_created}")
    print("Done. Open the dashboard and check the Alerts page.")


if __name__ == "__main__":
    main()