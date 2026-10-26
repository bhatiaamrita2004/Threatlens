"""Publish security events or alerts to Kafka (Phase 10).

Run from the project root:
  python3 detection-engine/kafka_publisher.py events path/to/events.json
  python3 detection-engine/kafka_publisher.py alerts path/to/alerts.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from kafka import KafkaProducer
from kafka.errors import KafkaError

BOOTSTRAP = "localhost:9092"
TOPICS = {"events": ("security-events", "userId"), "alerts": ("threat-alerts", "alertId")}


def normalise_time(value: str) -> str:
    """Write times the way Java expects: UTC with a trailing Z, e.g. 2026-06-01T10:00:00.000Z."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def to_backend_event(r: dict) -> dict:
    """Convert one Phase 1 event (snake_case) to the backend's EventIn shape (camelCase)."""
    meta = r.get("metadata") or {}
    return {
        "eventId": r["event_id"],
        "userId": r["user_id"],
        "sourceIp": r["source_ip"],
        "eventType": r["event_type"],
        "status": r["status"],
        "occurredAt": normalise_time(r["timestamp"]),
        "location": r.get("location"),
        "destinationPort": r.get("destination_port"),
        "scenario": meta.get("scenario"),
    }


def make_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=BOOTSTRAP,
        acks="all",                # wait until the broker has the message
        enable_idempotence=True,   # retries cannot create duplicates
        retries=5,
        key_serializer=lambda k: k.encode("utf-8"),
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Publish events or alerts to Kafka.")
    parser.add_argument("kind", choices=TOPICS.keys())
    parser.add_argument("path", type=Path, help="JSON file containing a list of records")
    args = parser.parse_args()

    topic, key_field = TOPICS[args.kind]
    raw = json.loads(args.path.read_text())

    if args.kind == "events":
        records = [to_backend_event(r) for r in raw]
    else:
        records = raw
        for record in records:
            record["occurredAt"] = normalise_time(record["occurredAt"])

    producer = make_producer()
    futures = [
        producer.send(topic, key=str(record.get(key_field) or "unknown"), value=record)
        for record in records
    ]
    producer.flush()

    sent, failed = 0, 0
    for record, future in zip(records, futures):
        try:
            future.get(timeout=10)
            sent += 1
        except KafkaError as err:
            failed += 1
            print(f"FAILED {record.get(key_field)}: {err}", file=sys.stderr)
    producer.close()

    print(f"topic={topic} sent={sent} failed={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())