# Testing and known limitations (Phase 13)

## How to run the tests

From the repository root:

```bash
# Python: detection rules, scoring, features, baselines, ML, end-to-end pipeline, publisher
python3 -m unittest discover -s detection-engine/tests -v

# Live check against a running backend (skips itself if the backend is down)
THREATLENS_ANALYST_PASSWORD=analyst123 \
  python3 -m unittest detection-engine/tests/test_backend_live.py -v

# Java: API tests, unit tests (Mockito), health endpoint
cd backend && mvn clean test
```

Expected result today:

- Python discover run: 87 tests. One is skipped (the live backend test, when no backend is running). One is an expected failure (the unusual-login gap, below).
- Java: all tests pass once Maven can resolve dependencies (see "Not yet verified").

## What each layer covers

| Layer | Files | What it proves |
|---|---|---|
| Rules and scoring (Phases 2, 4, 5) | `test_rules.py`, `test_scoring.py`, `test_baseline.py`, `test_anomaly.py` | Each rule fires on its pattern; scoring bands are correct; baselines and the model load and score as expected |
| End-to-end pipeline | `test_pipeline_end_to_end.py` | Every data file validates; normal traffic raises no HIGH or CRITICAL alert; each attack scenario raises its rule; every alert cites only real events; output is repeatable |
| Publisher mapping | `test_publish_detections.py` | Timestamps become UTC with Z; field names map to the backend shape; alert IDs are stable; alerts link to the right incident |
| Live backend | `test_backend_live.py` | Alerts are listed; dashboard counts match; every alert detail has evidence (regression for the empty timeline in Phase 12); a known event can be fetched |
| Backend API | `ApiTests.java` | Login, roles, ingest, duplicate handling, validation errors, feedback, incidents, dashboard |
| Backend unit (Mockito) | `RedisLoginRateLimiterTest`, `AuthServiceTest`, `EventServiceTest` | Rate-limit counting and window rules; login refuses before the password check; unknown user and wrong password give the same error; duplicate events are skipped |
| Health | `HealthEndpointTests.java` | `/actuator/health` is public and reports UP |

## Known limitations

These are recorded here and, where a test can show them, in the test suite.

**Detection**
- **Unusual login is not caught by any rule.** The `scenario_unusual_login` file is a single event. `run_rules()` produces no alert for it. It is only visible to the baseline and ML layers. This is marked as an `expectedFailure` test, so it will show up as "unexpected success" once a rule covers it.
- **Synthetic data only.** All events are generated, and the IP addresses are from documentation ranges (RFC 5737). Results say nothing about real attack rates or real false-positive rates.
- **Rules are thresholds, not learned behaviour.** They fire on fixed counts within a time window. An attacker who spreads attempts out will evade them.
- **Baselines need history.** A user with no history gets a default baseline, so new users generate more noise.
- **Small test scenarios.** The attack files are tiny (12, 100 and 1 events). The tests show the rules work on these files, not that they generalise.

**Backend**
- **Login rate limit is per username, not per IP.** Attackers can try many usernames, and the counter does not block by source address. It also counts every login for that username, including the admin's manual logins within the window.
- **Rate limit fails open.** If Redis returns no value, the attempt is allowed. This avoids locking everyone out during a Redis fault, at the cost of weaker protection during that fault.
- **Health check depends on Redis.** In a running system, `/actuator/health` reports DOWN if Redis is down. This is intended for readiness, but it means a Redis outage will show as an unhealthy app.
- **OpenSearch is optional and best-effort.** Indexing failures are logged, not raised. Search results can be missing or stale until `POST /api/search/reindex` is run. Severity only ever goes up on an event.
- **Demo accounts are seeded in development.** `analyst/analyst123` and `admin/admin123` exist unless `threatlens.seed-demo-users` is set to false. The JWT secret has a development default unless `THREATLENS_JWT_SECRET` is set.
- **Tokens are not revocable.** A stolen JWT stays valid until it expires (60 minutes by default).

**Frontend**
- **Polling, not push.** Pages refresh every 5 to 10 seconds. A new alert can take up to that long to appear.
- **Token kept in sessionStorage.** It survives page reloads in the same tab, and it is readable by any script running on the page. Acceptable for a local tool, not for a shared deployment.

**Pipeline and data**
- **Publisher uses placeholder values.** Events with no user or IP are sent as `UNKNOWN` and `0.0.0.0` so the backend accepts them. Those values are not real.
- **Alert IDs depend on content.** An alert's ID is derived from its rule, time, user, IP and file. Changing those changes the ID, so re-publishing modified data creates new alerts rather than updating old ones.
- **Evidence must already be loaded.** An alert's timeline is empty until its supporting events are in the backend. The publisher sends events first to avoid this.

## Not yet verified

- **Java tests were written but not compiled in the environment used to prepare this phase.** Maven could not resolve the parent POM there. They need to be run on your machine with `mvn clean test`. If a Java test fails to compile, the first error will name the file and line.
- **The live backend tests need a running backend and the data published.** They were not run against a live backend in preparation.
- **No load or concurrency tests.** Behaviour under many simultaneous logins or event batches has not been measured.

## Next

- Phase 14 (Docker) can run these same commands inside a container, so the test results are reproducible on a clean machine.