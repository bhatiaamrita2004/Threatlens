"use client";

import Link from "next/link";
import { useState } from "react";
import { api } from "../../../lib/api";
import { usePolling } from "../../../lib/usePolling";
import { attackFor } from "../../../lib/attack";
import { Card, ErrorBox, SeverityBadge, Shell, formatTime } from "../../../components/ui";

const VERDICTS = ["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"];

export default function AlertDetailPage({ params }) {
  const alertId = decodeURIComponent(params.id);
  const detail = usePolling(() => api(`/alerts/${encodeURIComponent(alertId)}`), 10000, [alertId]);

  const [verdict, setVerdict] = useState("TRUE_POSITIVE");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(null);

  async function submitFeedback(event) {
    event.preventDefault();
    setSaving(true);
    setSaveError(null);
    try {
      await api(`/alerts/${encodeURIComponent(alertId)}/feedback`, {
        method: "POST",
        body: { verdict, note: note || null },
      });
      setNote("");
      await detail.reload();
    } catch (err) {
      setSaveError(err.message);
    } finally {
      setSaving(false);
    }
  }

  const data = detail.data;
  const alert = data?.alert;
  const attack = alert ? attackFor(alert.ruleName) : null;
  const explanationPoints = alert?.explanation
    ? alert.explanation.split(";").map((s) => s.trim()).filter(Boolean)
    : [];

  return (
    <Shell>
      <div className="page-head">
        <h1>
          <Link href="/alerts">Alerts</Link> / {alertId}
        </h1>
      </div>
      <ErrorBox message={detail.error} />
      {!data && !detail.error && <p className="muted">Loading alert...</p>}

      {alert && (
        <>
          <Card title="Summary">
            <div className="page-head">
              <div>
                <strong style={{ fontSize: "1.15rem" }}>{alert.ruleName}</strong>
                <div className="muted">{alert.reason}</div>
              </div>
              <div style={{ textAlign: "right" }}>
                <SeverityBadge value={alert.band} /> <span className="chip">score {alert.score}</span>
                <div className="muted">Status: {alert.status}</div>
              </div>
            </div>
            <dl className="kv">
              <dt>Detected at</dt>
              <dd>{formatTime(alert.occurredAt)}</dd>
              <dt>User</dt>
              <dd className="mono">{alert.userId || "-"}</dd>
              <dt>Source IP</dt>
              <dd className="mono">{alert.sourceIp || "-"}</dd>
              <dt>Incident</dt>
              <dd>
                {alert.incidentId ? (
                  <Link href={`/incidents/${encodeURIComponent(alert.incidentId)}`}>{alert.incidentId}</Link>
                ) : (
                  "Not linked"
                )}
              </dd>
            </dl>
          </Card>

          <div className="grid two">
            <Card title="Why this was flagged">
              {explanationPoints.length > 0 ? (
                <ul className="explain">
                  {explanationPoints.map((point, i) => (
                    <li key={i}>{point}</li>
                  ))}
                </ul>
              ) : (
                <p className="muted">{alert.reason}</p>
              )}
            </Card>

            <Card title="MITRE ATT&amp;CK">
              {attack ? (
                <>
                  <div>
                    <span className="attack-id">{attack.id}</span> {attack.name}
                  </div>
                  <div className="muted">Tactic: {attack.tactic}</div>
                  <a href={attack.url} target="_blank" rel="noreferrer">
                    View technique
                  </a>
                  <p className="muted">
                    This is a labelling aid. It describes what the pattern resembles, not a confirmed attack.
                  </p>
                </>
              ) : (
                <p className="muted">No ATT&amp;CK mapping for this rule.</p>
              )}
            </Card>
          </div>

          <Card title={`Evidence timeline (${data.evidenceEvents.length} events)`}>
            {data.evidenceEvents.length === 0 && (
              <p className="muted">
                The supporting events are not in the backend yet. Publish the events first, then reload.
              </p>
            )}
            <ul className="timeline">
              {data.evidenceEvents.map((e) => (
                <li key={e.eventId}>
                  <div className="when">{formatTime(e.occurredAt)}</div>
                  <strong>{e.eventType}</strong> <span className="muted">({e.status})</span>
                  <div className="mono">
                    {e.userId} from {e.sourceIp}
                    {e.destinationPort ? `, port ${e.destinationPort}` : ""}
                    {e.location ? `, ${e.location}` : ""}
                  </div>
                </li>
              ))}
            </ul>
          </Card>

          <div className="grid two">
            <Card title="Analyst verdict">
              <form onSubmit={submitFeedback} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                <select value={verdict} onChange={(e) => setVerdict(e.target.value)}>
                  {VERDICTS.map((v) => (
                    <option key={v} value={v}>
                      {v.replace(/_/g, " ")}
                    </option>
                  ))}
                </select>
                <textarea
                  placeholder="Optional note, for example: known vulnerability scanner"
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  maxLength={1000}
                />
                <ErrorBox message={saveError} />
                <button type="submit" disabled={saving}>
                  {saving ? "Saving..." : "Record verdict"}
                </button>
              </form>
            </Card>

            <Card title="Feedback history">
              {data.feedback.length === 0 && <p className="muted">No verdicts yet.</p>}
              {data.feedback.map((f) => (
                <div key={f.id} className="row-link" style={{ flexDirection: "column" }}>
                  <span>
                    <strong>{f.verdict.replace(/_/g, " ")}</strong> by {f.analyst}
                  </span>
                  <span className="muted">{formatTime(f.createdAt)}</span>
                  {f.note && <span>{f.note}</span>}
                </div>
              ))}
            </Card>
          </div>
        </>
      )}
    </Shell>
  );
}