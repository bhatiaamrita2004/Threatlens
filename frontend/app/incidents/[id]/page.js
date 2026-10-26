"use client";

import Link from "next/link";
import { api } from "../../../lib/api";
import { usePolling } from "../../../lib/usePolling";
import { Card, ErrorBox, SeverityBadge, Shell, formatTime } from "../../../components/ui";

export default function IncidentPage({ params }) {
  const incidentId = decodeURIComponent(params.id);
  const detail = usePolling(() => api(`/incidents/${encodeURIComponent(incidentId)}`), 10000, [incidentId]);
  const data = detail.data;
  const inc = data?.incident;

  return (
    <Shell>
      <div className="page-head">
        <h1>
          <Link href="/dashboard">Overview</Link> / Incident {incidentId}
        </h1>
      </div>
      <ErrorBox message={detail.error} />
      {!data && !detail.error && <p className="muted">Loading incident...</p>}

      {inc && (
        <>
          <Card title="Summary">
            <div className="page-head">
              <p style={{ margin: 0 }}>{inc.explanation || "No explanation recorded."}</p>
              <div style={{ textAlign: "right" }}>
                <SeverityBadge value={inc.band} /> <span className="chip">score {inc.maxScore}</span>
              </div>
            </div>
            <dl className="kv">
              <dt>First seen</dt>
              <dd>{formatTime(inc.firstSeen)}</dd>
              <dt>Last seen</dt>
              <dd>{formatTime(inc.lastSeen)}</dd>
              <dt>Windows</dt>
              <dd>{inc.windowCount}</dd>
              <dt>Users</dt>
              <dd>{inc.users.map((u) => <span className="chip" key={u}>{u}</span>)}</dd>
              <dt>Source IPs</dt>
              <dd>{inc.sourceIps.map((ip) => <span className="chip" key={ip}>{ip}</span>)}</dd>
              <dt>Rules fired</dt>
              <dd>{inc.rules.map((r) => <span className="chip" key={r}>{r}</span>)}</dd>
            </dl>
          </Card>

          <Card title={`Linked alerts (${data.alerts.length})`}>
            {data.alerts.length === 0 && <p className="muted">No alerts linked to this incident.</p>}
            {data.alerts.map((a) => (
              <Link key={a.alertId} href={`/alerts/${encodeURIComponent(a.alertId)}`} className="row-link">
                <span>
                  <strong>{a.ruleName}</strong>
                  <br />
                  <span className="muted">{a.reason}</span>
                </span>
                <span style={{ textAlign: "right" }}>
                  <SeverityBadge value={a.band} />
                  <br />
                  <span className="muted">{formatTime(a.occurredAt)}</span>
                </span>
              </Link>
            ))}
          </Card>
        </>
      )}
    </Shell>
  );
}