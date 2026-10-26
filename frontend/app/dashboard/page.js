"use client";

import Link from "next/link";
import { api } from "../../lib/api";
import { usePolling } from "../../lib/usePolling";
import { BANDS, Card, ErrorBox, LiveControl, SeverityBadge, Shell, Stat, formatTime } from "../../components/ui";

export default function DashboardPage() {
  const summary = usePolling(() => api("/dashboard/summary"), 5000);
  const latest = usePolling(() => api("/alerts?size=6"), 5000);

  const byBand = summary.data?.alertsByBand ?? {};
  const maxBand = Math.max(1, ...BANDS.map((b) => byBand[b] ?? 0));

  return (
    <Shell>
      <div className="page-head">
        <h1>Overview</h1>
        <LiveControl {...summary} />
      </div>
      <ErrorBox message={summary.error} />

      {summary.data && (
        <div className="grid stats">
          <Stat label="Events stored" value={summary.data.totalEvents} />
          <Stat label="Alerts" value={summary.data.totalAlerts} />
          <Stat label="Open alerts" value={summary.data.openAlerts} tone="warn" />
          <Stat label="Incidents" value={summary.data.totalIncidents} />
        </div>
      )}

      {summary.data && (
        <div className="grid two">
          <Card title="Alerts by severity">
            {BANDS.map((band) => {
              const count = byBand[band] ?? 0;
              return (
                <div className="bar-row" key={band}>
                  <SeverityBadge value={band} />
                  <div className="bar-track">
                    <div className="bar-fill" style={{ width: `${(count / maxBand) * 100}%` }} />
                  </div>
                  <span className="mono">{count}</span>
                </div>
              );
            })}
          </Card>

          <Card title="Top incidents">
            {summary.data.topIncidents.length === 0 && <p className="muted">No incidents yet.</p>}
            {summary.data.topIncidents.map((inc) => (
              <Link key={inc.incidentId} href={`/incidents/${encodeURIComponent(inc.incidentId)}`} className="row-link">
                <span className="mono">{inc.incidentId}</span>
                <span>
                  <SeverityBadge value={inc.band} /> score {inc.maxScore}
                </span>
              </Link>
            ))}
          </Card>
        </div>
      )}

      <Card
        title="Latest alerts"
        right={<Link href="/alerts">View all</Link>}
      >
        <ErrorBox message={latest.error} />
        {latest.data?.items.length === 0 && <p className="muted">No alerts yet.</p>}
        {latest.data?.items.map((a) => (
          <Link key={a.alertId} href={`/alerts/${encodeURIComponent(a.alertId)}`} className="row-link">
            <span>
              <strong>{a.ruleName}</strong>
              <br />
              <span className="muted">{a.reason}</span>
            </span>
            <span style={{ textAlign: "right", whiteSpace: "nowrap" }}>
              <SeverityBadge value={a.band} />
              <br />
              <span className="muted">{formatTime(a.occurredAt)}</span>
            </span>
          </Link>
        ))}
      </Card>
    </Shell>
  );
}