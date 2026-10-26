"use client";

import Link from "next/link";
import { useState } from "react";
import { api } from "../../lib/api";
import { usePolling } from "../../lib/usePolling";
import { BANDS, Card, ErrorBox, LiveControl, SeverityBadge, Shell, formatTime } from "../../components/ui";

const STATUSES = ["OPEN", "IN_REVIEW", "CONFIRMED", "DISMISSED"];
const PAGE_SIZE = 20;

export default function AlertsPage() {
  const [band, setBand] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);

  const query = new URLSearchParams({ page: String(page), size: String(PAGE_SIZE) });
  if (band) query.set("band", band);
  if (status) query.set("status", status);
  const qs = query.toString();

  const alerts = usePolling(() => api(`/alerts?${qs}`), 5000, [qs]);
  const data = alerts.data;

  function changeFilter(setter) {
    return (event) => {
      setter(event.target.value);
      setPage(0);
    };
  }

  return (
    <Shell>
      <div className="page-head">
        <h1>Alerts</h1>
        <LiveControl {...alerts} />
      </div>

      <Card>
        <div className="filters">
          <label>
            Severity
            <select value={band} onChange={changeFilter(setBand)}>
              <option value="">All</option>
              {BANDS.map((b) => (
                <option key={b} value={b}>
                  {b} and below
                </option>
              ))}
            </select>
          </label>
          <label>
            Status
            <select value={status} onChange={changeFilter(setStatus)}>
              <option value="">All</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
        </div>
        <ErrorBox message={alerts.error} />

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Rule</th>
                <th>User / IP</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {data?.items.length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    No alerts match these filters.
                  </td>
                </tr>
              )}
              {data?.items.map((a) => (
                <tr key={a.alertId}>
                  <td className="mono">{formatTime(a.occurredAt)}</td>
                  <td>
                    <SeverityBadge value={a.band} />
                  </td>
                  <td>
                    <Link href={`/alerts/${encodeURIComponent(a.alertId)}`}>{a.ruleName}</Link>
                    <div className="muted">{a.reason}</div>
                  </td>
                  <td className="mono">
                    {a.userId || "-"}
                    <br />
                    {a.sourceIp || "-"}
                  </td>
                  <td>{a.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {data && (
          <div className="page-head">
            <span className="muted">
              {data.totalItems} alerts, page {data.page + 1} of {Math.max(data.totalPages, 1)}
            </span>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="ghost" disabled={page === 0} onClick={() => setPage(page - 1)}>
                Previous
              </button>
              <button
                className="ghost"
                disabled={page + 1 >= data.totalPages}
                onClick={() => setPage(page + 1)}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </Card>
    </Shell>
  );
}