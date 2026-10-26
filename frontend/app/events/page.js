"use client";

import { useState } from "react";
import { api } from "../../lib/api";
import { usePolling } from "../../lib/usePolling";
import { Card, ErrorBox, LiveControl, Shell, formatTime } from "../../components/ui";

const PAGE_SIZE = 50;

export default function EventsPage() {
  const [userInput, setUserInput] = useState("");
  const [userId, setUserId] = useState("");
  const [page, setPage] = useState(0);

  const query = new URLSearchParams({ page: String(page), size: String(PAGE_SIZE) });
  if (userId) query.set("userId", userId);
  const qs = query.toString();

  const events = usePolling(() => api(`/events?${qs}`), 5000, [qs]);
  const data = events.data;

  function applyFilter(event) {
    event.preventDefault();
    setUserId(userInput.trim());
    setPage(0);
  }

  return (
    <Shell>
      <div className="page-head">
        <h1>Event feed</h1>
        <LiveControl {...events} />
      </div>

      <Card>
        <form onSubmit={applyFilter} className="filters">
          <label>
            User ID
            <input
              value={userInput}
              onChange={(e) => setUserInput(e.target.value)}
              placeholder="for example U105"
            />
          </label>
          <button type="submit">Filter</button>
          {userId && (
            <button
              type="button"
              className="ghost"
              onClick={() => {
                setUserInput("");
                setUserId("");
                setPage(0);
              }}
            >
              Clear
            </button>
          )}
        </form>
        <ErrorBox message={events.error} />

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>User</th>
                <th>Source IP</th>
                <th>Status</th>
                <th>Location / port</th>
              </tr>
            </thead>
            <tbody>
              {data?.items.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    No events yet. Publish the detection output first.
                  </td>
                </tr>
              )}
              {data?.items.map((e) => (
                <tr key={e.eventId}>
                  <td className="mono">{formatTime(e.occurredAt)}</td>
                  <td>{e.eventType}</td>
                  <td className="mono">{e.userId}</td>
                  <td className="mono">{e.sourceIp}</td>
                  <td>{e.status}</td>
                  <td>
                    {e.location || "-"}
                    {e.destinationPort ? `:${e.destinationPort}` : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {data && (
          <div className="page-head">
            <span className="muted">
              {data.totalItems} events, page {data.page + 1} of {Math.max(data.totalPages, 1)}
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