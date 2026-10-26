"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { clearSession, getToken, getUser } from "../lib/api";

export const BANDS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const NAV = [
  { href: "/dashboard", label: "Overview" },
  { href: "/alerts", label: "Alerts" },
  { href: "/events", label: "Events" },
];

/** Page frame. Redirects to /login when there is no session token. */
export function Shell({ children }) {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (!getToken()) {
      router.replace("/login");
      return;
    }
    setUser(getUser());
    setReady(true);
  }, [router]);

  function logout() {
    clearSession();
    router.replace("/login");
  }

  if (!ready) {
    return <p className="muted pad">Checking session...</p>;
  }

  return (
    <>
      <header className="topbar">
        <div className="brand">ThreatLens</div>
        <nav>
          {NAV.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={pathname.startsWith(item.href) ? "active" : undefined}
            >
              {item.label}
            </Link>
          ))}
        </nav>
        <div className="who">
          <span className="muted">
            {user ? `${user.username} (${user.role})` : ""}
          </span>
          <button className="ghost" onClick={logout}>
            Log out
          </button>
        </div>
      </header>
      <main className="container">{children}</main>
    </>
  );
}

export function SeverityBadge({ value }) {
  const key = (value || "none").toLowerCase();
  return <span className={`badge sev-${key}`}>{value || "-"}</span>;
}

export function Card({ title, right, children }) {
  return (
    <section className="card">
      {(title || right) && (
        <div className="card-head">
          {title && <h2>{title}</h2>}
          {right && <div>{right}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, tone }) {
  return (
    <div className={`stat ${tone ? `tone-${tone}` : ""}`}>
      <div className="stat-value">{value ?? "-"}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

export function ErrorBox({ message }) {
  if (!message) return null;
  return <div className="error">{message}</div>;
}

/** Shows whether the page is refreshing itself, and lets the analyst pause or refresh now. */
export function LiveControl({ live, setLive, updatedAt, reload }) {
  return (
    <div className="live">
      <span className="muted">
        {updatedAt ? `Updated ${updatedAt.toLocaleTimeString()}` : "Loading..."}
      </span>
      <button className="ghost" onClick={reload}>
        Refresh
      </button>
      <button className="ghost" onClick={() => setLive(!live)}>
        {live ? "Pause live" : "Go live"}
      </button>
    </div>
  );
}

export function formatTime(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleString();
}