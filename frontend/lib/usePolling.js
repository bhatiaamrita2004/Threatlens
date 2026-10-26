"use client";

import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Loads data now, then again every intervalMs while "live" is on. Pass deps (for example
 * filter values) to reload immediately when they change.
 *
 * This is polling, not push. It is simple and reliable for a dashboard that refreshes every
 * few seconds. Server-sent events can replace it later without changing the pages.
 */
export function usePolling(fetcher, intervalMs = 5000, deps = []) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [live, setLive] = useState(true);
  const [updatedAt, setUpdatedAt] = useState(null);

  // Always call the latest fetcher, so filters captured in the closure stay current.
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const reload = useCallback(async () => {
    try {
      const result = await fetcherRef.current();
      setData(result);
      setError(null);
      setUpdatedAt(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reload, ...deps]);

  useEffect(() => {
    if (!live) return undefined;
    const timer = setInterval(reload, intervalMs);
    return () => clearInterval(timer);
  }, [live, reload, intervalMs]);

  return { data, error, loading, live, setLive, updatedAt, reload };
}