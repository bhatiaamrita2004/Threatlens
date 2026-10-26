"""Time-window helpers shared by the rules.

TimeWindow keeps the items seen in the last N seconds.
find_bursts() finds periods where a metric over that window reaches a
threshold, grouped by a key such as user or source IP.
"""

from __future__ import annotations

from collections import deque
from datetime import timedelta
from typing import Callable, Iterator


class TimeWindow:
    """Holds (timestamp, item) pairs no older than `seconds` before the newest one."""

    def __init__(self, seconds: float) -> None:
        self.span = timedelta(seconds=seconds)
        self._items: deque = deque()

    def add(self, timestamp, item) -> None:
        # Items must be added in timestamp order.
        self._items.append((timestamp, item))
        cutoff = timestamp - self.span
        while self._items and self._items[0][0] < cutoff:
            self._items.popleft()

    def values(self) -> list:
        return [item for _, item in self._items]

    def __len__(self) -> int:
        return len(self._items)


def find_bursts(
    events: list,
    group_key: Callable,
    metric: Callable[[list], float],
    threshold: float,
    window_seconds: float,
) -> Iterator[tuple]:
    """Yield (key, run_events, peak_value) for each burst found.

    A burst starts when metric(events in window) >= threshold and ends when
    it drops below the threshold. Consecutive qualifying events form one
    burst, so a long attack produces one alert instead of one per event.
    """
    groups: dict = {}
    for event in events:
        groups.setdefault(group_key(event), []).append(event)

    for key, group in groups.items():
        group.sort(key=lambda e: e.timestamp)
        window = TimeWindow(window_seconds)
        run: list | None = None
        peak = 0

        for event in group:
            window.add(event.timestamp, event)
            value = metric(window.values())
            if value >= threshold:
                if run is None:
                    run = window.values()  # the whole window is part of the burst
                else:
                    run.append(event)
                peak = max(peak, value)
            elif run is not None:
                yield key, run, peak
                run, peak = None, 0

        if run is not None:
            yield key, run, peak