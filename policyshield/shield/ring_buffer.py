"""Fixed-size ring buffer for temporal event tracking."""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class ToolEvent:
    """A recorded tool call event."""

    tool: str
    timestamp: datetime
    verdict: str
    args_summary: str = ""  # Truncated repr of args for debugging


class EventRingBuffer:
    """Fixed-size ring buffer for tool call events.

    Uses collections.deque with maxlen for O(1) append.
    Thread-safe: all mutations and reads are protected by a lock.
    """

    def __init__(self, max_size: int = 100) -> None:
        self._buffer: deque[ToolEvent] = deque(maxlen=max_size)
        self._lock = threading.Lock()

    def add(self, tool: str, verdict: str, args_summary: str = "") -> None:
        """Record a tool event."""
        event = ToolEvent(
            tool=tool,
            timestamp=datetime.now(timezone.utc),
            verdict=verdict,
            args_summary=args_summary[:200],  # Truncate args
        )
        with self._lock:
            self._buffer.append(event)

    def find_recent(
        self,
        tool: str,
        *,
        within_seconds: float | None = None,
        verdict: str | None = None,
    ) -> list[ToolEvent]:
        """Find recent events matching criteria.

        Returns matching events in chronological order (oldest first).

        Args:
            tool: Tool name to search for.
            within_seconds: Only events within this many seconds from now.
            verdict: Filter by verdict.

        Returns:
            List of matching events (oldest first).
        """
        now = datetime.now(timezone.utc)
        # Snapshot under lock, filter outside
        with self._lock:
            events = list(self._buffer)
        results = []
        for event in events:
            if event.tool != tool:
                continue
            if verdict is not None and event.verdict != verdict:
                continue
            if within_seconds is not None:
                age = (now - event.timestamp).total_seconds()
                if age > within_seconds:
                    continue
            results.append(event)
        return results

    def has_recent(
        self,
        tool: str,
        *,
        within_seconds: float | None = None,
        verdict: str | None = None,
    ) -> bool:
        """Check if a tool was called recently.

        Args:
            tool: Tool name to search for.
            within_seconds: Only events within this many seconds.
            verdict: Filter by verdict (e.g. "BLOCK", "ALLOW").
        """
        return len(self.find_recent(tool, within_seconds=within_seconds, verdict=verdict)) > 0

    @property
    def events(self) -> list[ToolEvent]:
        """Return all events in order (oldest first)."""
        with self._lock:
            return list(self._buffer)

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()
