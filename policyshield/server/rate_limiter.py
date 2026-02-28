"""Simple in-memory rate limiter for admin endpoints."""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from time import monotonic


class InMemoryRateLimiter:
    """Sliding window rate limiter per key.

    Uses deque for O(1) amortized expired-entry cleanup.
    Periodically evicts stale keys to prevent unbounded memory growth.
    """

    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_cleanup = 0.0
        self._cleanup_interval = max(60.0, window_seconds * 2)

    def is_allowed(self, key: str) -> bool:
        now = monotonic()
        with self._lock:
            self._maybe_cleanup(now)
            dq = self._requests[key]
            cutoff = now - self._window
            # O(1) amortized — pop expired from left
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= self._max:
                return False
            dq.append(now)
            return True

    def _maybe_cleanup(self, now: float) -> None:
        """Remove stale keys to prevent unbounded memory growth."""
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        stale_keys = [
            k for k, dq in self._requests.items()
            if not dq or (now - dq[-1]) > self._window * 2
        ]
        for k in stale_keys:
            del self._requests[k]


class APIRateLimiter:
    """Rate limiter for HTTP API endpoints."""

    def __init__(
        self,
        max_requests: int = 100,
        window_seconds: float = 60.0,
    ) -> None:
        self._max_requests = max_requests
        self._window = window_seconds
        self._limiter = InMemoryRateLimiter(max_requests=max_requests, window_seconds=window_seconds)

    def is_allowed(self, key: str) -> bool:
        return self._limiter.is_allowed(key)

    @property
    def limit_info(self) -> dict:
        return {"max_requests": self._max_requests, "window_seconds": self._window}

