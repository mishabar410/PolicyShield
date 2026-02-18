"""Simple in-memory rate limiter for admin endpoints."""

from __future__ import annotations

import threading
from collections import defaultdict
from time import monotonic


class InMemoryRateLimiter:
    """Sliding window rate limiter per key."""

    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        now = monotonic()
        with self._lock:
            self._requests[key] = [t for t in self._requests[key] if now - t < self._window]
            if len(self._requests[key]) >= self._max:
                return False
            self._requests[key].append(now)
            # Prune stale keys to prevent unbounded memory growth
            stale = [k for k, v in self._requests.items() if k != key and not v]
            for k in stale:
                del self._requests[k]
            return True


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
