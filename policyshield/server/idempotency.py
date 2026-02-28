"""Idempotency cache for API requests."""

from __future__ import annotations

import threading
from collections import OrderedDict
from time import monotonic


class IdempotencyCache:
    """TTL + size-bounded cache for idempotent API responses."""

    _EVICT_EVERY_N = 100  # Check for stale entries every N inserts

    def __init__(self, max_size: int = 10_000, ttl: float = 300.0) -> None:
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl
        self._lock = threading.Lock()
        self._inserts_since_eviction = 0

    def get(self, key: str) -> dict | None:
        with self._lock:
            if key in self._cache:
                ts, result = self._cache[key]
                if monotonic() - ts < self._ttl:
                    return result
                del self._cache[key]
        return None

    def set(self, key: str, result: dict) -> None:
        with self._lock:
            self._cache[key] = (monotonic(), result)
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)
            # Periodically evict expired entries
            self._inserts_since_eviction += 1
            if self._inserts_since_eviction >= self._EVICT_EVERY_N:
                self._inserts_since_eviction = 0
                now = monotonic()
                stale = [k for k, (ts, _) in self._cache.items() if now - ts >= self._ttl]
                for k in stale:
                    del self._cache[k]
