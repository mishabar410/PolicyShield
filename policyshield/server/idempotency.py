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

    @staticmethod
    def _validate_key(key: str) -> None:
        if len(key.encode()) > 128:
            raise ValueError("Idempotency key exceeds 128 bytes")
        if any(c < " " for c in key):
            raise ValueError("Idempotency key contains non-printable characters")

    def get(self, key: str) -> dict | None:
        self._validate_key(key)
        with self._lock:
            if key in self._cache:
                ts, result = self._cache[key]
                if monotonic() - ts >= self._ttl:
                    del self._cache[key]
                    return None
                return result
        return None

    def set(self, key: str, result: dict) -> None:
        self._validate_key(key)
        with self._lock:
            self._cache[key] = (monotonic(), result)
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)
            # Periodically evict expired entries
            self._inserts_since_eviction += 1
            if self._inserts_since_eviction >= self._EVICT_EVERY_N:
                self._inserts_since_eviction = 0
                now = monotonic()
                stale = [
                    k for k, (ts, _) in self._cache.items() if now - ts >= self._ttl
                ]
                for k in stale:
                    del self._cache[k]
