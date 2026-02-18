"""Idempotency cache for API requests."""

from __future__ import annotations

import threading
from collections import OrderedDict
from time import monotonic


class IdempotencyCache:
    """TTL + size-bounded cache for idempotent API responses."""

    def __init__(self, max_size: int = 10_000, ttl: float = 300.0) -> None:
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl
        self._lock = threading.Lock()

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
