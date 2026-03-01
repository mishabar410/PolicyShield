"""Session storage backends for PolicyShield.

Provides pluggable session storage with two built-in implementations:

- :class:`InMemorySessionBackend` — thread-safe ``OrderedDict`` with O(1) LRU
  eviction and TTL.  Default backend, suitable for single-process deployments.
- :class:`RedisSessionBackend` — distributed session storage via Redis.
  Requires the ``redis`` package (``pip install policyshield[redis]``).
"""

from __future__ import annotations

import json
import logging
import threading
from abc import ABC, abstractmethod
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("policyshield")


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------


class SessionBackend(ABC):
    """Abstract session storage backend."""

    @abstractmethod
    def get(self, session_id: str) -> dict | None:
        """Get session data, or ``None`` if not found / expired."""

    @abstractmethod
    def put(self, session_id: str, data: dict) -> None:
        """Store session data (upsert)."""

    @abstractmethod
    def delete(self, session_id: str) -> None:
        """Delete a session."""

    @abstractmethod
    def count(self) -> int:
        """Number of active sessions."""

    @abstractmethod
    def stats(self) -> dict:
        """Return backend statistics."""


# ---------------------------------------------------------------------------
# In-memory (default)
# ---------------------------------------------------------------------------


class InMemorySessionBackend(SessionBackend):
    """Thread-safe in-memory backend with O(1) LRU + TTL.

    Uses :class:`collections.OrderedDict` so that ``move_to_end`` + ``popitem``
    give genuine O(1) eviction.

    Args:
        max_size: Maximum number of sessions to keep.
        ttl_seconds: Time-to-live for each session (seconds).
    """

    def __init__(self, max_size: int = 10_000, ttl_seconds: int = 3600) -> None:
        self._store: OrderedDict[str, tuple[dict, float]] = OrderedDict()
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._lock = threading.Lock()

        # Counters
        self.evictions: int = 0
        self.hits: int = 0
        self.misses: int = 0
        self.total_created: int = 0

    # --- public API ---

    def get(self, session_id: str) -> dict | None:  # noqa: D401
        with self._lock:
            entry = self._store.get(session_id)
            if entry is None:
                self.misses += 1
                return None
            data, ts = entry
            if self._is_expired(ts):
                del self._store[session_id]
                self.misses += 1
                return None
            self._store.move_to_end(session_id)  # LRU touch
            self.hits += 1
            return data

    def put(self, session_id: str, data: dict) -> None:
        with self._lock:
            if session_id in self._store:
                self._store.move_to_end(session_id)
            else:
                self.total_created += 1
            self._store[session_id] = (data, _now_ts())
            # Evict LRU entries if over capacity
            while len(self._store) > self._max_size:
                self._store.popitem(last=False)
                self.evictions += 1

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._store.pop(session_id, None)

    def count(self) -> int:
        return len(self._store)

    def stats(self) -> dict:
        total_requests = self.hits + self.misses
        return {
            "backend": "memory",
            "active_sessions": self.count(),
            "max_sessions": self._max_size,
            "ttl_seconds": self._ttl_seconds,
            "evictions": self.evictions,
            "total_created": self.total_created,
            "hits": self.hits,
            "misses": self.misses,
            "hit_ratio": round(self.hits / total_requests, 3) if total_requests else 0.0,
        }

    # --- internals ---

    def _is_expired(self, ts: float) -> bool:
        return (_now_ts() - ts) > self._ttl_seconds


# ---------------------------------------------------------------------------
# Redis backend
# ---------------------------------------------------------------------------


class RedisSessionBackend(SessionBackend):
    """Redis-backed session storage for distributed deployments.

    Sessions are stored as JSON strings with Redis TTL for auto-expiry.
    Requires the ``redis`` package.

    Args:
        redis_url: Redis connection URL.
        ttl_seconds: Time-to-live for each session (seconds).
        key_prefix: Prefix for all Redis keys.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        ttl_seconds: int = 3600,
        key_prefix: str = "ps:session:",
    ) -> None:
        try:
            import redis as _redis  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "RedisSessionBackend requires the 'redis' package. "
                "Install with: pip install policyshield[redis]"
            ) from exc

        self._client = _redis.from_url(redis_url, decode_responses=True)
        self._ttl = ttl_seconds
        self._prefix = key_prefix

    def _key(self, session_id: str) -> str:
        return f"{self._prefix}{session_id}"

    def get(self, session_id: str) -> dict | None:  # noqa: D401
        raw = self._client.get(self._key(session_id))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Corrupt session data for %s", session_id)
            self._client.delete(self._key(session_id))
            return None

    def put(self, session_id: str, data: dict) -> None:
        self._client.setex(
            self._key(session_id),
            self._ttl,
            json.dumps(data, default=str),
        )

    def delete(self, session_id: str) -> None:
        self._client.delete(self._key(session_id))

    def count(self) -> int:
        cursor, keys = self._client.scan(0, match=f"{self._prefix}*", count=100)
        total = len(keys)
        while cursor:
            cursor, keys = self._client.scan(cursor, match=f"{self._prefix}*", count=100)
            total += len(keys)
        return total

    def stats(self) -> dict:
        return {
            "backend": "redis",
            "active_sessions": self.count(),
            "ttl_seconds": self._ttl,
            "key_prefix": self._prefix,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_ts() -> float:
    """Monotonic-safe timestamp for TTL calculations."""
    return datetime.now(timezone.utc).timestamp()
