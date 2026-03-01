"""Tests for session storage backends."""

from __future__ import annotations

from unittest.mock import patch

from policyshield.shield.session_backend import InMemorySessionBackend, _now_ts


# ---------------------------------------------------------------------------
# InMemorySessionBackend
# ---------------------------------------------------------------------------


class TestInMemorySessionBackend:
    def test_put_and_get(self):
        backend = InMemorySessionBackend(max_size=100, ttl_seconds=3600)
        backend.put("s1", {"user": "alice"})
        assert backend.get("s1") == {"user": "alice"}

    def test_get_missing(self):
        backend = InMemorySessionBackend()
        assert backend.get("nonexistent") is None

    def test_delete(self):
        backend = InMemorySessionBackend()
        backend.put("s1", {"user": "alice"})
        backend.delete("s1")
        assert backend.get("s1") is None

    def test_count(self):
        backend = InMemorySessionBackend()
        backend.put("s1", {"a": 1})
        backend.put("s2", {"b": 2})
        assert backend.count() == 2

    def test_lru_eviction_at_capacity(self):
        backend = InMemorySessionBackend(max_size=3, ttl_seconds=3600)
        backend.put("s1", {"a": 1})
        backend.put("s2", {"b": 2})
        backend.put("s3", {"c": 3})
        # s1 is oldest (LRU) — should be evicted
        backend.put("s4", {"d": 4})
        assert backend.get("s1") is None
        assert backend.get("s2") is not None
        assert backend.count() == 3
        assert backend.evictions == 1

    def test_lru_touch_prevents_eviction(self):
        backend = InMemorySessionBackend(max_size=3, ttl_seconds=3600)
        backend.put("s1", {"a": 1})
        backend.put("s2", {"b": 2})
        backend.put("s3", {"c": 3})
        # Touch s1 — now s2 is the oldest
        backend.get("s1")
        backend.put("s4", {"d": 4})
        assert backend.get("s1") is not None  # survived
        assert backend.get("s2") is None  # evicted instead

    def test_ttl_expiry(self):
        backend = InMemorySessionBackend(max_size=100, ttl_seconds=1)
        backend.put("s1", {"a": 1})
        assert backend.get("s1") is not None

        # Simulate time passing
        with patch(
            "policyshield.shield.session_backend._now_ts",
            return_value=_now_ts() + 2,
        ):
            assert backend.get("s1") is None

    def test_hit_miss_counters(self):
        backend = InMemorySessionBackend()
        backend.put("s1", {"a": 1})
        backend.get("s1")  # hit
        backend.get("s1")  # hit
        backend.get("nonexistent")  # miss
        assert backend.hits == 2
        assert backend.misses == 1

    def test_stats(self):
        backend = InMemorySessionBackend(max_size=50, ttl_seconds=1800)
        backend.put("s1", {"a": 1})
        backend.get("s1")
        backend.get("miss")
        stats = backend.stats()
        assert stats["backend"] == "memory"
        assert stats["active_sessions"] == 1
        assert stats["max_sessions"] == 50
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_ratio"] == 0.5

    def test_upsert_existing(self):
        backend = InMemorySessionBackend()
        backend.put("s1", {"v": 1})
        backend.put("s1", {"v": 2})
        assert backend.get("s1") == {"v": 2}
        assert backend.count() == 1

    def test_total_created(self):
        backend = InMemorySessionBackend()
        backend.put("s1", {"a": 1})
        backend.put("s2", {"b": 2})
        backend.put("s1", {"a": 3})  # update, not create
        assert backend.total_created == 2


# ---------------------------------------------------------------------------
# SessionManager integration with backend
# ---------------------------------------------------------------------------


class TestSessionManagerWithBackend:
    def test_default_backend_is_memory(self):
        """SessionManager should use InMemorySessionBackend by default."""
        from policyshield.shield.session import SessionManager

        mgr = SessionManager(ttl_seconds=300, max_sessions=50)
        assert isinstance(mgr._backend, InMemorySessionBackend)

    def test_custom_backend(self):
        """SessionManager should accept a custom backend."""
        from policyshield.shield.session import SessionManager

        custom = InMemorySessionBackend(max_size=5, ttl_seconds=60)
        mgr = SessionManager(ttl_seconds=300, max_sessions=50, backend=custom)
        assert mgr._backend is custom

    def test_stats_include_backend(self):
        """SessionManager.stats() should include backend stats."""
        from policyshield.shield.session import SessionManager

        mgr = SessionManager(ttl_seconds=300, max_sessions=50)
        stats = mgr.stats()
        assert "backend" in stats
        assert stats["backend"]["backend"] == "memory"


# ---------------------------------------------------------------------------
# RedisSessionBackend (mocked)
# ---------------------------------------------------------------------------


class TestRedisSessionBackendMocked:
    def _make_backend(self):
        """Create a RedisSessionBackend with a mocked redis client."""
        from unittest.mock import MagicMock

        from policyshield.shield.session_backend import RedisSessionBackend

        # Patch the import inside __init__
        with patch.dict("sys.modules", {"redis": MagicMock()}):
            backend = RedisSessionBackend.__new__(RedisSessionBackend)
            backend._client = MagicMock()
            backend._ttl = 3600
            backend._prefix = "ps:session:"
        return backend

    def test_get_found(self):
        backend = self._make_backend()
        backend._client.get.return_value = '{"user": "alice"}'
        result = backend.get("s1")
        assert result == {"user": "alice"}

    def test_get_not_found(self):
        backend = self._make_backend()
        backend._client.get.return_value = None
        assert backend.get("s1") is None

    def test_get_corrupt_data(self):
        backend = self._make_backend()
        backend._client.get.return_value = "not json"
        assert backend.get("s1") is None
        backend._client.delete.assert_called()

    def test_put(self):
        backend = self._make_backend()
        backend.put("s1", {"user": "alice"})
        backend._client.setex.assert_called_once()

    def test_delete(self):
        backend = self._make_backend()
        backend.delete("s1")
        backend._client.delete.assert_called_once()

    def test_count_single_page(self):
        backend = self._make_backend()
        backend._client.scan.return_value = (0, ["ps:session:s1", "ps:session:s2"])
        assert backend.count() == 2

    def test_count_multi_page(self):
        backend = self._make_backend()
        backend._client.scan.side_effect = [
            (1, ["ps:session:s1"]),
            (0, ["ps:session:s2"]),
        ]
        assert backend.count() == 2

    def test_stats(self):
        backend = self._make_backend()
        backend._client.scan.return_value = (0, [])
        stats = backend.stats()
        assert stats["backend"] == "redis"
        assert "active_sessions" in stats

    def test_key_prefix(self):
        backend = self._make_backend()
        assert backend._key("test") == "ps:session:test"
