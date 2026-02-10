"""Tests for session manager."""

import threading
import time

import pytest

from policyshield.core.models import PIIType
from policyshield.shield.session import SessionManager


class TestSessionManager:
    @pytest.fixture
    def manager(self):
        return SessionManager(ttl_seconds=3600, max_sessions=10)

    def test_get_or_create_new(self, manager):
        session = manager.get_or_create("s1")
        assert session.session_id == "s1"
        assert session.total_calls == 0

    def test_get_or_create_existing(self, manager):
        s1 = manager.get_or_create("s1")
        s1.increment("exec")
        s2 = manager.get_or_create("s1")
        assert s2.total_calls == 1  # Same session

    def test_get_missing(self, manager):
        assert manager.get("nonexistent") is None

    def test_get_existing(self, manager):
        manager.get_or_create("s1")
        assert manager.get("s1") is not None

    def test_increment(self, manager):
        session = manager.increment("s1", "exec")
        assert session.tool_counts["exec"] == 1
        assert session.total_calls == 1

        session = manager.increment("s1", "exec")
        assert session.tool_counts["exec"] == 2
        assert session.total_calls == 2

    def test_add_taint(self, manager):
        manager.get_or_create("s1")
        manager.add_taint("s1", PIIType.EMAIL)
        session = manager.get("s1")
        assert PIIType.EMAIL in session.taints

    def test_remove(self, manager):
        manager.get_or_create("s1")
        assert manager.remove("s1") is True
        assert manager.get("s1") is None
        assert manager.remove("s1") is False

    def test_stats(self, manager):
        manager.get_or_create("s1")
        manager.get_or_create("s2")
        stats = manager.stats()
        assert stats["active_sessions"] == 2
        assert stats["max_sessions"] == 10
        assert stats["ttl_seconds"] == 3600

    def test_ttl_expiry(self):
        manager = SessionManager(ttl_seconds=0, max_sessions=10)
        manager.get_or_create("s1")
        time.sleep(0.01)
        assert manager.get("s1") is None

    def test_max_sessions_eviction(self):
        manager = SessionManager(ttl_seconds=3600, max_sessions=3)
        manager.get_or_create("s1")
        manager.get_or_create("s2")
        manager.get_or_create("s3")
        # Adding s4 should evict s1 (oldest)
        manager.get_or_create("s4")
        stats = manager.stats()
        assert stats["active_sessions"] == 3
        assert manager.get("s1") is None

    def test_thread_safety(self, manager):
        """Test concurrent access from multiple threads."""
        errors = []

        def worker(session_id):
            try:
                for _ in range(100):
                    manager.increment(session_id, "tool")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f"s{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        for i in range(5):
            session = manager.get(f"s{i}")
            assert session is not None
            assert session.total_calls == 100
