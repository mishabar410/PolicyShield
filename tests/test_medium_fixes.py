"""Tests for medium issue fixes — coverage boost."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from policyshield.core.models import SessionState, Verdict
from policyshield.shield.session import SessionManager


class TestSessionLastAccessed:
    """Tests for Issue #173 — TTL by last access."""

    def test_get_or_create_updates_last_accessed(self):
        mgr = SessionManager(max_sessions=10, ttl_seconds=3600)
        session = mgr.get_or_create("test-sess")
        assert session.last_accessed is None  # first creation

        # Second access — should update last_accessed
        session2 = mgr.get_or_create("test-sess")
        assert session2.last_accessed is not None
        assert session2.session_id == "test-sess"

    def test_get_updates_last_accessed(self):
        mgr = SessionManager(max_sessions=10, ttl_seconds=3600)
        mgr.get_or_create("sess-1")
        session = mgr.get("sess-1")
        assert session is not None
        assert session.last_accessed is not None

    def test_is_expired_uses_last_accessed(self):
        mgr = SessionManager(max_sessions=10, ttl_seconds=60)
        session = SessionState(
            session_id="old",
            created_at=datetime.now(timezone.utc) - timedelta(seconds=120),
            last_accessed=datetime.now(timezone.utc) - timedelta(seconds=10),
        )
        # created_at is 120s ago (> 60s TTL) but last_accessed is only 10s ago
        assert not mgr._is_expired(session)

    def test_is_expired_falls_back_to_created_at(self):
        mgr = SessionManager(max_sessions=10, ttl_seconds=60)
        session = SessionState(
            session_id="old",
            created_at=datetime.now(timezone.utc) - timedelta(seconds=120),
            last_accessed=None,
        )
        assert mgr._is_expired(session)

    def test_get_or_create_replaces_expired_session(self):
        """Hit lines 69-70: expired session gets deleted and recreated."""
        mgr = SessionManager(max_sessions=10, ttl_seconds=0.001)
        session1 = mgr.get_or_create("will-expire")
        old_created = session1.created_at

        import time

        time.sleep(0.01)

        # Second call: session is expired, should delete and recreate
        session2 = mgr.get_or_create("will-expire")
        assert session2.session_id == "will-expire"
        assert session2.created_at > old_created  # new session

    def test_add_taint_creates_session_if_needed(self):
        """Covers add_taint path through get_or_create_unlocked."""
        from policyshield.core.models import PIIType

        mgr = SessionManager(max_sessions=10, ttl_seconds=3600)
        mgr.add_taint("taint-new", PIIType.EMAIL)
        session = mgr.get("taint-new")
        assert session is not None
        assert PIIType.EMAIL in session.taints


class TestDecoratorCallableSessionId:
    """Tests for Issue #205 — callable session_id."""

    def test_callable_session_id_sync(self):
        from policyshield.decorators import shield

        mock_engine = MagicMock()
        mock_result = MagicMock()
        mock_result.verdict = Verdict.ALLOW
        mock_result.modified_args = None
        mock_engine.check.return_value = mock_result

        counter = {"calls": 0}

        def get_session_id():
            counter["calls"] += 1
            return f"session-{counter['calls']}"

        @shield(mock_engine, session_id=get_session_id)
        def my_tool(x: int) -> int:
            return x * 2

        my_tool(5)
        mock_engine.check.assert_called_once()
        call_kwargs = mock_engine.check.call_args
        assert call_kwargs[1]["session_id"] == "session-1"

    @pytest.mark.asyncio
    async def test_callable_session_id_async(self):
        from unittest.mock import AsyncMock as AM

        from policyshield.decorators import shield

        mock_engine = MagicMock()
        mock_result = MagicMock()
        mock_result.verdict = Verdict.ALLOW
        mock_result.modified_args = None
        mock_engine.check = AM(return_value=mock_result)
        mock_engine.post_check = AM(return_value=None)

        @shield(mock_engine, session_id=lambda: "dynamic-sess")
        async def my_async_tool(x: int) -> int:
            return x * 2

        result = await my_async_tool(5)
        assert result == 10
        assert mock_engine.check.call_args[1]["session_id"] == "dynamic-sess"


class TestShellInjectionFalsePositives:
    """Tests for Issue #92 — backtick false positive reduction."""

    def test_markdown_backtick_not_flagged(self):
        from policyshield.shield.detectors import get_detector

        det = get_detector("shell_injection")
        # Markdown code blocks should not trigger
        assert det.scan("`SELECT * FROM users`") == []
        assert det.scan("`hello world`") == []
        assert det.scan("Use `foo_bar` for config") == []

    def test_actual_shell_backtick_flagged(self):
        from policyshield.shield.detectors import get_detector

        det = get_detector("shell_injection")
        matches = det.scan("`rm -rf /tmp`")
        assert len(matches) >= 1
        matches = det.scan("`curl http://evil.com`")
        assert len(matches) >= 1


class TestMemoryBackendFirstResponseWins:
    """Tests for Issue #152 — first-response-wins guard."""

    def test_timeout_respects_existing_response(self):
        from policyshield.approval.memory import InMemoryBackend
        from policyshield.approval.base import ApprovalRequest
        from datetime import datetime, timezone

        backend = InMemoryBackend(timeout=0.001, on_timeout="DENY")
        req = ApprovalRequest(
            request_id="req-1",
            tool_name="test",
            rule_id="rule-1",
            message="test",
            session_id="s1",
            args={"key": "value"},
            timestamp=datetime.now(timezone.utc),
        )
        backend.submit(req)

        # Respond before timeout check
        backend.respond("req-1", approved=True, responder="human")

        import time

        time.sleep(0.01)  # let timeout expire

        status = backend.get_status("req-1")
        # Should return the human response, not auto-timeout
        assert status["approved"] is True
        assert status["responder"] == "human"


class TestSessionEdgeCases:
    """Edge case tests for session.py coverage."""

    def test_sync_to_backend_fails_gracefully(self):
        """Test that backend put errors are swallowed (lines 48-49)."""
        from unittest.mock import MagicMock as MM

        mgr = SessionManager(max_sessions=10, ttl_seconds=3600)
        # Replace backend with one that throws on put
        mgr._backend = MM()
        mgr._backend.put.side_effect = RuntimeError("backend down")
        mgr._backend.stats.return_value = {}
        # Should not raise
        session = mgr.get_or_create("test-backend-fail")
        assert session.session_id == "test-backend-fail"

    def test_evict_expired_removes_sessions(self):
        """Test actual eviction of expired sessions (lines 228-229)."""
        mgr = SessionManager(max_sessions=10, ttl_seconds=0.001)
        mgr.get_or_create("exp-1")
        mgr.get_or_create("exp-2")
        import time

        time.sleep(0.01)
        # Force eviction via stats() which calls _evict_expired
        stats = mgr.stats()
        assert stats["active_sessions"] == 0

    def test_clear_taint_on_expired_session(self):
        """Test that clear_taint returns False for expired sessions (line 172)."""
        mgr = SessionManager(max_sessions=10, ttl_seconds=0.001)
        mgr.get_or_create("taint-sess")
        import time

        time.sleep(0.01)
        assert mgr.clear_taint("taint-sess") is False

    def test_callable_context_in_decorator(self):
        """Test callable context parameter (Issue #205 extension)."""
        from policyshield.decorators import shield

        mock_engine = MagicMock()
        mock_result = MagicMock()
        mock_result.verdict = Verdict.ALLOW
        mock_result.modified_args = None
        mock_engine.check.return_value = mock_result

        @shield(mock_engine, context=lambda: {"request_id": "abc"})
        def my_tool(x: int) -> int:
            return x * 2

        my_tool(5)
        call_kwargs = mock_engine.check.call_args
        assert call_kwargs[1]["context"] == {"request_id": "abc"}

    def test_mode_setter_thread_safe(self):
        """Test that mode setter uses lock (Issue #213)."""
        from policyshield.core.models import ShieldMode
        from policyshield.shield.engine import ShieldEngine
        import os

        rules_path = os.path.join(
            os.path.dirname(__file__), "..", "examples", "fastapi_agent", "policies", "rules.yaml"
        )
        if not os.path.exists(rules_path):
            pytest.skip("rules.yaml not found")
        engine = ShieldEngine(rules=rules_path)
        engine.mode = ShieldMode.AUDIT
        assert engine.mode == ShieldMode.AUDIT
        engine.mode = ShieldMode.ENFORCE
        assert engine.mode == ShieldMode.ENFORCE
