"""Additional coverage boost tests for session and approval modules."""

from __future__ import annotations

from datetime import datetime, timezone


from policyshield.core.models import PIIType, SessionState
from policyshield.shield.session import SessionManager


class TestSessionManagerAdditional:
    def test_record_call_atomic(self):
        mgr = SessionManager(ttl_seconds=60, max_sessions=10)
        s = mgr.record_call("sess1", "tool_a")
        assert s.total_calls == 1
        assert s.tool_counts["tool_a"] == 1

    def test_increment_delegates(self):
        mgr = SessionManager(ttl_seconds=60, max_sessions=10)
        s = mgr.increment("sess1", "tool_b")
        assert s.total_calls == 1

    def test_add_taint(self):
        mgr = SessionManager(ttl_seconds=60, max_sessions=10)
        mgr.add_taint("sess1", PIIType.EMAIL)
        s = mgr.get("sess1")
        assert s is not None
        assert PIIType.EMAIL in s.taints

    def test_remove_existing(self):
        mgr = SessionManager(ttl_seconds=60, max_sessions=10)
        mgr.get_or_create("sess1")
        assert mgr.remove("sess1") is True
        assert mgr.get("sess1") is None

    def test_remove_nonexistent(self):
        mgr = SessionManager(ttl_seconds=60, max_sessions=10)
        assert mgr.remove("nope") is False

    def test_event_buffer_created(self):
        mgr = SessionManager(ttl_seconds=60, max_sessions=10)
        buf = mgr.get_event_buffer("sess1")
        assert buf is not None

    def test_stats(self):
        mgr = SessionManager(ttl_seconds=60, max_sessions=10)
        mgr.get_or_create("s1")
        mgr.get_or_create("s2")
        stats = mgr.stats()
        assert stats["active_sessions"] == 2
        assert stats["max_sessions"] == 10

    def test_serialize_session(self):
        mgr = SessionManager()
        s = SessionState(session_id="test", created_at=datetime.now(timezone.utc))
        data = mgr._serialize_session(s)
        assert data["session_id"] == "test"
        assert "created_at" in data


class TestApprovalBackendCoverage:
    def test_in_memory_submit_and_poll(self):
        from policyshield.approval.memory import InMemoryBackend
        from policyshield.approval.base import ApprovalRequest

        backend = InMemoryBackend()
        req = ApprovalRequest.create(
            tool_name="tool_a", args={"arg": 1}, rule_id="test_rule", message="test", session_id="s1"
        )
        backend.submit(req)
        status = backend.get_status(req.request_id)
        assert status["status"] == "pending"

    def test_in_memory_resolve(self):
        from policyshield.approval.memory import InMemoryBackend
        from policyshield.approval.base import ApprovalRequest

        backend = InMemoryBackend()
        req = ApprovalRequest.create(tool_name="tool_a", args={}, rule_id="test_rule", message="test", session_id="s1")
        backend.submit(req)
        backend.respond(req.request_id, approved=True, responder="test")
        status = backend.get_status(req.request_id)
        assert status["status"] == "approved"

    def test_in_memory_reject(self):
        from policyshield.approval.memory import InMemoryBackend
        from policyshield.approval.base import ApprovalRequest

        backend = InMemoryBackend()
        req = ApprovalRequest.create(tool_name="tool_a", args={}, rule_id="test_rule", message="test", session_id="s1")
        backend.submit(req)
        backend.respond(req.request_id, approved=False, responder="test")
        status = backend.get_status(req.request_id)
        assert status["status"] == "denied"
