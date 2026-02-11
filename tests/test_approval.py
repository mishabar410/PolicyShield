"""Tests for approval backends and ShieldEngine integration."""

from __future__ import annotations

import io
import threading


from policyshield.approval import (
    ApprovalRequest,
    CLIBackend,
    InMemoryBackend,
)
from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.shield.engine import ShieldEngine


def _make_request(**overrides) -> ApprovalRequest:
    defaults = dict(
        tool_name="exec",
        args={"command": "test"},
        rule_id="rule-1",
        message="Approval required",
        session_id="s1",
    )
    defaults.update(overrides)
    return ApprovalRequest.create(**defaults)


def _approve_ruleset() -> RuleSet:
    return RuleSet(
        shield_name="test",
        version=1,
        rules=[
            RuleConfig(
                id="needs-approval",
                when={"tool": "exec"},
                then=Verdict.APPROVE,
                message="exec requires approval",
            )
        ],
    )


# ---------- InMemoryBackend tests ----------


class TestInMemoryBackend:
    def test_submit_and_respond(self):
        backend = InMemoryBackend()
        req = _make_request()
        backend.submit(req)
        backend.respond(req.request_id, approved=True, responder="admin")
        resp = backend.wait_for_response(req.request_id, timeout=1.0)
        assert resp is not None
        assert resp.approved is True
        assert resp.responder == "admin"

    def test_approve(self):
        backend = InMemoryBackend()
        req = _make_request()
        backend.submit(req)
        backend.respond(req.request_id, approved=True)
        resp = backend.wait_for_response(req.request_id, timeout=1.0)
        assert resp.approved is True

    def test_deny(self):
        backend = InMemoryBackend()
        req = _make_request()
        backend.submit(req)
        backend.respond(req.request_id, approved=False)
        resp = backend.wait_for_response(req.request_id, timeout=1.0)
        assert resp.approved is False

    def test_timeout(self):
        backend = InMemoryBackend()
        req = _make_request()
        backend.submit(req)
        # No respond → should timeout
        resp = backend.wait_for_response(req.request_id, timeout=0.1)
        assert resp is None

    def test_pending(self):
        backend = InMemoryBackend()
        for i in range(3):
            backend.submit(_make_request(tool_name=f"tool-{i}"))
        assert len(backend.pending()) == 3

    def test_respond_clears_pending(self):
        backend = InMemoryBackend()
        req = _make_request()
        backend.submit(req)
        assert len(backend.pending()) == 1
        backend.respond(req.request_id, approved=True)
        assert len(backend.pending()) == 0

    def test_threaded_submit_respond(self):
        """Test that submit + respond works across threads."""
        backend = InMemoryBackend()
        req = _make_request()
        backend.submit(req)

        def approve_after_delay():
            import time
            time.sleep(0.05)
            backend.respond(req.request_id, approved=True)

        t = threading.Thread(target=approve_after_delay)
        t.start()
        resp = backend.wait_for_response(req.request_id, timeout=2.0)
        t.join()
        assert resp is not None
        assert resp.approved is True


# ---------- CLIBackend tests ----------


class TestCLIBackend:
    def test_approve(self):
        output = io.StringIO()
        backend = CLIBackend(input_func=lambda _: "y", output_file=output)
        req = _make_request()
        backend.submit(req)
        resp = backend.wait_for_response(req.request_id, timeout=1.0)
        assert resp.approved is True
        assert "APPROVE REQUIRED" in output.getvalue()

    def test_deny(self):
        output = io.StringIO()
        backend = CLIBackend(input_func=lambda _: "n", output_file=output)
        req = _make_request()
        backend.submit(req)
        resp = backend.wait_for_response(req.request_id, timeout=1.0)
        assert resp.approved is False

    def test_eof_denies(self):
        def eof_input(_):
            raise EOFError

        backend = CLIBackend(input_func=eof_input)
        req = _make_request()
        backend.submit(req)
        resp = backend.wait_for_response(req.request_id, timeout=1.0)
        assert resp.approved is False


# ---------- ShieldEngine integration ----------


class TestEngineApproval:
    def test_approve_verdict_approved(self):
        backend = InMemoryBackend()
        engine = ShieldEngine(
            rules=_approve_ruleset(),
            approval_backend=backend,
            approval_timeout=2.0,
        )

        def approve_first_pending():
            import time
            time.sleep(0.05)
            for req in backend.pending():
                backend.respond(req.request_id, approved=True, responder="admin")

        t = threading.Thread(target=approve_first_pending)
        t.start()
        result = engine.check("exec")
        t.join()
        assert result.verdict == Verdict.ALLOW

    def test_approve_verdict_denied(self):
        backend = InMemoryBackend()
        engine = ShieldEngine(
            rules=_approve_ruleset(),
            approval_backend=backend,
            approval_timeout=2.0,
        )

        def deny():
            import time
            time.sleep(0.05)
            for req in backend.pending():
                backend.respond(req.request_id, approved=False, responder="admin")

        t = threading.Thread(target=deny)
        t.start()
        result = engine.check("exec")
        t.join()
        assert result.verdict == Verdict.BLOCK
        assert "denied" in result.message.lower()

    def test_approve_timeout_blocks(self):
        backend = InMemoryBackend()
        engine = ShieldEngine(
            rules=_approve_ruleset(),
            approval_backend=backend,
            approval_timeout=0.1,
        )
        result = engine.check("exec")
        assert result.verdict == Verdict.BLOCK
        assert "timed out" in result.message.lower()

    def test_no_backend_blocks(self):
        engine = ShieldEngine(rules=_approve_ruleset())
        result = engine.check("exec")
        assert result.verdict == Verdict.BLOCK
        assert "no approval backend" in result.message.lower()


# ---------- Serialization ----------


class TestApprovalRequestSerialization:
    def test_round_trip(self):
        req = _make_request()
        d = {
            "request_id": req.request_id,
            "tool_name": req.tool_name,
            "args": req.args,
            "rule_id": req.rule_id,
            "message": req.message,
            "session_id": req.session_id,
            "timestamp": req.timestamp.isoformat(),
        }
        assert d["tool_name"] == "exec"
        assert d["request_id"] == req.request_id
