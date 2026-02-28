"""Tests for approval flow hardening — prompts 311-317."""

from __future__ import annotations

import json
import time

from policyshield.approval.base import ApprovalRequest
from policyshield.approval.memory import InMemoryBackend
from policyshield.approval.sanitizer import sanitize_args
from policyshield.core.models import Verdict
from policyshield.shield.engine import ShieldEngine
from policyshield.trace.recorder import TraceRecorder


def _make_request(rid: str = "r1") -> ApprovalRequest:
    return ApprovalRequest.create(tool_name="test", args={}, rule_id="rule-1", message="Test", session_id="s1")


# ── Prompt 311: Approval Timeout ─────────────────────────────────


class TestApprovalTimeout:
    def test_approval_times_out(self):
        backend = InMemoryBackend(timeout=0.1, on_timeout="BLOCK")
        req = _make_request()
        backend.submit(req)
        time.sleep(0.15)
        status = backend.get_status(req.request_id)
        assert status["status"] == "timeout"
        assert status["auto_verdict"] == "BLOCK"
        backend.stop()

    def test_approval_within_timeout(self):
        backend = InMemoryBackend(timeout=10.0)
        req = _make_request()
        backend.submit(req)
        status = backend.get_status(req.request_id)
        assert status["status"] == "pending"
        backend.stop()

    def test_on_timeout_allow(self):
        backend = InMemoryBackend(timeout=0.1, on_timeout="ALLOW")
        req = _make_request()
        backend.submit(req)
        time.sleep(0.15)
        status = backend.get_status(req.request_id)
        assert status["auto_verdict"] == "ALLOW"
        backend.stop()


# ── Prompt 312: Approval Audit Trail ─────────────────────────────


class TestApprovalAuditTrail:
    def test_trace_includes_approval_info(self, tmp_path):
        recorder = TraceRecorder(output_dir=tmp_path)
        recorder.record(
            "s1",
            "test",
            Verdict.ALLOW,
            approval_info={
                "approval_id": "ap-123",
                "status": "approved",
                "responder": "@admin",
                "response_time_ms": 5000,
            },
        )
        recorder.flush()
        lines = list(tmp_path.glob("*.jsonl"))[0].read_text().strip().split("\n")
        entry = json.loads(lines[0])
        assert entry["approval"]["responder"] == "@admin"
        assert entry["approval"]["status"] == "approved"

    def test_trace_without_approval_info(self, tmp_path):
        recorder = TraceRecorder(output_dir=tmp_path)
        recorder.record("s1", "test", Verdict.BLOCK)
        recorder.flush()
        lines = list(tmp_path.glob("*.jsonl"))[0].read_text().strip().split("\n")
        entry = json.loads(lines[0])
        assert "approval" not in entry


# ── Prompt 313: Stale Approval GC ────────────────────────────────


class TestStaleApprovalGC:
    def test_expired_approvals_cleaned(self):
        backend = InMemoryBackend(gc_ttl=0.1, gc_interval=999)
        req = _make_request()
        backend.submit(req)
        time.sleep(0.15)
        backend._run_gc()
        assert req.request_id not in backend._requests
        backend.stop()

    def test_fresh_approvals_not_cleaned(self):
        backend = InMemoryBackend(gc_ttl=60, gc_interval=999)
        req = _make_request()
        backend.submit(req)
        backend._run_gc()
        assert req.request_id in backend._requests
        backend.stop()

    def test_stop_cancels_timer(self):
        backend = InMemoryBackend()
        assert backend._gc_timer is not None
        backend.stop()
        assert backend._gc_timer is None


# ── Prompt 314: First Response Wins ──────────────────────────────


class TestFirstResponseWins:
    def test_first_response_wins(self):
        backend = InMemoryBackend()
        req = _make_request()
        backend.submit(req)
        backend.respond(req.request_id, approved=True, responder="alice")
        backend.respond(req.request_id, approved=False, responder="bob")
        status = backend.get_status(req.request_id)
        assert status["approved"] is True
        assert status["responder"] == "alice"
        backend.stop()

    def test_unknown_approval_ignored(self):
        backend = InMemoryBackend()
        backend.respond("nonexistent", approved=True)
        backend.stop()

    def test_respond_after_timeout_ignored(self):
        backend = InMemoryBackend(timeout=0.1)
        req = _make_request()
        backend.submit(req)
        time.sleep(0.15)
        backend.respond(req.request_id, approved=True, responder="late")
        backend.stop()


# ── Prompt 315: Args Sanitization ────────────────────────────────


class TestArgsSanitization:
    def test_aws_key_redacted(self):
        result = sanitize_args({"key": "AKIAIOSFODNN7EXAMPLE"})
        assert "AKIA" not in result["key"]
        assert "REDACTED" in result["key"]

    def test_password_redacted(self):
        result = sanitize_args({"config": "password=s3cret123"})
        assert "s3cret" not in result["config"]

    def test_long_value_truncated(self):
        result = sanitize_args({"data": "x" * 500})
        assert len(result["data"]) < 300
        assert "truncated" in result["data"]

    def test_safe_args_unchanged(self):
        result = sanitize_args({"name": "hello", "count": "5"})
        assert result["name"] == "hello"
        assert result["count"] == "5"

    def test_api_key_redacted(self):
        result = sanitize_args({"key": "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL"})
        assert "REDACTED" in result["key"]


# ── Prompt 316: Approval Polling Timeout ─────────────────────────


class TestApprovalPollingTimeout:
    def test_normal_poll_works(self):
        engine = ShieldEngine(rules="tests/test_rules.yaml")
        result = engine.get_approval_status("nonexistent")
        assert result["status"] in ("pending", "denied")


# ── Prompt 317: Approval Meta Cleanup ────────────────────────────


class TestApprovalMetaCleanup:
    def test_expired_entries_cleaned(self):
        engine = ShieldEngine(rules="tests/test_rules.yaml")
        engine._approval_meta = {"old": {}}
        engine._approval_meta_ts = {"old": 0}
        engine._approval_meta_ttl = 1.0
        engine._cleanup_approval_meta()
        assert "old" not in engine._approval_meta

    def test_hard_limit_enforced(self):
        engine = ShieldEngine(rules="tests/test_rules.yaml")
        engine._max_approval_meta = 3
        for i in range(5):
            engine._approval_meta[f"k{i}"] = {}
            engine._approval_meta_ts[f"k{i}"] = float(i)
        engine._cleanup_approval_meta()
        assert len(engine._approval_meta) <= 3
