"""Tests for trace recorder."""

import json

import pytest

from policyshield.core.models import Verdict
from policyshield.trace.recorder import TraceRecorder, compute_args_hash


class TestComputeArgsHash:
    def test_deterministic(self):
        args = {"key": "value", "num": 42}
        h1 = compute_args_hash(args)
        h2 = compute_args_hash(args)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_different_args_different_hash(self):
        h1 = compute_args_hash({"a": 1})
        h2 = compute_args_hash({"a": 2})
        assert h1 != h2

    def test_key_order_independent(self):
        h1 = compute_args_hash({"b": 2, "a": 1})
        h2 = compute_args_hash({"a": 1, "b": 2})
        assert h1 == h2


class TestTraceRecorder:
    @pytest.fixture
    def trace_dir(self, tmp_path):
        return tmp_path / "traces"

    def test_basic_record(self, trace_dir):
        with TraceRecorder(trace_dir) as recorder:
            recorder.record(
                session_id="s1",
                tool="exec",
                verdict=Verdict.BLOCK,
                rule_id="block-exec",
            )
        assert recorder.record_count == 1
        # Check file was written
        content = recorder.file_path.read_text()
        data = json.loads(content.strip())
        assert data["session_id"] == "s1"
        assert data["tool"] == "exec"
        assert data["verdict"] == "BLOCK"
        assert data["rule_id"] == "block-exec"

    def test_multiple_records(self, trace_dir):
        with TraceRecorder(trace_dir) as recorder:
            for i in range(5):
                recorder.record(
                    session_id=f"s{i}",
                    tool="exec",
                    verdict=Verdict.ALLOW,
                )
        lines = recorder.file_path.read_text().strip().split("\n")
        assert len(lines) == 5

    def test_batch_flush(self, trace_dir):
        recorder = TraceRecorder(trace_dir, batch_size=3)
        for i in range(3):
            recorder.record(
                session_id="s1",
                tool="exec",
                verdict=Verdict.ALLOW,
            )
        # Should have auto-flushed
        content = recorder.file_path.read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 3

    def test_privacy_mode(self, trace_dir):
        with TraceRecorder(trace_dir, privacy_mode=True) as recorder:
            recorder.record(
                session_id="s1",
                tool="exec",
                verdict=Verdict.ALLOW,
                args={"command": "ls"},
            )
        content = recorder.file_path.read_text()
        data = json.loads(content.strip())
        assert "args_hash" in data
        assert "args" not in data

    def test_non_privacy_mode(self, trace_dir):
        with TraceRecorder(trace_dir, privacy_mode=False) as recorder:
            recorder.record(
                session_id="s1",
                tool="exec",
                verdict=Verdict.ALLOW,
                args={"command": "ls"},
            )
        content = recorder.file_path.read_text()
        data = json.loads(content.strip())
        assert "args" in data
        assert data["args"]["command"] == "ls"

    def test_output_dir_created(self, tmp_path):
        new_dir = tmp_path / "nested" / "traces"
        with TraceRecorder(new_dir) as recorder:
            recorder.record(session_id="s1", tool="t", verdict=Verdict.ALLOW)
        assert new_dir.exists()

    def test_pii_types_recorded(self, trace_dir):
        with TraceRecorder(trace_dir) as recorder:
            recorder.record(
                session_id="s1",
                tool="send",
                verdict=Verdict.REDACT,
                pii_types=["EMAIL", "SSN"],
            )
        content = recorder.file_path.read_text()
        data = json.loads(content.strip())
        assert data["pii_types"] == ["EMAIL", "SSN"]

    def test_latency_recorded(self, trace_dir):
        with TraceRecorder(trace_dir) as recorder:
            recorder.record(
                session_id="s1",
                tool="exec",
                verdict=Verdict.ALLOW,
                latency_ms=1.2345,
            )
        content = recorder.file_path.read_text()
        data = json.loads(content.strip())
        assert data["latency_ms"] == 1.23

    def test_file_path_property(self, trace_dir):
        recorder = TraceRecorder(trace_dir)
        assert recorder.file_path is not None
        assert recorder.file_path.suffix == ".jsonl"
        assert "trace_" in recorder.file_path.name
