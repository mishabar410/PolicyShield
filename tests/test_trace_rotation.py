"""Tests for trace file rotation and retention."""

from __future__ import annotations

import os

from policyshield.core.models import Verdict
from policyshield.trace.recorder import TraceRecorder


class TestTraceRotation:
    def test_rotation_by_size(self, tmp_path):
        """Trace file should rotate when exceeding max_file_size."""
        recorder = TraceRecorder(tmp_path, batch_size=1, max_file_size=50)
        for i in range(30):
            recorder.record(session_id="s1", tool=f"tool_{i}", verdict=Verdict.ALLOW)
        recorder.flush()
        files = list(tmp_path.glob("trace_*.jsonl"))
        assert len(files) >= 2  # Should have rotated

    def test_retention_cleanup(self, tmp_path):
        """Old trace files should be removed by cleanup_old_traces."""
        old_file = tmp_path / "trace_20200101_000000.jsonl"
        old_file.write_text("{}\n")
        os.utime(old_file, (0, 0))  # very old mtime
        recorder = TraceRecorder(tmp_path, retention_days=1)
        removed = recorder.cleanup_old_traces()
        assert removed == 1
        assert not old_file.exists()

    def test_no_rotation_when_disabled(self, tmp_path):
        """Rotation=none should never rotate."""
        recorder = TraceRecorder(tmp_path, batch_size=1, rotation="none")
        for i in range(10):
            recorder.record(session_id="s1", tool="t", verdict=Verdict.ALLOW)
        recorder.flush()
        files = list(tmp_path.glob("trace_*.jsonl"))
        assert len(files) == 1

    def test_retention_zero_days_no_cleanup(self, tmp_path):
        """retention_days=0 should not remove any files."""
        old_file = tmp_path / "trace_20200101_000000.jsonl"
        old_file.write_text("{}\n")
        os.utime(old_file, (0, 0))
        recorder = TraceRecorder(tmp_path, retention_days=0)
        removed = recorder.cleanup_old_traces()
        assert removed == 0
        assert old_file.exists()

    def test_should_not_rotate_small_file(self, tmp_path):
        """Files under max_file_size should not rotate."""
        recorder = TraceRecorder(tmp_path, batch_size=1, max_file_size=1_000_000)
        for i in range(5):
            recorder.record(session_id="s1", tool="t", verdict=Verdict.ALLOW)
        recorder.flush()
        files = list(tmp_path.glob("trace_*.jsonl"))
        assert len(files) == 1

    def test_default_rotation_params(self, tmp_path):
        """Default params should be size-based, 100MB, 30 days retention."""
        recorder = TraceRecorder(tmp_path)
        assert recorder._rotation == "size"
        assert recorder._max_file_size == 100 * 1024 * 1024
        assert recorder._retention_days == 30
