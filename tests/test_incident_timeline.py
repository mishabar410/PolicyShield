"""Tests for incident timeline generator."""

from __future__ import annotations

from policyshield.reporting.incident import (
    IncidentTimeline,
    TimelineEvent,
    build_timeline,
    render_timeline_text,
)


class TestIncidentTimeline:
    def test_build_timeline(self, tmp_path):
        traces = tmp_path / "traces"
        traces.mkdir()
        (traces / "trace_test.jsonl").write_text(
            '{"session_id": "s1", "tool": "exec", "verdict": "BLOCK", "timestamp": "2025-01-01T10:00:00"}\n'
            '{"session_id": "s1", "tool": "read", "verdict": "ALLOW", "timestamp": "2025-01-01T10:00:01"}\n'
            '{"session_id": "s2", "tool": "write", "verdict": "ALLOW", "timestamp": "2025-01-01T10:00:02"}\n'
        )
        tl = build_timeline("s1", traces)
        assert tl.total_checks == 2
        assert tl.violations == 1
        assert tl.events[0].tool == "exec"

    def test_render_text(self):
        tl = IncidentTimeline(
            session_id="s1",
            events=[
                TimelineEvent(timestamp="10:00", tool="exec", verdict="BLOCK", is_violation=True),
            ],
            total_checks=1,
            violations=1,
        )
        output = render_timeline_text(tl)
        assert "exec" in output
        assert "BLOCK" in output

    def test_empty_session(self, tmp_path):
        traces = tmp_path / "traces"
        traces.mkdir()
        (traces / "trace_test.jsonl").write_text(
            '{"session_id": "other", "tool": "exec", "verdict": "BLOCK", "timestamp": "10:00"}\n'
        )
        tl = build_timeline("nonexistent", traces)
        assert tl.total_checks == 0
