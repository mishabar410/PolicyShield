"""Tests for trace aggregation API."""

import json
from datetime import datetime, timedelta

import pytest

from policyshield.trace.aggregator import (
    PIIHeatmapEntry,
    TimeSeriesPoint,
    TimeWindow,
    ToolStats,
    TraceAggregator,
    VerdictBreakdown,
    format_aggregation,
)


def _make_record(
    tool="exec",
    verdict="ALLOW",
    session_id="s1",
    timestamp=None,
    rule_id=None,
    pii_types=None,
    args=None,
    latency_ms=None,
):
    rec = {
        "timestamp": timestamp or datetime.now().isoformat(),
        "tool": tool,
        "verdict": verdict,
        "session_id": session_id,
    }
    if rule_id:
        rec["rule_id"] = rule_id
    if pii_types:
        rec["pii_types"] = pii_types
    if args:
        rec["args"] = args
    if latency_ms is not None:
        rec["latency_ms"] = latency_ms
    return rec


def _write_jsonl(path, records):
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


@pytest.fixture
def trace_dir(tmp_path):
    d = tmp_path / "traces"
    d.mkdir()
    return d


@pytest.fixture
def sample_records():
    base = datetime(2025, 1, 1, 12, 0, 0)
    return [
        _make_record(
            tool="exec",
            verdict="BLOCK",
            session_id="s1",
            timestamp=(base + timedelta(minutes=0)).isoformat(),
            latency_ms=10,
        ),
        _make_record(
            tool="read_file",
            verdict="ALLOW",
            session_id="s1",
            timestamp=(base + timedelta(minutes=10)).isoformat(),
            latency_ms=5,
        ),
        _make_record(
            tool="web_fetch",
            verdict="REDACT",
            session_id="s2",
            timestamp=(base + timedelta(minutes=20)).isoformat(),
            pii_types=["EMAIL", "PHONE"],
            latency_ms=20,
        ),
        _make_record(
            tool="send_message",
            verdict="BLOCK",
            session_id="s2",
            timestamp=(base + timedelta(minutes=30)).isoformat(),
            latency_ms=3,
        ),
        _make_record(
            tool="exec",
            verdict="ALLOW",
            session_id="s3",
            timestamp=(base + timedelta(minutes=40)).isoformat(),
            latency_ms=8,
        ),
        _make_record(
            tool="web_fetch",
            verdict="ALLOW",
            session_id="s3",
            timestamp=(base + timedelta(minutes=50)).isoformat(),
            latency_ms=15,
        ),
        _make_record(
            tool="write_file",
            verdict="REDACT",
            session_id="s1",
            timestamp=(base + timedelta(minutes=60)).isoformat(),
            pii_types=["SSN"],
        ),
        _make_record(
            tool="exec",
            verdict="BLOCK",
            session_id="s4",
            timestamp=(base + timedelta(minutes=70)).isoformat(),
            latency_ms=12,
        ),
        _make_record(
            tool="send_message",
            verdict="APPROVE",
            session_id="s4",
            timestamp=(base + timedelta(minutes=80)).isoformat(),
            latency_ms=6,
        ),
        _make_record(
            tool="read_file",
            verdict="ALLOW",
            session_id="s5",
            timestamp=(base + timedelta(minutes=90)).isoformat(),
            latency_ms=4,
        ),
    ]


@pytest.fixture
def populated_trace_dir(trace_dir, sample_records):
    _write_jsonl(trace_dir / "trace_20250101.jsonl", sample_records)
    return trace_dir


class TestVerdictBreakdown:
    def test_full_breakdown(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        result = agg.aggregate()
        vb = result.verdict_breakdown
        assert vb.total == 10
        assert vb.allow == 4
        assert vb.block == 3
        assert vb.redact == 2
        assert vb.approve == 1

    def test_verdict_breakdown_to_dict(self):
        vb = VerdictBreakdown(allow=5, block=3, redact=1, approve=1, total=10)
        d = vb.to_dict()
        assert d["allow"] == 5
        assert d["total"] == 10


class TestTopTools:
    def test_top_tools_by_count(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        result = agg.aggregate()
        top = result.top_tools
        # exec has 3 calls, should be first
        assert top[0].tool == "exec"
        assert top[0].call_count == 3

    def test_top_tools_block_rate(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        result = agg.aggregate()
        exec_stats = [t for t in result.top_tools if t.tool == "exec"][0]
        assert exec_stats.block_count == 2
        assert abs(exec_stats.block_rate - 2 / 3) < 0.01

    def test_top_tools_method(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        top = agg.top_tools(limit=2)
        assert len(top) == 2


class TestTopBlockedTools:
    def test_top_blocked(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        result = agg.aggregate()
        blocked = result.top_blocked_tools
        assert len(blocked) > 0
        # All should have block_count > 0
        assert all(t.block_count > 0 for t in blocked)
        # exec has most blocks
        assert blocked[0].tool == "exec"


class TestPIIHeatmap:
    def test_pii_heatmap(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        result = agg.aggregate()
        heatmap = result.pii_heatmap
        assert len(heatmap) >= 2  # EMAIL, PHONE, SSN entries
        types = {h.pii_type for h in heatmap}
        assert "EMAIL" in types
        assert "SSN" in types

    def test_pii_heatmap_method(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        heatmap = agg.pii_heatmap()
        assert len(heatmap) > 0


class TestTimeline:
    def test_timeline_buckets(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        base = datetime(2025, 1, 1, 12, 0, 0)
        window = TimeWindow(start=base, end=base + timedelta(hours=2), bucket_seconds=3600)
        tl = agg.timeline(window)
        assert len(tl) == 3  # 3 buckets: 0-1h, 1-2h, h2+

    def test_timeline_in_aggregate(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        result = agg.aggregate()
        # auto-infers time range
        assert result.time_range is not None


class TestSessionCount:
    def test_unique_sessions(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        result = agg.aggregate()
        assert result.unique_sessions == 5


class TestFilters:
    def test_filter_by_tool(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        result = agg.aggregate(tool="exec")
        assert result.verdict_breakdown.total == 3

    def test_filter_by_session(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        result = agg.aggregate(session_id="s2")
        assert result.verdict_breakdown.total == 2

    def test_filter_by_time_window(self, populated_trace_dir):
        base = datetime(2025, 1, 1, 12, 0, 0)
        agg = TraceAggregator(populated_trace_dir)
        tw = TimeWindow(start=base, end=base + timedelta(minutes=30))
        result = agg.aggregate(time_window=tw)
        assert result.verdict_breakdown.total == 4


class TestEmptyData:
    def test_empty_dir(self, trace_dir):
        agg = TraceAggregator(trace_dir)
        result = agg.aggregate()
        assert result.verdict_breakdown.total == 0
        assert result.top_tools == []
        assert result.pii_heatmap == []


class TestMultipleFiles:
    def test_aggregates_across_files(self, trace_dir, sample_records):
        _write_jsonl(trace_dir / "a.jsonl", sample_records[:5])
        _write_jsonl(trace_dir / "b.jsonl", sample_records[5:])
        agg = TraceAggregator(trace_dir)
        result = agg.aggregate()
        assert result.verdict_breakdown.total == 10


class TestSerialization:
    def test_to_dict(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        result = agg.aggregate()
        d = result.to_dict()
        assert "verdict_breakdown" in d
        assert "top_tools" in d
        assert "pii_heatmap" in d

    def test_tool_stats_to_dict(self):
        ts = ToolStats(tool="exec", call_count=10, block_count=3, block_rate=0.3, avg_latency_ms=5.5)
        d = ts.to_dict()
        assert d["tool"] == "exec"
        assert d["block_rate"] == 0.3

    def test_pii_heatmap_entry_to_dict(self):
        e = PIIHeatmapEntry(pii_type="EMAIL", tool="send_message", count=5)
        d = e.to_dict()
        assert d["pii_type"] == "EMAIL"
        assert d["count"] == 5

    def test_timeseries_point_to_dict(self):
        p = TimeSeriesPoint(
            timestamp=datetime(2025, 1, 1, 12, 0),
            count=5,
            verdict_breakdown=VerdictBreakdown(allow=3, block=2, total=5),
        )
        d = p.to_dict()
        assert d["count"] == 5
        assert d["verdict_breakdown"]["allow"] == 3


class TestFormatAggregation:
    def test_format_output(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        result = agg.aggregate()
        text = format_aggregation(result)
        assert "Verdict Breakdown:" in text
        assert "ALLOW:" in text
        assert "Top Tools" in text


class TestLatency:
    def test_avg_latency(self, populated_trace_dir):
        agg = TraceAggregator(populated_trace_dir)
        result = agg.aggregate()
        exec_stats = [t for t in result.top_tools if t.tool == "exec"][0]
        # exec has latencies: 10, 8, 12  -> avg = 10.0
        assert exec_stats.avg_latency_ms == 10.0


class TestCLIIntegration:
    def test_cli_stats_dir_json(self, populated_trace_dir):
        from policyshield.cli.main import app

        exit_code = app(["trace", "stats", "--dir", str(populated_trace_dir), "--format", "json"])
        assert exit_code == 0

    def test_cli_stats_dir_text(self, populated_trace_dir):
        from policyshield.cli.main import app

        exit_code = app(["trace", "stats", "--dir", str(populated_trace_dir)])
        assert exit_code == 0

    def test_cli_stats_missing_dir(self, tmp_path):
        from policyshield.cli.main import app

        exit_code = app(["trace", "stats", "--dir", str(tmp_path / "nope")])
        assert exit_code == 1
