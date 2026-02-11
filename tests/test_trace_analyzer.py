"""Tests for TraceAnalyzer and trace stats CLI command."""

from __future__ import annotations

import json

import pytest

from policyshield.cli.main import app as cli_main
from policyshield.trace.analyzer import TraceAnalyzer, TraceStats, format_stats


def _make_record(**overrides) -> dict:
    base = {
        "timestamp": "2025-02-11T10:00:00Z",
        "tool": "exec",
        "verdict": "ALLOW",
        "rule_id": None,
        "session_id": "s1",
        "pii_types": [],
        "latency_ms": 1.0,
    }
    base.update(overrides)
    return base


class TestTraceAnalyzer:
    def test_empty_trace_file(self, tmp_path):
        f = tmp_path / "empty.jsonl"
        f.write_text("")
        stats = TraceAnalyzer.from_file(f)
        assert stats.total_calls == 0

    def test_single_record(self):
        stats = TraceAnalyzer.from_records([_make_record()])
        assert stats.total_calls == 1
        assert stats.verdict_counts["ALLOW"] == 1
        assert stats.tool_counts["exec"] == 1

    def test_verdict_distribution(self):
        records = [_make_record()] * 10 + [
            _make_record(verdict="BLOCK", rule_id="r1"),
            _make_record(verdict="BLOCK", rule_id="r1"),
        ]
        stats = TraceAnalyzer.from_records(records)
        assert stats.verdict_counts["ALLOW"] == 10
        assert stats.verdict_counts["BLOCK"] == 2

    def test_tool_counts(self):
        records = [
            _make_record(tool="exec"),
            _make_record(tool="exec"),
            _make_record(tool="web_fetch"),
        ]
        stats = TraceAnalyzer.from_records(records)
        assert stats.tool_counts["exec"] == 2
        assert stats.tool_counts["web_fetch"] == 1

    def test_rule_hit_counts(self):
        records = [
            _make_record(verdict="BLOCK", rule_id="no-shell"),
            _make_record(verdict="BLOCK", rule_id="no-shell"),
            _make_record(verdict="APPROVE", rule_id="approve-exec"),
            _make_record(),  # ALLOW — not counted
        ]
        stats = TraceAnalyzer.from_records(records)
        assert stats.rule_hit_counts["no-shell"] == 2
        assert stats.rule_hit_counts["approve-exec"] == 1
        assert "None" not in stats.rule_hit_counts

    def test_pii_type_counts(self):
        records = [
            _make_record(pii_types=["EMAIL", "SSN"]),
            _make_record(pii_types=["EMAIL"]),
            _make_record(),
        ]
        stats = TraceAnalyzer.from_records(records)
        assert stats.pii_type_counts["EMAIL"] == 2
        assert stats.pii_type_counts["SSN"] == 1

    def test_session_count(self):
        records = [
            _make_record(session_id="s1"),
            _make_record(session_id="s2"),
            _make_record(session_id="s3"),
            _make_record(session_id="s1"),
        ]
        stats = TraceAnalyzer.from_records(records)
        assert stats.session_count == 3

    def test_latency_percentiles(self):
        latencies = list(range(1, 101))  # 1 to 100
        records = [_make_record(latency_ms=float(lat)) for lat in latencies]
        stats = TraceAnalyzer.from_records(records)
        assert stats.avg_latency_ms == pytest.approx(50.5)
        assert stats.p95_latency_ms == pytest.approx(95.05, abs=0.5)
        assert stats.p99_latency_ms == pytest.approx(99.01, abs=0.5)

    def test_block_rate_calculation(self):
        records = [_make_record()] * 8 + [
            _make_record(verdict="BLOCK", rule_id="r1"),
            _make_record(verdict="BLOCK", rule_id="r2"),
        ]
        stats = TraceAnalyzer.from_records(records)
        assert stats.block_rate == pytest.approx(0.2)

    def test_time_range(self):
        records = [
            _make_record(timestamp="2025-02-11T10:00:00Z"),
            _make_record(timestamp="2025-02-11T14:30:00Z"),
        ]
        stats = TraceAnalyzer.from_records(records)
        assert stats.time_range == ("2025-02-11T10:00:00Z", "2025-02-11T14:30:00Z")

    def test_format_stats(self):
        stats = TraceStats(
            total_calls=10,
            verdict_counts={"ALLOW": 8, "BLOCK": 2},
            tool_counts={"exec": 10},
            rule_hit_counts={"rule-1": 2},
            pii_type_counts={},
            session_count=2,
            avg_latency_ms=1.5,
            p95_latency_ms=3.0,
            p99_latency_ms=5.0,
            time_range=("2025-02-11T10:00:00Z", "2025-02-11T14:30:00Z"),
            block_rate=0.2,
        )
        output = format_stats(stats)
        assert "Trace Statistics" in output
        assert "Total calls:" in output
        assert "Block rate:" in output

    def test_to_dict(self):
        stats = TraceStats(total_calls=5, block_rate=0.2)
        d = stats.to_dict()
        assert d["total_calls"] == 5
        assert d["block_rate"] == 0.2


class TestTraceStatsCLI:
    def test_cli_trace_stats(self, tmp_path, capsys):
        f = tmp_path / "trace.jsonl"
        records = [
            _make_record(),
            _make_record(verdict="BLOCK", rule_id="r1"),
        ]
        f.write_text("\n".join(json.dumps(r) for r in records))
        rc = cli_main(["trace", "stats", str(f)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Trace Statistics" in out

    def test_cli_trace_stats_json(self, tmp_path, capsys):
        f = tmp_path / "trace.jsonl"
        records = [_make_record(), _make_record(verdict="BLOCK", rule_id="r1")]
        f.write_text("\n".join(json.dumps(r) for r in records))
        rc = cli_main(["trace", "stats", str(f), "--format", "json"])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["total_calls"] == 2
