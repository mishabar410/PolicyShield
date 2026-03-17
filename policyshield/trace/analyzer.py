"""Trace file analyzer for aggregated statistics."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TraceStats:
    """Aggregated statistics from trace records."""

    total_calls: int = 0
    verdict_counts: dict[str, int] = field(default_factory=dict)
    tool_counts: dict[str, int] = field(default_factory=dict)
    rule_hit_counts: dict[str, int] = field(default_factory=dict)
    pii_type_counts: dict[str, int] = field(default_factory=dict)
    session_count: int = 0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    time_range: tuple[str, str] | None = None
    block_rate: float = 0.0

    def to_dict(self) -> dict:
        """Convert to plain dict for JSON serialization."""
        d = {
            "total_calls": self.total_calls,
            "verdict_counts": self.verdict_counts,
            "tool_counts": self.tool_counts,
            "rule_hit_counts": self.rule_hit_counts,
            "pii_type_counts": self.pii_type_counts,
            "session_count": self.session_count,
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "p95_latency_ms": round(self.p95_latency_ms, 2),
            "p99_latency_ms": round(self.p99_latency_ms, 2),
            "time_range": list(self.time_range) if self.time_range else None,
            "block_rate": round(self.block_rate, 4),
        }
        return d


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Calculate percentile from a sorted list."""
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_values[int(k)]
    return sorted_values[f] * (c - k) + sorted_values[c] * (k - f)


class TraceAnalyzer:
    """Analyze JSONL trace files and produce statistics."""

    @staticmethod
    def from_file(path: str | Path) -> TraceStats:
        """Load and analyze a JSONL trace file."""
        p = Path(path)
        if not p.exists():
            return TraceStats()
        records: list[dict] = []
        with p.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return TraceAnalyzer.from_records(records)

    @staticmethod
    def from_records(records: list[dict]) -> TraceStats:
        """Analyze pre-loaded trace records."""
        if not records:
            return TraceStats()

        verdict_counts: dict[str, int] = {}
        tool_counts: dict[str, int] = {}
        rule_hit_counts: dict[str, int] = {}
        pii_type_counts: dict[str, int] = {}
        sessions: set[str] = set()
        latencies: list[float] = []
        timestamps: list[str] = []
        block_count = 0

        for rec in records:
            # Verdict
            verdict = rec.get("verdict", "UNKNOWN")
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            if verdict == "BLOCK":
                block_count += 1

            # Tool
            tool = rec.get("tool", "unknown")
            tool_counts[tool] = tool_counts.get(tool, 0) + 1

            # Rule (only non-ALLOW verdicts)
            rule_id = rec.get("rule_id")
            if rule_id and verdict != "ALLOW":
                rule_hit_counts[rule_id] = rule_hit_counts.get(rule_id, 0) + 1

            # PII types
            pii_types = rec.get("pii_types") or []
            for pt in pii_types:
                pii_type_counts[pt] = pii_type_counts.get(pt, 0) + 1

            # Session
            session_id = rec.get("session_id")
            if session_id:
                sessions.add(session_id)

            # Latency
            latency = rec.get("latency_ms")
            if latency is not None:
                latencies.append(float(latency))

            # Timestamp
            ts = rec.get("timestamp")
            if ts:
                timestamps.append(ts)

        total = len(records)
        latencies.sort()

        return TraceStats(
            total_calls=total,
            verdict_counts=dict(sorted(verdict_counts.items())),
            tool_counts=dict(sorted(tool_counts.items(), key=lambda x: -x[1])),
            rule_hit_counts=dict(sorted(rule_hit_counts.items(), key=lambda x: -x[1])),
            pii_type_counts=dict(sorted(pii_type_counts.items(), key=lambda x: -x[1])),
            session_count=len(sessions),
            avg_latency_ms=sum(latencies) / len(latencies) if latencies else 0.0,
            p95_latency_ms=_percentile(latencies, 95),
            p99_latency_ms=_percentile(latencies, 99),
            time_range=(min(timestamps), max(timestamps)) if timestamps else None,
            block_rate=block_count / total if total > 0 else 0.0,
        )


def format_stats(stats: TraceStats) -> str:
    """Format stats for CLI display."""
    lines: list[str] = []
    lines.append("📊 Trace Statistics")
    lines.append("──────────────────────────────────")
    lines.append(f"  Total calls:     {stats.total_calls}")
    lines.append(f"  Sessions:        {stats.session_count}")
    if stats.time_range:
        lines.append(f"  Time range:      {stats.time_range[0]} → {stats.time_range[1]}")
    lines.append(f"  Block rate:      {stats.block_rate * 100:.1f}%")
    lines.append("")

    if stats.verdict_counts:
        lines.append("📋 Verdicts")
        for v, c in stats.verdict_counts.items():
            pct = c / stats.total_calls * 100 if stats.total_calls else 0
            lines.append(f"  {v:<12} {c:>5}  ({pct:.1f}%)")
        lines.append("")

    if stats.tool_counts:
        lines.append("🔧 Top Tools")
        for t, c in list(stats.tool_counts.items())[:10]:
            pct = c / stats.total_calls * 100 if stats.total_calls else 0
            lines.append(f"  {t:<16} {c:>5}  ({pct:.1f}%)")
        lines.append("")

    if stats.rule_hit_counts:
        lines.append("🛑 Top Rules (non-ALLOW)")
        for r, c in list(stats.rule_hit_counts.items())[:10]:
            lines.append(f"  {r:<20} {c} hits")
        lines.append("")

    lines.append("⚡ Latency")
    lines.append(f"  avg:   {stats.avg_latency_ms:.1f}ms")
    lines.append(f"  p95:   {stats.p95_latency_ms:.1f}ms")
    lines.append(f"  p99:   {stats.p99_latency_ms:.1f}ms")
    lines.append("")

    if stats.pii_type_counts:
        lines.append("🔒 PII Detected")
        for pt, c in stats.pii_type_counts.items():
            lines.append(f"  {pt:<12} {c}")

    return "\n".join(lines)
