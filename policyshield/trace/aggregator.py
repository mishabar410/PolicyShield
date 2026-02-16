"""Trace aggregation API — analytics with verdict breakdown, PII heatmap, timeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from policyshield.trace.search import SearchQuery, TraceSearchEngine


@dataclass
class TimeWindow:
    """Time window for aggregation queries."""

    start: datetime
    end: datetime
    bucket_seconds: int = 3600


@dataclass
class VerdictBreakdown:
    """Verdict counts."""

    allow: int = 0
    block: int = 0
    redact: int = 0
    approve: int = 0
    total: int = 0

    def to_dict(self) -> dict:
        return {
            "allow": self.allow,
            "block": self.block,
            "redact": self.redact,
            "approve": self.approve,
            "total": self.total,
        }


@dataclass
class ToolStats:
    """Per-tool statistics."""

    tool: str
    call_count: int
    block_count: int
    block_rate: float
    avg_latency_ms: float | None = None

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "call_count": self.call_count,
            "block_count": self.block_count,
            "block_rate": round(self.block_rate, 4),
            "avg_latency_ms": round(self.avg_latency_ms, 2) if self.avg_latency_ms is not None else None,
        }


@dataclass
class PIIHeatmapEntry:
    """PII detection count per tool."""

    pii_type: str
    tool: str
    count: int

    def to_dict(self) -> dict:
        return {"pii_type": self.pii_type, "tool": self.tool, "count": self.count}


@dataclass
class TimeSeriesPoint:
    """A single point in a time series."""

    timestamp: datetime
    count: int
    verdict_breakdown: VerdictBreakdown

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "count": self.count,
            "verdict_breakdown": self.verdict_breakdown.to_dict(),
        }


@dataclass
class AggregationResult:
    """Full aggregation result."""

    verdict_breakdown: VerdictBreakdown
    top_tools: list[ToolStats] = field(default_factory=list)
    top_blocked_tools: list[ToolStats] = field(default_factory=list)
    pii_heatmap: list[PIIHeatmapEntry] = field(default_factory=list)
    timeline: list[TimeSeriesPoint] = field(default_factory=list)
    unique_sessions: int = 0
    time_range: TimeWindow | None = None

    def to_dict(self) -> dict:
        return {
            "verdict_breakdown": self.verdict_breakdown.to_dict(),
            "top_tools": [t.to_dict() for t in self.top_tools],
            "top_blocked_tools": [t.to_dict() for t in self.top_blocked_tools],
            "pii_heatmap": [p.to_dict() for p in self.pii_heatmap],
            "timeline": [t.to_dict() for t in self.timeline],
            "unique_sessions": self.unique_sessions,
            "time_range": {
                "start": self.time_range.start.isoformat(),
                "end": self.time_range.end.isoformat(),
                "bucket_seconds": self.time_range.bucket_seconds,
            }
            if self.time_range
            else None,
        }


class TraceAggregator:
    """Analytics engine for trace data: verdict breakdown, top tools, PII heatmap, timeline."""

    def __init__(self, trace_dir: str | Path) -> None:
        self._trace_dir = Path(trace_dir)
        self._search_engine = TraceSearchEngine(trace_dir)

    def aggregate(
        self,
        time_window: TimeWindow | None = None,
        session_id: str | None = None,
        tool: str | None = None,
    ) -> AggregationResult:
        """Full aggregation with optional filters."""
        records = self._get_records(time_window, session_id, tool)

        if not records:
            return AggregationResult(verdict_breakdown=VerdictBreakdown())

        vb = self._compute_verdict_breakdown(records)
        top = self._compute_top_tools(records)
        top_blocked = self._compute_top_blocked_tools(records)
        pii = self._compute_pii_heatmap(records)
        sessions = {r.get("session_id") for r in records if r.get("session_id")}

        # Time range
        tw = time_window
        if tw is None:
            timestamps = []
            for r in records:
                ts = r.get("timestamp")
                if ts:
                    try:
                        timestamps.append(datetime.fromisoformat(ts))
                    except ValueError:
                        pass
            if timestamps:
                tw = TimeWindow(start=min(timestamps), end=max(timestamps))

        tl = self._compute_timeline(records, tw) if tw else []

        return AggregationResult(
            verdict_breakdown=vb,
            top_tools=top,
            top_blocked_tools=top_blocked,
            pii_heatmap=pii,
            timeline=tl,
            unique_sessions=len(sessions),
            time_range=tw,
        )

    def verdict_breakdown(self, **filters) -> VerdictBreakdown:
        """Verdict counts only."""
        records = self._get_records(**filters)
        return self._compute_verdict_breakdown(records)

    def top_tools(self, limit: int = 10, **filters) -> list[ToolStats]:
        """Top N tools by call count."""
        records = self._get_records(**filters)
        return self._compute_top_tools(records, limit=limit)

    def pii_heatmap(self, **filters) -> list[PIIHeatmapEntry]:
        """PII detections grouped by (pii_type, tool)."""
        records = self._get_records(**filters)
        return self._compute_pii_heatmap(records)

    def timeline(self, window: TimeWindow, **filters) -> list[TimeSeriesPoint]:
        """Time series with grouping by bucket_seconds."""
        records = self._get_records(**filters)
        return self._compute_timeline(records, window)

    def _get_records(
        self,
        time_window: TimeWindow | None = None,
        session_id: str | None = None,
        tool: str | None = None,
    ) -> list[dict]:
        """Fetch records using search engine with optional filters."""
        query = SearchQuery(
            session_id=session_id,
            tool=tool,
            time_from=time_window.start if time_window else None,
            time_to=time_window.end if time_window else None,
            limit=999999,
        )
        result = self._search_engine.search(query)
        return result.records

    def _compute_verdict_breakdown(self, records: list[dict]) -> VerdictBreakdown:
        counts = {"ALLOW": 0, "BLOCK": 0, "REDACT": 0, "APPROVE": 0}
        for r in records:
            v = r.get("verdict", "")
            if v in counts:
                counts[v] += 1
        return VerdictBreakdown(
            allow=counts["ALLOW"],
            block=counts["BLOCK"],
            redact=counts["REDACT"],
            approve=counts["APPROVE"],
            total=len(records),
        )

    def _compute_top_tools(self, records: list[dict], limit: int = 10) -> list[ToolStats]:
        tool_data: dict[str, dict] = {}
        for r in records:
            t = r.get("tool", "unknown")
            if t not in tool_data:
                tool_data[t] = {"calls": 0, "blocks": 0, "latencies": []}
            tool_data[t]["calls"] += 1
            if r.get("verdict") == "BLOCK":
                tool_data[t]["blocks"] += 1
            lat = r.get("latency_ms")
            if lat is not None:
                tool_data[t]["latencies"].append(float(lat))

        stats = []
        for tool, data in tool_data.items():
            calls = data["calls"]
            blocks = data["blocks"]
            lats = data["latencies"]
            stats.append(
                ToolStats(
                    tool=tool,
                    call_count=calls,
                    block_count=blocks,
                    block_rate=blocks / calls if calls > 0 else 0.0,
                    avg_latency_ms=sum(lats) / len(lats) if lats else None,
                )
            )

        stats.sort(key=lambda s: s.call_count, reverse=True)
        return stats[:limit]

    def _compute_top_blocked_tools(self, records: list[dict], limit: int = 10) -> list[ToolStats]:
        all_tools = self._compute_top_tools(records, limit=9999)
        blocked = [t for t in all_tools if t.block_count > 0]
        blocked.sort(key=lambda s: s.block_count, reverse=True)
        return blocked[:limit]

    def _compute_pii_heatmap(self, records: list[dict]) -> list[PIIHeatmapEntry]:
        counts: dict[tuple[str, str], int] = {}
        for r in records:
            pii_types = r.get("pii_types", [])
            tool = r.get("tool", "unknown")
            for pt in pii_types:
                key = (pt, tool)
                counts[key] = counts.get(key, 0) + 1

        entries = [PIIHeatmapEntry(pii_type=k[0], tool=k[1], count=v) for k, v in counts.items()]
        entries.sort(key=lambda e: e.count, reverse=True)
        return entries

    def _compute_timeline(self, records: list[dict], window: TimeWindow) -> list[TimeSeriesPoint]:
        bucket_s = window.bucket_seconds
        start_ts = window.start.timestamp()
        end_ts = window.end.timestamp()

        # Build buckets
        buckets: dict[float, list[dict]] = {}
        t = start_ts
        while t <= end_ts:
            buckets[t] = []
            t += bucket_s

        # Assign records to buckets
        for r in records:
            ts_str = r.get("timestamp")
            if not ts_str:
                continue
            try:
                ts = datetime.fromisoformat(ts_str).timestamp()
            except ValueError:
                continue
            # Find bucket
            bucket_key = start_ts + ((ts - start_ts) // bucket_s) * bucket_s
            if bucket_key in buckets:
                buckets[bucket_key].append(r)

        points = []
        for bk in sorted(buckets.keys()):
            recs = buckets[bk]
            vb = self._compute_verdict_breakdown(recs)
            points.append(
                TimeSeriesPoint(
                    timestamp=datetime.fromtimestamp(bk, tz=timezone.utc),
                    count=len(recs),
                    verdict_breakdown=vb,
                )
            )

        return points


def format_aggregation(result: AggregationResult, top_n: int = 10) -> str:
    """Format aggregation result for CLI display."""
    lines: list[str] = []

    vb = result.verdict_breakdown
    lines.append("Verdict Breakdown:")
    parts = []
    for name, count in [("ALLOW", vb.allow), ("BLOCK", vb.block), ("REDACT", vb.redact), ("APPROVE", vb.approve)]:
        pct = count / vb.total * 100 if vb.total else 0
        parts.append(f"  {name}: {count} ({pct:.0f}%)")
    lines.extend(parts)
    lines.append("")

    if result.top_tools:
        lines.append("Top Tools (by calls):")
        for i, ts in enumerate(result.top_tools[:top_n], 1):
            lines.append(
                f"  {i}. {ts.tool:<16} {ts.call_count} calls, {ts.block_count:>3} blocks ({ts.block_rate * 100:.1f}%)"
            )
        lines.append("")

    if result.pii_heatmap:
        lines.append("PII Detections:")
        by_type: dict[str, list[str]] = {}
        for p in result.pii_heatmap:
            by_type.setdefault(p.pii_type, []).append(f"{p.tool} ({p.count})")
        for pt, tools in by_type.items():
            lines.append(f"  {pt:<8} → {', '.join(tools)}")
        lines.append("")

    return "\n".join(lines)
