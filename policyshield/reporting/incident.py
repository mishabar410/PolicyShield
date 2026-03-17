"""Incident timeline generator for PolicyShield."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TimelineEvent:
    timestamp: str
    tool: str
    verdict: str
    rule_id: str | None = None
    message: str = ""
    pii_detected: bool = False
    is_violation: bool = False


@dataclass
class IncidentTimeline:
    session_id: str
    events: list[TimelineEvent] = field(default_factory=list)
    first_event: str = ""
    last_event: str = ""
    total_checks: int = 0
    violations: int = 0
    pii_events: int = 0


def build_timeline(session_id: str, trace_dir: str | Path) -> IncidentTimeline:
    """Build chronological timeline for a session from traces."""
    trace_path = Path(trace_dir)
    timeline = IncidentTimeline(session_id=session_id)
    events: list[TimelineEvent] = []

    for trace_file in sorted(trace_path.glob("trace_*.jsonl")):
        with open(trace_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if entry.get("session_id") != session_id:
                    continue

                is_violation = entry.get("verdict", "ALLOW") != "ALLOW"
                pii = bool(entry.get("pii_detected") or entry.get("pii_matches"))

                events.append(
                    TimelineEvent(
                        timestamp=entry.get("timestamp", "unknown"),
                        tool=entry.get("tool", "unknown"),
                        verdict=entry.get("verdict", "ALLOW"),
                        rule_id=entry.get("rule_id"),
                        message=entry.get("message", ""),
                        pii_detected=pii,
                        is_violation=is_violation,
                    )
                )

    events.sort(key=lambda e: e.timestamp)

    timeline.events = events
    timeline.total_checks = len(events)
    timeline.violations = sum(1 for e in events if e.is_violation)
    timeline.pii_events = sum(1 for e in events if e.pii_detected)
    if events:
        timeline.first_event = events[0].timestamp
        timeline.last_event = events[-1].timestamp

    return timeline


def render_timeline_text(timeline: IncidentTimeline) -> str:
    """Render timeline as styled text output."""
    lines = [
        f"Incident Timeline: session {timeline.session_id}",
        f"   Period: {timeline.first_event} -> {timeline.last_event}",
        f"   Total: {timeline.total_checks} checks, {timeline.violations} violations, {timeline.pii_events} PII events",
        "",
    ]

    for i, event in enumerate(timeline.events, 1):
        icon = "!!" if event.is_violation else "OK"
        pii_flag = " PII" if event.pii_detected else ""
        rule = f" (rule: {event.rule_id})" if event.rule_id else ""
        lines.append(f"  {i:3d}. [{event.timestamp}] {icon} {event.tool} -> {event.verdict}{rule}{pii_flag}")
        if event.message:
            lines.append(f"       {event.message}")

    return "\n".join(lines)
