"""Compliance report generator for PolicyShield."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class ComplianceReport:
    """Structured compliance report data."""

    period_start: str
    period_end: str
    total_checks: int = 0
    verdicts: dict[str, int] = field(default_factory=dict)
    violations: list[dict] = field(default_factory=list)
    top_blocked_tools: list[tuple[str, int]] = field(default_factory=list)
    pii_detections: int = 0
    sessions_analyzed: int = 0
    rules_used: set[str] = field(default_factory=set)


def generate_report(trace_dir: str | Path, period_days: int = 30) -> ComplianceReport:
    """Generate compliance report from trace files."""
    trace_path = Path(trace_dir)
    now = datetime.now(tz=timezone.utc)
    report = ComplianceReport(
        period_start=now.replace(day=1).isoformat(),
        period_end=now.isoformat(),
    )

    verdict_counts: Counter[str] = Counter()
    tool_blocks: Counter[str] = Counter()
    sessions: set[str] = set()
    rules: set[str] = set()

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

                report.total_checks += 1
                verdict = entry.get("verdict", "ALLOW")
                verdict_counts[verdict] += 1
                sessions.add(entry.get("session_id", "unknown"))

                if entry.get("rule_id"):
                    rules.add(entry["rule_id"])

                if verdict in ("BLOCK", "REDACT", "APPROVE"):
                    report.violations.append(
                        {
                            "tool": entry.get("tool", "unknown"),
                            "verdict": verdict,
                            "rule_id": entry.get("rule_id"),
                            "timestamp": entry.get("timestamp"),
                        }
                    )
                    if verdict == "BLOCK":
                        tool_blocks[entry.get("tool", "unknown")] += 1

                if entry.get("pii_detected"):
                    report.pii_detections += 1

    report.verdicts = dict(verdict_counts)
    report.top_blocked_tools = tool_blocks.most_common(10)
    report.sessions_analyzed = len(sessions)
    report.rules_used = rules
    return report


def render_html(report: ComplianceReport) -> str:
    """Render compliance report as HTML."""
    html = f"""<!DOCTYPE html>
<html><head><title>PolicyShield Compliance Report</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }}
table {{ width: 100%; border-collapse: collapse; margin: 1em 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f5f5f5; }}
.stat {{ font-size: 2em; font-weight: bold; color: #333; }}
.block {{ color: #dc3545; }} .allow {{ color: #28a745; }}
</style></head><body>
<h1>PolicyShield Compliance Report</h1>
<p>Period: {report.period_start} &mdash; {report.period_end}</p>
<h2>Summary</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Total Checks</td><td class="stat">{report.total_checks}</td></tr>
<tr><td>Sessions</td><td>{report.sessions_analyzed}</td></tr>
<tr><td>PII Detections</td><td>{report.pii_detections}</td></tr>
<tr><td>Rules Active</td><td>{len(report.rules_used)}</td></tr>
</table>
<h2>Verdict Breakdown</h2>
<table><tr><th>Verdict</th><th>Count</th><th>%</th></tr>"""

    for verdict, count in sorted(report.verdicts.items()):
        pct = (count / report.total_checks * 100) if report.total_checks else 0
        css = "block" if verdict == "BLOCK" else ("allow" if verdict == "ALLOW" else "")
        html += f'<tr><td class="{css}">{verdict}</td><td>{count}</td><td>{pct:.1f}%</td></tr>'

    html += "</table>"

    if report.top_blocked_tools:
        html += "<h2>Top Blocked Tools</h2><table><tr><th>Tool</th><th>Blocks</th></tr>"
        for tool, count in report.top_blocked_tools:
            html += f"<tr><td>{tool}</td><td>{count}</td></tr>"
        html += "</table>"

    html += "</body></html>"
    return html
