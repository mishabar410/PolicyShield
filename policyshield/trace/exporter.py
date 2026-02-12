"""Export JSONL trace files to CSV and HTML formats."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from io import StringIO
from pathlib import Path

from policyshield.trace.analyzer import TraceAnalyzer


class TraceExporter:
    """Export JSONL trace files to CSV and HTML formats."""

    _DEFAULT_COLUMNS = [
        "timestamp",
        "session_id",
        "tool",
        "verdict",
        "rule_id",
        "pii_types",
        "latency_ms",
        "args_hash",
    ]

    @staticmethod
    def _load_records(input_path: str | Path) -> list[dict]:
        records: list[dict] = []
        p = Path(input_path)
        if not p.exists():
            return records
        with p.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records

    @staticmethod
    def to_csv(
        input_path: str | Path,
        output_path: str | Path,
        columns: list[str] | None = None,
    ) -> int:
        """Export to CSV. Returns number of records exported."""
        records = TraceExporter._load_records(input_path)
        cols = columns or TraceExporter._DEFAULT_COLUMNS

        out = Path(output_path)
        with out.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            writer.writeheader()

            for rec in records:
                row = {}
                for c in cols:
                    if c == "pii_types":
                        row[c] = ";".join(rec.get("pii_types") or [])
                    elif c == "args_hash":
                        row[c] = rec.get("args_hash", "")
                    else:
                        row[c] = rec.get(c, "")
                writer.writerow(row)

        return len(records)

    @staticmethod
    def to_html(
        input_path: str | Path,
        output_path: str | Path,
        title: str = "PolicyShield Trace Report",
        include_stats: bool = True,
    ) -> int:
        """Export to standalone HTML report. Returns number of records exported."""
        records = TraceExporter._load_records(input_path)

        stats_html = ""
        if include_stats and records:
            stats = TraceAnalyzer.from_records(records)
            buf = StringIO()
            buf.write('<div class="stats-section">\n')
            buf.write("<h2>Summary</h2>\n")
            buf.write(f"<p><strong>Total calls:</strong> {stats.total_calls}</p>\n")
            buf.write(f"<p><strong>Block rate:</strong> {stats.block_rate * 100:.1f}%</p>\n")
            buf.write(f"<p><strong>Unique sessions:</strong> {stats.session_count}</p>\n")
            if stats.time_range:
                buf.write(f"<p><strong>Time range:</strong> {stats.time_range[0]} → {stats.time_range[1]}</p>\n")
            # Verdict breakdown
            if stats.verdict_counts:
                buf.write("<h3>Verdict Breakdown</h3>\n")
                buf.write("<ul>\n")
                for v, c in stats.verdict_counts.items():
                    pct = c / stats.total_calls * 100 if stats.total_calls else 0
                    buf.write(f"<li>{v}: {c} ({pct:.1f}%)</li>\n")
                buf.write("</ul>\n")
            buf.write("</div>\n")
            stats_html = buf.getvalue()

        # Build table rows
        cols = TraceExporter._DEFAULT_COLUMNS
        rows_html = StringIO()
        for rec in records:
            verdict = rec.get("verdict", "")
            row_class = ""
            if verdict in ("BLOCK", "REDACT"):
                row_class = ' class="row-block"'
            elif verdict == "APPROVE":
                row_class = ' class="row-approve"'

            rows_html.write(f"<tr{row_class}>")
            for c in cols:
                if c == "pii_types":
                    val = ";".join(rec.get("pii_types") or [])
                elif c == "args_hash":
                    val = rec.get("args_hash", "")
                else:
                    val = str(rec.get(c, ""))
                rows_html.write(f"<td>{val}</td>")
            rows_html.write("</tr>\n")

        header_cells = "".join(f"<th>{c}</th>" for c in cols)

        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }}
h1 {{ color: #0ff; }}
h2, h3 {{ color: #7fdbff; }}
.stats-section {{ background: #16213e; padding: 16px; border-radius: 8px; margin-bottom: 20px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
th {{ background: #0a0a23; color: #7fdbff; padding: 8px; text-align: left; }}
td {{ padding: 6px 8px; border-bottom: 1px solid #333; }}
tr:hover {{ background: #16213e; }}
.row-block {{ background: rgba(255,0,0,0.15); }}
.row-approve {{ background: rgba(255,200,0,0.12); }}
.search-box {{ margin: 12px 0; }}
.search-box input {{ padding: 8px; width: 300px; border-radius: 4px; border: 1px solid #555; background: #0a0a23; color: #eee; }}
.generated {{ color: #888; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="generated">Generated: {generated_at}</p>
{stats_html}
<div class="search-box">
<input type="text" id="searchInput" placeholder="Filter table..." onkeyup="filterTable()">
</div>
<table id="traceTable">
<thead><tr>{header_cells}</tr></thead>
<tbody>
{rows_html.getvalue()}
</tbody>
</table>
<script>
function filterTable() {{
  var input = document.getElementById('searchInput');
  var filter = input.value.toLowerCase();
  var rows = document.querySelectorAll('#traceTable tbody tr');
  rows.forEach(function(row) {{
    var text = row.textContent.toLowerCase();
    row.style.display = text.indexOf(filter) > -1 ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

        out = Path(output_path)
        out.write_text(html, encoding="utf-8")
        return len(records)
