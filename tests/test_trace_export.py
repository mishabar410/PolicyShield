"""Tests for TraceExporter (Prompt 07)."""

from __future__ import annotations

import csv
import json

from policyshield.trace.exporter import TraceExporter


def _write_trace(path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def _sample_records() -> list[dict]:
    return [
        {
            "timestamp": "2025-01-15T10:00:00",
            "session_id": "s1",
            "tool": "exec",
            "verdict": "BLOCK",
            "rule_id": "no-rm",
            "pii_types": ["EMAIL", "PHONE"],
            "latency_ms": 1.5,
            "args_hash": "abc123",
        },
        {
            "timestamp": "2025-01-15T10:01:00",
            "session_id": "s1",
            "tool": "web_fetch",
            "verdict": "ALLOW",
            "latency_ms": 0.3,
        },
        {
            "timestamp": "2025-01-15T10:02:00",
            "session_id": "s2",
            "tool": "exec",
            "verdict": "APPROVE",
            "rule_id": "need-approval",
            "latency_ms": 2.1,
        },
    ]


# ── Test 1: CSV basic ───────────────────────────────────────────────


def test_csv_basic(tmp_path):
    trace = tmp_path / "trace.jsonl"
    _write_trace(trace, _sample_records())
    out_csv = tmp_path / "out.csv"

    count = TraceExporter.to_csv(trace, out_csv)
    assert count == 3
    assert out_csv.exists()

    with out_csv.open(encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 3
    assert "timestamp" in reader.fieldnames
    assert "verdict" in reader.fieldnames


# ── Test 2: CSV columns filter ──────────────────────────────────────


def test_csv_columns_filter(tmp_path):
    trace = tmp_path / "trace.jsonl"
    _write_trace(trace, _sample_records())
    out_csv = tmp_path / "out.csv"

    TraceExporter.to_csv(trace, out_csv, columns=["tool", "verdict"])
    with out_csv.open(encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert set(reader.fieldnames) == {"tool", "verdict"}
    assert len(rows) == 3


# ── Test 3: CSV pii_types join ──────────────────────────────────────


def test_csv_pii_types_join(tmp_path):
    trace = tmp_path / "trace.jsonl"
    _write_trace(trace, _sample_records())
    out_csv = tmp_path / "out.csv"

    TraceExporter.to_csv(trace, out_csv)
    with out_csv.open(encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    # First record has EMAIL;PHONE
    assert rows[0]["pii_types"] == "EMAIL;PHONE"
    # Second record has no PII
    assert rows[1]["pii_types"] == ""


# ── Test 4: CSV empty trace ─────────────────────────────────────────


def test_csv_empty_trace(tmp_path):
    trace = tmp_path / "trace.jsonl"
    trace.write_text("", encoding="utf-8")
    out_csv = tmp_path / "out.csv"

    count = TraceExporter.to_csv(trace, out_csv)
    assert count == 0
    # Still has headers
    with out_csv.open(encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 0
    assert len(reader.fieldnames) > 0


# ── Test 5: CSV record count ────────────────────────────────────────


def test_csv_record_count(tmp_path):
    trace = tmp_path / "trace.jsonl"
    recs = _sample_records()
    _write_trace(trace, recs)
    out_csv = tmp_path / "out.csv"

    count = TraceExporter.to_csv(trace, out_csv)
    assert count == len(recs)


# ── Test 6: HTML basic ──────────────────────────────────────────────


def test_html_basic(tmp_path):
    trace = tmp_path / "trace.jsonl"
    _write_trace(trace, _sample_records())
    out_html = tmp_path / "report.html"

    count = TraceExporter.to_html(trace, out_html)
    assert count == 3
    assert out_html.exists()


# ── Test 7: HTML contains table ─────────────────────────────────────


def test_html_contains_table(tmp_path):
    trace = tmp_path / "trace.jsonl"
    _write_trace(trace, _sample_records())
    out_html = tmp_path / "report.html"

    TraceExporter.to_html(trace, out_html)
    content = out_html.read_text(encoding="utf-8")
    assert "<table" in content
    assert "<th>" in content
    assert "BLOCK" in content


# ── Test 8: HTML block highlighted ──────────────────────────────────


def test_html_block_highlighted(tmp_path):
    trace = tmp_path / "trace.jsonl"
    _write_trace(trace, _sample_records())
    out_html = tmp_path / "report.html"

    TraceExporter.to_html(trace, out_html)
    content = out_html.read_text(encoding="utf-8")
    assert "row-block" in content


# ── Test 9: HTML stats section ──────────────────────────────────────


def test_html_stats_section(tmp_path):
    trace = tmp_path / "trace.jsonl"
    _write_trace(trace, _sample_records())
    out_html = tmp_path / "report.html"

    TraceExporter.to_html(trace, out_html, include_stats=True)
    content = out_html.read_text(encoding="utf-8")
    assert "stats-section" in content
    assert "Total calls" in content
    assert "Block rate" in content


# ── Test 10: HTML title ─────────────────────────────────────────────


def test_html_title(tmp_path):
    trace = tmp_path / "trace.jsonl"
    _write_trace(trace, _sample_records())
    out_html = tmp_path / "report.html"

    TraceExporter.to_html(trace, out_html, title="Agent Audit Q1")
    content = out_html.read_text(encoding="utf-8")
    assert "Agent Audit Q1" in content


# ── Test 11: HTML standalone ────────────────────────────────────────


def test_html_standalone(tmp_path):
    trace = tmp_path / "trace.jsonl"
    _write_trace(trace, _sample_records())
    out_html = tmp_path / "report.html"

    TraceExporter.to_html(trace, out_html)
    content = out_html.read_text(encoding="utf-8")
    # No external links
    assert "http://" not in content
    assert "https://" not in content
    # All styles inline
    assert "<style>" in content


# ── Test 12: HTML search JS ─────────────────────────────────────────


def test_html_search_js(tmp_path):
    trace = tmp_path / "trace.jsonl"
    _write_trace(trace, _sample_records())
    out_html = tmp_path / "report.html"

    TraceExporter.to_html(trace, out_html)
    content = out_html.read_text(encoding="utf-8")
    assert "<script>" in content
    assert "filterTable" in content


# ── Test 13: CLI export CSV ─────────────────────────────────────────


def test_cli_export_csv(tmp_path, monkeypatch):
    from policyshield.cli.main import app

    trace = tmp_path / "trace.jsonl"
    _write_trace(trace, _sample_records())
    out_csv = tmp_path / "out.csv"

    rc = app(["trace", "export", str(trace), "--format", "csv", "--output", str(out_csv)])
    assert rc == 0
    assert out_csv.exists()


# ── Test 14: CLI export HTML ────────────────────────────────────────


def test_cli_export_html(tmp_path):
    from policyshield.cli.main import app

    trace = tmp_path / "trace.jsonl"
    _write_trace(trace, _sample_records())
    out_html = tmp_path / "report.html"

    rc = app(["trace", "export", str(trace), "--format", "html", "--output", str(out_html)])
    assert rc == 0
    assert out_html.exists()


# ── Test 15: CLI export auto name ───────────────────────────────────


def test_cli_export_auto_name(tmp_path, monkeypatch):
    from policyshield.cli.main import app

    trace = tmp_path / "trace.jsonl"
    _write_trace(trace, _sample_records())
    monkeypatch.chdir(tmp_path)

    rc = app(["trace", "export", str(trace), "--format", "csv"])
    assert rc == 0
    # Auto-generated CSV file should exist matching pattern trace_export_*.csv
    csv_files = list(tmp_path.glob("trace_export_*.csv"))
    assert len(csv_files) == 1
