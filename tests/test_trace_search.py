"""Tests for trace search engine."""

import json
from datetime import datetime, timedelta

import pytest

from policyshield.trace.search import SearchQuery, TraceSearchEngine


def _make_record(
    tool="exec",
    verdict="ALLOW",
    session_id="s1",
    timestamp=None,
    rule_id=None,
    pii_types=None,
    args=None,
    message=None,
):
    """Create a trace record dict."""
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
    if message:
        rec["message"] = message
    return rec


def _write_jsonl(path, records):
    """Write records to a JSONL file."""
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


@pytest.fixture
def trace_dir(tmp_path):
    """Create a trace directory with sample data."""
    d = tmp_path / "traces"
    d.mkdir()
    return d


@pytest.fixture
def sample_records():
    """Return a list of sample trace records."""
    base = datetime(2025, 1, 1, 12, 0, 0)
    return [
        _make_record(tool="exec", verdict="BLOCK", session_id="s1", timestamp=(base + timedelta(minutes=0)).isoformat(), rule_id="block-exec", args={"command": "rm -rf /"}, message="Blocked dangerous command"),
        _make_record(tool="read_file", verdict="ALLOW", session_id="s1", timestamp=(base + timedelta(minutes=1)).isoformat(), args={"path": "/etc/passwd"}),
        _make_record(tool="web_fetch", verdict="REDACT", session_id="s2", timestamp=(base + timedelta(minutes=2)).isoformat(), pii_types=["EMAIL", "PHONE"], rule_id="redact-pii"),
        _make_record(tool="send_message", verdict="BLOCK", session_id="s2", timestamp=(base + timedelta(minutes=3)).isoformat(), rule_id="block-send", args={"to": "user@example.com", "body": "Hello"}),
        _make_record(tool="exec", verdict="ALLOW", session_id="s3", timestamp=(base + timedelta(minutes=4)).isoformat(), args={"command": "ls -la"}),
        _make_record(tool="web_fetch", verdict="ALLOW", session_id="s3", timestamp=(base + timedelta(minutes=5)).isoformat(), args={"url": "https://example.com"}),
        _make_record(tool="write_file", verdict="REDACT", session_id="s1", timestamp=(base + timedelta(minutes=6)).isoformat(), pii_types=["SSN"], rule_id="redact-pii"),
        _make_record(tool="exec", verdict="BLOCK", session_id="s4", timestamp=(base + timedelta(minutes=7)).isoformat(), rule_id="block-exec", args={"command": "sudo shutdown"}),
        _make_record(tool="send_message", verdict="ALLOW", session_id="s4", timestamp=(base + timedelta(minutes=8)).isoformat(), args={"to": "admin", "body": "Report ready"}),
        _make_record(tool="read_file", verdict="ALLOW", session_id="s5", timestamp=(base + timedelta(minutes=9)).isoformat(), args={"path": "/tmp/data.json"}),
    ]


@pytest.fixture
def populated_trace_dir(trace_dir, sample_records):
    """Create a trace dir with one JSONL file."""
    _write_jsonl(trace_dir / "trace_20250101.jsonl", sample_records)
    return trace_dir


class TestSearchByTool:
    def test_search_by_tool(self, populated_trace_dir):
        engine = TraceSearchEngine(populated_trace_dir)
        result = engine.search(SearchQuery(tool="exec"))
        assert result.total == 3
        assert all(r["tool"] == "exec" for r in result.records)


class TestSearchByVerdict:
    def test_search_by_verdict(self, populated_trace_dir):
        engine = TraceSearchEngine(populated_trace_dir)
        result = engine.search(SearchQuery(verdict="BLOCK"))
        assert result.total == 3
        assert all(r["verdict"] == "BLOCK" for r in result.records)
        # Should not include ALLOW
        for r in result.records:
            assert r["verdict"] != "ALLOW"


class TestSearchBySession:
    def test_search_by_session(self, populated_trace_dir):
        engine = TraceSearchEngine(populated_trace_dir)
        result = engine.search(SearchQuery(session_id="s2"))
        assert result.total == 2
        assert all(r["session_id"] == "s2" for r in result.records)


class TestSearchFullText:
    def test_search_full_text(self, populated_trace_dir):
        engine = TraceSearchEngine(populated_trace_dir)
        # Search for text in args
        result = engine.search(SearchQuery(text="rm -rf"))
        assert result.total == 1
        assert result.records[0]["tool"] == "exec"

    def test_search_full_text_in_message(self, populated_trace_dir):
        engine = TraceSearchEngine(populated_trace_dir)
        result = engine.search(SearchQuery(text="dangerous"))
        assert result.total == 1

    def test_search_full_text_case_insensitive(self, populated_trace_dir):
        engine = TraceSearchEngine(populated_trace_dir)
        result = engine.search(SearchQuery(text="EXAMPLE.COM"))
        assert result.total >= 1


class TestSearchByRuleId:
    def test_search_by_rule_id(self, populated_trace_dir):
        engine = TraceSearchEngine(populated_trace_dir)
        result = engine.search(SearchQuery(rule_id="block-exec"))
        assert result.total == 2
        assert all("block-exec" in r.get("rule_id", "") for r in result.records)


class TestSearchByPiiType:
    def test_search_by_pii_type(self, populated_trace_dir):
        engine = TraceSearchEngine(populated_trace_dir)
        result = engine.search(SearchQuery(pii_type="EMAIL"))
        assert result.total == 1
        assert "EMAIL" in result.records[0]["pii_types"]


class TestSearchTimeRange:
    def test_search_time_range(self, populated_trace_dir, sample_records):
        engine = TraceSearchEngine(populated_trace_dir)
        base = datetime(2025, 1, 1, 12, 0, 0)
        query = SearchQuery(
            time_from=base + timedelta(minutes=2),
            time_to=base + timedelta(minutes=5),
        )
        result = engine.search(query)
        assert result.total == 4  # minutes 2, 3, 4, 5


class TestCombinedFilters:
    def test_search_combined_filters(self, populated_trace_dir):
        engine = TraceSearchEngine(populated_trace_dir)
        result = engine.search(SearchQuery(tool="exec", verdict="BLOCK"))
        assert result.total == 2
        for r in result.records:
            assert r["tool"] == "exec"
            assert r["verdict"] == "BLOCK"


class TestPagination:
    def test_search_pagination(self, populated_trace_dir):
        engine = TraceSearchEngine(populated_trace_dir)
        # Get first page
        r1 = engine.search(SearchQuery(limit=5, offset=0))
        assert len(r1.records) == 5
        assert r1.total == 10

        # Get second page
        r2 = engine.search(SearchQuery(limit=5, offset=5))
        assert len(r2.records) == 5
        assert r2.total == 10

        # Records should be different
        ids1 = {r["timestamp"] for r in r1.records}
        ids2 = {r["timestamp"] for r in r2.records}
        assert ids1.isdisjoint(ids2)


class TestEmptyResult:
    def test_search_empty_result(self, populated_trace_dir):
        engine = TraceSearchEngine(populated_trace_dir)
        result = engine.search(SearchQuery(tool="nonexistent_tool"))
        assert result.total == 0
        assert result.records == []


class TestMultipleFiles:
    def test_search_multiple_files(self, trace_dir, sample_records):
        # Write records across two files
        _write_jsonl(trace_dir / "trace_20250101.jsonl", sample_records[:5])
        _write_jsonl(trace_dir / "trace_20250102.jsonl", sample_records[5:])

        engine = TraceSearchEngine(trace_dir)
        result = engine.search(SearchQuery())
        assert result.total == 10


class TestCLIIntegration:
    def test_search_cli_integration(self, populated_trace_dir):
        from policyshield.cli.main import app

        exit_code = app(["trace", "search", "--dir", str(populated_trace_dir), "--tool", "exec", "--format", "json"])
        assert exit_code == 0

    def test_search_cli_help(self):
        from policyshield.cli.main import app

        with pytest.raises(SystemExit) as exc_info:
            app(["trace", "search", "--help"])
        assert exc_info.value.code == 0


class TestAsyncSearch:
    @pytest.mark.asyncio
    async def test_async_search(self, populated_trace_dir):
        engine = TraceSearchEngine(populated_trace_dir)
        # async_search should produce the same results as sync search
        sync_result = engine.search(SearchQuery(tool="exec"))
        async_result = await engine.async_search(SearchQuery(tool="exec"))
        assert async_result.total == sync_result.total
        assert len(async_result.records) == len(sync_result.records)


class TestSearchResult:
    def test_search_result_has_query(self, populated_trace_dir):
        engine = TraceSearchEngine(populated_trace_dir)
        query = SearchQuery(tool="exec")
        result = engine.search(query)
        assert result.query is query

    def test_search_result_empty_dir(self, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        engine = TraceSearchEngine(empty_dir)
        result = engine.search(SearchQuery())
        assert result.total == 0
        assert result.records == []

    def test_search_nonexistent_dir(self, tmp_path):
        engine = TraceSearchEngine(tmp_path / "does_not_exist")
        result = engine.search(SearchQuery())
        assert result.total == 0
