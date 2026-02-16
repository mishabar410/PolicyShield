import json
from pathlib import Path

from policyshield.replay.loader import TraceLoader


def _write_traces(path: Path, entries: list[dict]):
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def test_load_single_file(tmp_path):
    trace_file = tmp_path / "trace.jsonl"
    _write_traces(
        trace_file,
        [
            {"timestamp": "2026-01-01T00:00:00+00:00", "session_id": "s1", "tool": "read_file", "verdict": "allow"},
            {"timestamp": "2026-01-01T00:01:00+00:00", "session_id": "s1", "tool": "write_file", "verdict": "block"},
        ],
    )

    loader = TraceLoader.from_path(trace_file)
    entries = loader.load()
    assert len(entries) == 2
    assert entries[0].tool == "read_file"
    assert entries[1].verdict == "block"


def test_load_directory(tmp_path):
    _write_traces(
        tmp_path / "a.jsonl",
        [
            {"timestamp": "2026-01-01T00:00:00+00:00", "session_id": "s1", "tool": "t1", "verdict": "allow"},
        ],
    )
    _write_traces(
        tmp_path / "b.jsonl",
        [
            {"timestamp": "2026-01-01T00:01:00+00:00", "session_id": "s2", "tool": "t2", "verdict": "block"},
        ],
    )

    loader = TraceLoader.from_path(tmp_path)
    entries = loader.load()
    assert len(entries) == 2


def test_filter_by_session(tmp_path):
    trace_file = tmp_path / "trace.jsonl"
    _write_traces(
        trace_file,
        [
            {"timestamp": "2026-01-01T00:00:00+00:00", "session_id": "s1", "tool": "t1", "verdict": "allow"},
            {"timestamp": "2026-01-01T00:01:00+00:00", "session_id": "s2", "tool": "t2", "verdict": "allow"},
        ],
    )

    loader = TraceLoader.from_path(trace_file)
    entries = loader.load(session_id="s1")
    assert len(entries) == 1
    assert entries[0].session_id == "s1"


def test_filter_by_verdict(tmp_path):
    trace_file = tmp_path / "trace.jsonl"
    _write_traces(
        trace_file,
        [
            {"timestamp": "2026-01-01T00:00:00+00:00", "session_id": "s1", "tool": "t1", "verdict": "allow"},
            {"timestamp": "2026-01-01T00:01:00+00:00", "session_id": "s1", "tool": "t2", "verdict": "block"},
        ],
    )

    loader = TraceLoader.from_path(trace_file)
    entries = loader.load(verdict="block")
    assert len(entries) == 1


def test_skip_malformed_lines(tmp_path):
    trace_file = tmp_path / "trace.jsonl"
    with open(trace_file, "w") as f:
        f.write('{"timestamp":"2026-01-01T00:00:00+00:00","session_id":"s1","tool":"t1","verdict":"allow"}\n')
        f.write("not json\n")
        f.write('{"timestamp":"2026-01-01T00:02:00+00:00","session_id":"s1","tool":"t2","verdict":"block"}\n')

    loader = TraceLoader.from_path(trace_file)
    entries = loader.load()
    assert len(entries) == 2


def test_stats(tmp_path):
    trace_file = tmp_path / "trace.jsonl"
    _write_traces(
        trace_file,
        [
            {"timestamp": "2026-01-01T00:00:00+00:00", "session_id": "s1", "tool": "t1", "verdict": "allow"},
            {"timestamp": "2026-01-01T00:01:00+00:00", "session_id": "s2", "tool": "t2", "verdict": "block"},
        ],
    )

    loader = TraceLoader.from_path(trace_file)
    s = loader.stats()
    assert s["total_entries"] == 2
    assert s["session_count"] == 2
    assert s["tool_count"] == 2


def test_file_not_found():
    import pytest

    with pytest.raises(FileNotFoundError):
        TraceLoader.from_path("/nonexistent/path")


def test_empty_directory(tmp_path):
    import pytest

    with pytest.raises(ValueError, match="No .jsonl"):
        TraceLoader.from_path(tmp_path)
