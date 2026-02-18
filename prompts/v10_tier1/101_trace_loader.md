# Prompt 101 — Trace Loader

## Цель

Создать модуль `policyshield/replay/loader.py` — загрузчик JSONL-трейсов для replay. Парсит файлы трейсов, фильтрует записи, возвращает итератор `TraceEntry`.

## Контекст

- Трейсы хранятся в JSONL (по одному JSON-объекту на строку)
- Формат записи (из `trace/recorder.py`):
  ```json
  {"timestamp": "2026-...", "session_id": "s1", "tool": "read_file", "verdict": "allow", "rule_id": "rule-1", "args": {"path": "/tmp/x"}, "latency_ms": 1.23}
  ```
- Нужен удобный dataclass `TraceEntry` для работы с записями
- Фильтрация: по session_id, tool, verdict, time range
- Должен работать с несколькими файлами (directory glob)

## Что сделать

### 1. Создать `policyshield/replay/__init__.py`

Пустой, для пакета.

### 2. Создать `policyshield/replay/loader.py`

```python
"""Trace loader for PolicyShield replay — parses JSONL trace files."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class TraceEntry:
    """A single trace record loaded from JSONL."""

    timestamp: str
    session_id: str
    tool: str
    verdict: str
    rule_id: str | None = None
    args: dict = field(default_factory=dict)
    pii_types: list[str] = field(default_factory=list)
    latency_ms: float = 0.0

    @property
    def datetime(self) -> datetime:
        """Parse timestamp as datetime."""
        return datetime.fromisoformat(self.timestamp)


class TraceLoader:
    """Loads and filters JSONL trace files for replay.

    Supports loading from a single file, multiple files, or a directory.
    Provides filtering by session, tool, verdict, and time range.
    """

    def __init__(self, paths: list[Path]) -> None:
        self._paths = paths

    @classmethod
    def from_path(cls, path: str | Path) -> TraceLoader:
        """Create a loader from a file or directory path.

        Args:
            path: Path to a JSONL file or directory containing JSONL files.

        Returns:
            TraceLoader instance.

        Raises:
            FileNotFoundError: If path does not exist.
            ValueError: If no JSONL files found.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Path not found: {p}")

        if p.is_file():
            return cls([p])

        files = sorted(p.glob("*.jsonl"))
        if not files:
            raise ValueError(f"No .jsonl files found in {p}")
        return cls(files)

    def load(
        self,
        *,
        session_id: str | None = None,
        tool: str | None = None,
        verdict: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[TraceEntry]:
        """Load and filter trace entries.

        Args:
            session_id: Filter by session ID.
            tool: Filter by tool name (exact match).
            verdict: Filter by verdict (allow, block, redact, approve).
            since: Only entries after this timestamp.
            until: Only entries before this timestamp.

        Returns:
            List of matching TraceEntry objects, sorted by timestamp.
        """
        entries = []
        for entry in self._iter_raw():
            if session_id and entry.session_id != session_id:
                continue
            if tool and entry.tool != tool:
                continue
            if verdict and entry.verdict.lower() != verdict.lower():
                continue
            if since and entry.datetime < since:
                continue
            if until and entry.datetime > until:
                continue
            entries.append(entry)

        return sorted(entries, key=lambda e: e.timestamp)

    def _iter_raw(self) -> Iterator[TraceEntry]:
        """Iterate over all trace entries from all files."""
        for path in self._paths:
            with open(path, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        yield TraceEntry(
                            timestamp=data.get("timestamp", ""),
                            session_id=data.get("session_id", ""),
                            tool=data.get("tool", ""),
                            verdict=data.get("verdict", ""),
                            rule_id=data.get("rule_id"),
                            args=data.get("args", {}),
                            pii_types=data.get("pii_types", []),
                            latency_ms=data.get("latency_ms", 0.0),
                        )
                    except (json.JSONDecodeError, KeyError) as exc:
                        # Skip malformed lines, log warning
                        import logging
                        logging.getLogger(__name__).warning(
                            "Skipping malformed line %d in %s: %s",
                            line_num, path, exc,
                        )

    def stats(self) -> dict:
        """Return summary statistics about loaded traces.

        Returns:
            Dict with file_count, total_entries, sessions, tools.
        """
        entries = self.load()
        sessions = set()
        tools = set()
        for e in entries:
            sessions.add(e.session_id)
            tools.add(e.tool)
        return {
            "file_count": len(self._paths),
            "total_entries": len(entries),
            "session_count": len(sessions),
            "tool_count": len(tools),
            "sessions": sorted(sessions),
            "tools": sorted(tools),
        }
```

### 3. Тесты

#### `tests/test_trace_loader.py`

```python
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone

from policyshield.replay.loader import TraceLoader, TraceEntry


def _write_traces(path: Path, entries: list[dict]):
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def test_load_single_file(tmp_path):
    trace_file = tmp_path / "trace.jsonl"
    _write_traces(trace_file, [
        {"timestamp": "2026-01-01T00:00:00+00:00", "session_id": "s1", "tool": "read_file", "verdict": "allow"},
        {"timestamp": "2026-01-01T00:01:00+00:00", "session_id": "s1", "tool": "write_file", "verdict": "block"},
    ])

    loader = TraceLoader.from_path(trace_file)
    entries = loader.load()
    assert len(entries) == 2
    assert entries[0].tool == "read_file"
    assert entries[1].verdict == "block"


def test_load_directory(tmp_path):
    _write_traces(tmp_path / "a.jsonl", [
        {"timestamp": "2026-01-01T00:00:00+00:00", "session_id": "s1", "tool": "t1", "verdict": "allow"},
    ])
    _write_traces(tmp_path / "b.jsonl", [
        {"timestamp": "2026-01-01T00:01:00+00:00", "session_id": "s2", "tool": "t2", "verdict": "block"},
    ])

    loader = TraceLoader.from_path(tmp_path)
    entries = loader.load()
    assert len(entries) == 2


def test_filter_by_session(tmp_path):
    trace_file = tmp_path / "trace.jsonl"
    _write_traces(trace_file, [
        {"timestamp": "2026-01-01T00:00:00+00:00", "session_id": "s1", "tool": "t1", "verdict": "allow"},
        {"timestamp": "2026-01-01T00:01:00+00:00", "session_id": "s2", "tool": "t2", "verdict": "allow"},
    ])

    loader = TraceLoader.from_path(trace_file)
    entries = loader.load(session_id="s1")
    assert len(entries) == 1
    assert entries[0].session_id == "s1"


def test_filter_by_verdict(tmp_path):
    trace_file = tmp_path / "trace.jsonl"
    _write_traces(trace_file, [
        {"timestamp": "2026-01-01T00:00:00+00:00", "session_id": "s1", "tool": "t1", "verdict": "allow"},
        {"timestamp": "2026-01-01T00:01:00+00:00", "session_id": "s1", "tool": "t2", "verdict": "block"},
    ])

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
    _write_traces(trace_file, [
        {"timestamp": "2026-01-01T00:00:00+00:00", "session_id": "s1", "tool": "t1", "verdict": "allow"},
        {"timestamp": "2026-01-01T00:01:00+00:00", "session_id": "s2", "tool": "t2", "verdict": "block"},
    ])

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
```

## Самопроверка

```bash
pytest tests/test_trace_loader.py -v
pytest tests/ -q
```

## Коммит

```
feat(replay): add trace loader for JSONL replay

- Add TraceEntry dataclass for parsed trace records
- Add TraceLoader with file/directory loading and glob support
- Filter by session_id, tool, verdict, time range
- Skip malformed lines with warning
- Stats helper for trace summary
```
