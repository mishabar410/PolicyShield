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
                            line_num,
                            path,
                            exc,
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
