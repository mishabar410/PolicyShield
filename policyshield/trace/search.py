"""Trace search engine — full-text and structured search across JSONL trace files."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class SearchQuery:
    """Search query parameters for filtering trace records."""

    tool: str | None = None
    verdict: str | None = None
    session_id: str | None = None
    text: str | None = None
    rule_id: str | None = None
    pii_type: str | None = None
    time_from: datetime | None = None
    time_to: datetime | None = None
    limit: int = 100
    offset: int = 0


@dataclass
class SearchResult:
    """Result of a search query."""

    total: int
    records: list[dict] = field(default_factory=list)
    query: SearchQuery = field(default_factory=SearchQuery)


class TraceSearchEngine:
    """Full-text and structured search across JSONL trace files.

    Supports filtering by tool, verdict, session, rule, PII type,
    time range, and free-text search in args/message fields.
    """

    def __init__(self, trace_dir: str | Path) -> None:
        self._trace_dir = Path(trace_dir)

    def search(self, query: SearchQuery) -> SearchResult:
        """Synchronous search across all JSONL trace files."""
        all_records = self._load_all_records()
        matched = [r for r in all_records if self._matches(r, query)]
        total = len(matched)
        page = matched[query.offset : query.offset + query.limit]
        return SearchResult(total=total, records=page, query=query)

    async def async_search(self, query: SearchQuery) -> SearchResult:
        """Asynchronous search across all JSONL trace files.

        Uses aiofiles if available, falls back to sync.
        """
        try:
            import aiofiles

            all_records = await self._async_load_all_records(aiofiles)
        except ImportError:
            all_records = self._load_all_records()
        matched = [r for r in all_records if self._matches(r, query)]
        total = len(matched)
        page = matched[query.offset : query.offset + query.limit]
        return SearchResult(total=total, records=page, query=query)

    def _matches(self, record: dict, query: SearchQuery) -> bool:
        """Check if a record matches all query filters."""
        if query.tool is not None and record.get("tool") != query.tool:
            return False

        if query.verdict is not None and record.get("verdict") != query.verdict:
            return False

        if query.session_id is not None and record.get("session_id") != query.session_id:
            return False

        if query.rule_id is not None:
            matched_rule = record.get("rule_id", "")
            if query.rule_id not in str(matched_rule):
                return False

        if query.pii_type is not None:
            pii_found = record.get("pii_types", [])
            if query.pii_type not in pii_found:
                return False

        if query.time_from is not None or query.time_to is not None:
            ts_str = record.get("timestamp")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str)
                    if query.time_from is not None and ts < query.time_from:
                        return False
                    if query.time_to is not None and ts > query.time_to:
                        return False
                except ValueError:
                    return False
            else:
                return False

        if query.text is not None:
            if not self._full_text_match(record, query.text):
                return False

        return True

    def _full_text_match(self, record: dict, text: str) -> bool:
        """Search for text in args (recursively), message, and tool fields."""
        text_lower = text.lower()

        # Check tool
        if text_lower in str(record.get("tool", "")).lower():
            return True

        # Check message
        if text_lower in str(record.get("message", "")).lower():
            return True

        # Check args recursively
        args = record.get("args")
        if args is not None and self._search_in_value(args, text_lower):
            return True

        return False

    def _search_in_value(self, value: Any, text: str) -> bool:
        """Recursively search for text in a value (dict, list, or scalar)."""
        if isinstance(value, dict):
            for v in value.values():
                if self._search_in_value(v, text):
                    return True
        elif isinstance(value, list):
            for item in value:
                if self._search_in_value(item, text):
                    return True
        else:
            if text in str(value).lower():
                return True
        return False

    def _load_all_records(self) -> list[dict]:
        """Load records from all JSONL files in the trace directory."""
        records: list[dict] = []
        if not self._trace_dir.exists():
            return records
        for jsonl_file in sorted(self._trace_dir.glob("*.jsonl")):
            with jsonl_file.open() as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        return records

    async def _async_load_all_records(self, aiofiles: Any) -> list[dict]:
        """Async load records from all JSONL files."""
        records: list[dict] = []
        if not self._trace_dir.exists():
            return records
        for jsonl_file in sorted(self._trace_dir.glob("*.jsonl")):
            async with aiofiles.open(jsonl_file) as f:
                async for line in f:
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        return records
