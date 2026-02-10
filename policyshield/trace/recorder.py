"""Trace recorder for PolicyShield — JSONL audit logging."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from policyshield.core.models import Verdict


def compute_args_hash(args: dict) -> str:
    """Compute a SHA-256 hash of arguments for privacy mode.

    Args:
        args: Argument dictionary to hash.

    Returns:
        Hex string of SHA-256 hash.
    """
    serialized = json.dumps(args, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


class TraceRecorder:
    """Records audit logs in JSONL format.

    Features:
        - Batched writes for performance
        - Privacy mode (args hashing)
        - Context manager support
        - Auto-named trace files
    """

    def __init__(
        self,
        output_dir: str | Path,
        batch_size: int = 100,
        privacy_mode: bool = False,
    ):
        self._output_dir = Path(output_dir)
        self._batch_size = batch_size
        self._privacy_mode = privacy_mode
        self._buffer: list[dict] = []
        self._file_path: Path | None = None
        self._record_count = 0

        # Ensure output directory exists
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._file_path = self._generate_file_path()

    def _generate_file_path(self) -> Path:
        """Generate a timestamped trace file path."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self._output_dir / f"trace_{timestamp}.jsonl"

    def record(
        self,
        session_id: str,
        tool: str,
        verdict: Verdict,
        rule_id: str | None = None,
        pii_types: list[str] | None = None,
        latency_ms: float = 0.0,
        args: dict | None = None,
    ) -> None:
        """Add a trace record to the buffer.

        Args:
            session_id: Session identifier.
            tool: Tool name.
            verdict: The verdict.
            rule_id: ID of the matched rule.
            pii_types: List of detected PII type names.
            latency_ms: Processing latency in milliseconds.
            args: Original arguments (hashed in privacy mode).
        """
        entry: dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "session_id": session_id,
            "tool": tool,
            "verdict": verdict.value,
        }

        if rule_id:
            entry["rule_id"] = rule_id
        if pii_types:
            entry["pii_types"] = pii_types
        if latency_ms > 0:
            entry["latency_ms"] = round(latency_ms, 2)
        if args:
            if self._privacy_mode:
                entry["args_hash"] = compute_args_hash(args)
            else:
                entry["args"] = args

        self._buffer.append(entry)
        self._record_count += 1

        if len(self._buffer) >= self._batch_size:
            self.flush()

    def flush(self) -> None:
        """Write buffered records to the trace file."""
        if not self._buffer:
            return

        with open(self._file_path, "a", encoding="utf-8") as f:
            for entry in self._buffer:
                f.write(json.dumps(entry, default=str) + "\n")

        self._buffer.clear()

    @property
    def record_count(self) -> int:
        """Return total records written (including buffered)."""
        return self._record_count

    @property
    def file_path(self) -> Path | None:
        """Return the current trace file path."""
        return self._file_path

    def __enter__(self) -> TraceRecorder:
        return self

    def __exit__(self, *args) -> None:
        self.flush()
