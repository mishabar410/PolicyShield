"""Trace recorder for PolicyShield — JSONL audit logging."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from policyshield.core.models import Verdict

logger = logging.getLogger(__name__)


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
        max_file_size: int = 100 * 1024 * 1024,  # 100MB
        rotation: str = "size",  # "size" | "daily" | "none"
        retention_days: int = 30,
    ):
        import atexit

        self._output_dir = Path(output_dir)
        self._batch_size = batch_size
        self._privacy_mode = privacy_mode
        self._max_file_size = max_file_size
        self._rotation = rotation
        self._retention_days = retention_days
        self._current_date = datetime.now(timezone.utc).strftime("%Y%m%d")
        self._buffer: list[dict] = []
        self._file_path: Path | None = None
        self._record_count = 0
        self._lock = threading.Lock()
        self._closed = False

        # Ensure output directory exists
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._file_path = self._generate_file_path()

        # Register atexit handler for crash safety
        atexit.register(self._atexit_flush)

    def close(self) -> None:
        """Flush and deregister atexit handler."""
        import atexit

        if not self._closed:
            self.flush()
            atexit.unregister(self._atexit_flush)
            self._closed = True

    def __enter__(self) -> TraceRecorder:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _atexit_flush(self) -> None:
        """Flush remaining buffer on process exit (best effort)."""
        if not self._closed:
            try:
                self.flush()
            except Exception:
                pass

    def _generate_file_path(self) -> Path:
        """Generate a timestamped trace file path (unique even within same second)."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base = self._output_dir / f"trace_{timestamp}.jsonl"
        if not base.exists():
            return base
        # Append counter to avoid collisions during rapid rotation
        counter = 1
        while True:
            candidate = self._output_dir / f"trace_{timestamp}_{counter}.jsonl"
            if not candidate.exists():
                return candidate
            counter += 1

    def record(
        self,
        session_id: str,
        tool: str,
        verdict: Verdict,
        rule_id: str | None = None,
        pii_types: list[str] | None = None,
        latency_ms: float = 0.0,
        args: dict | None = None,
        approval_info: dict | None = None,
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
            approval_info: Optional approval audit trail data.
        """
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
        if approval_info:
            entry["approval"] = approval_info

        with self._lock:
            self._buffer.append(entry)
            self._record_count += 1

            if len(self._buffer) >= self._batch_size:
                self._flush_unlocked()

    def flush(self) -> None:
        """Write buffered records to the trace file."""
        with self._lock:
            self._flush_unlocked()

    def _open_file(self, path: Path):
        """Open trace file with restricted permissions (0o600 on Unix)."""
        import sys

        if sys.platform != "win32":
            if not path.exists():
                path.touch(mode=0o600)
            else:
                current = path.stat().st_mode & 0o777
                if current != 0o600:
                    os.chmod(path, 0o600)
                    logger.warning(
                        "Fixed trace file permissions: %s (%o → 600)",
                        path,
                        current,
                    )
        elif not path.exists():
            path.touch()
        return open(path, "a", encoding="utf-8")  # noqa: SIM115

    def _flush_unlocked(self) -> None:
        """Flush buffer without acquiring the lock (caller must hold it)."""
        if not self._buffer:
            return

        if self._should_rotate():
            self._rotate()

        try:
            assert self._file_path is not None
            with self._open_file(self._file_path) as f:
                for entry in self._buffer:
                    f.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.error(
                "Failed to write trace file %s: %s (retaining %d records for retry)",
                self._file_path,
                exc,
                len(self._buffer),
            )
            # Don't clear buffer — records will be retried on next flush.
            # Cap retained buffer to prevent unbounded memory growth.
            max_retained = self._batch_size * 10
            if len(self._buffer) > max_retained:
                dropped = len(self._buffer) - max_retained
                self._buffer = self._buffer[-max_retained:]
                logger.warning("Trace buffer overflow: dropped %d oldest records", dropped)
            return

        self._buffer.clear()

    @property
    def record_count(self) -> int:
        """Return total records written (including buffered)."""
        return self._record_count

    @property
    def file_path(self) -> Path | None:
        """Return the current trace file path."""
        return self._file_path

    def _should_rotate(self) -> bool:
        """Check if current trace file needs rotation."""
        if self._file_path is None or not self._file_path.exists():
            return False
        if self._rotation == "size":
            return self._file_path.stat().st_size >= self._max_file_size
        if self._rotation == "daily":
            today = datetime.now(timezone.utc).strftime("%Y%m%d")
            return today != self._current_date
        return False

    def _rotate(self) -> None:
        """Rotate to a new trace file."""
        self._file_path = self._generate_file_path()
        self._current_date = datetime.now(timezone.utc).strftime("%Y%m%d")
        logger.info("Rotated trace file to %s", self._file_path)

    def cleanup_old_traces(self) -> int:
        """Remove trace files older than retention_days. Returns count removed."""
        if self._retention_days <= 0:
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._retention_days)
        removed = 0
        for f in self._output_dir.glob("trace_*.jsonl"):
            if f.stat().st_mtime < cutoff.timestamp():
                f.unlink()
                removed += 1
        if removed:
            logger.info(
                "Cleaned up %d old trace files (retention=%dd)",
                removed,
                self._retention_days,
            )
        return removed
