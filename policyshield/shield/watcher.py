"""File watcher for hot-reloading YAML rules."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable

from policyshield.core.models import RuleSet
from policyshield.core.parser import load_rules

logger = logging.getLogger("policyshield")


class RuleWatcher:
    """Watches YAML rule files for changes and triggers reload.

    Uses polling-based change detection (no external dependencies).

    Args:
        path: Path to YAML file or directory to watch.
        callback: Called with the new RuleSet when changes are detected.
        poll_interval: Seconds between checks.
    """

    def __init__(
        self,
        path: str | Path,
        callback: Callable[[RuleSet], None],
        poll_interval: float = 2.0,
    ):
        self._path = Path(path)
        self._callback = callback
        self._poll_interval = poll_interval
        self._mtimes: dict[Path, float] = {}
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._scan_mtimes()

    def _scan_mtimes(self) -> None:
        """Build initial mtime map."""
        if self._path.is_file():
            self._mtimes[self._path] = self._path.stat().st_mtime
        elif self._path.is_dir():
            for f in self._path.glob("*.yaml"):
                self._mtimes[f] = f.stat().st_mtime
            for f in self._path.glob("*.yml"):
                self._mtimes[f] = f.stat().st_mtime

    def start(self) -> None:
        """Start watching in a background daemon thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop watching."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    @property
    def is_alive(self) -> bool:
        """Return True if watcher thread is running."""
        return self._thread is not None and self._thread.is_alive()

    def _watch_loop(self) -> None:
        """Main polling loop."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self._poll_interval)
            if self._stop_event.is_set():
                break
            try:
                if self._has_changes():
                    self._reload()
            except Exception as e:
                logger.warning("Watcher error: %s", e)

    def _has_changes(self) -> bool:
        """Check if any YAML file has been modified."""
        current: dict[Path, float] = {}
        if self._path.is_file():
            current[self._path] = self._path.stat().st_mtime
        elif self._path.is_dir():
            for f in self._path.glob("*.yaml"):
                current[f] = f.stat().st_mtime
            for f in self._path.glob("*.yml"):
                current[f] = f.stat().st_mtime

        changed = current != self._mtimes
        if changed:
            self._mtimes = current
        return changed

    def _reload(self) -> None:
        """Attempt to reload rules and invoke callback."""
        try:
            new_ruleset = load_rules(self._path)
            self._callback(new_ruleset)
            logger.info("Rules hot-reloaded from %s", self._path)
        except Exception as e:
            logger.warning("Hot reload failed (keeping old rules): %s", e)
