"""Rate limiter engine for PolicyShield — sliding window per-tool/per-session limits."""

from __future__ import annotations

import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class RateLimitConfig:
    """Configuration for a single rate limit rule.

    Args:
        tool: Tool name pattern (exact match or '*' for all tools).
        max_calls: Maximum number of calls allowed in the window.
        window_seconds: Sliding window size in seconds.
        per_session: If True, limit is per-session. If False, global.
        message: Optional message when limit is exceeded.
    """

    tool: str
    max_calls: int
    window_seconds: float
    per_session: bool = True
    message: str = "Rate limit exceeded"


@dataclass
class _SlidingWindow:
    """Sliding window counter for rate limiting."""

    timestamps: deque[float] = field(default_factory=deque)

    def add(self, now: float) -> None:
        self.timestamps.append(now)

    def _count_and_prune(self, now: float, window: float) -> int:
        """Count timestamps in window, pruning expired ones (mutates deque).

        Issue #143: Renamed from count_in_window to signal mutation side-effect.
        """
        cutoff = now - window
        # Remove expired timestamps from left (oldest first) — O(1) amortized
        while self.timestamps and self.timestamps[0] <= cutoff:
            self.timestamps.popleft()
        return len(self.timestamps)


class RateLimiter:
    """Sliding-window rate limiter.

    Supports per-tool and per-session rate limits configured via YAML DSL.
    """

    def __init__(self, configs: list[RateLimitConfig] | None = None):
        self._configs: list[RateLimitConfig] = list(configs or [])
        # key = (tool, session_id) for per-session, (tool, "__global__") for global
        self._windows: dict[tuple[str, str], _SlidingWindow] = defaultdict(_SlidingWindow)
        self._lock = threading.Lock()
        self._last_cleanup = 0.0
        self._cleanup_interval = 60.0  # seconds between stale window evictions

    def _cleanup_stale_windows(self, now: float) -> None:
        """Remove windows with no recent timestamps to prevent memory leaks.

        Must be called under self._lock.
        """
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        max_window = max((c.window_seconds for c in self._configs), default=60)
        stale_keys = [
            k for k, w in self._windows.items() if not w.timestamps or (now - w.timestamps[-1]) > max_window * 2
        ]
        for k in stale_keys:
            del self._windows[k]

    @classmethod
    def from_yaml_dict(cls, data: list[dict]) -> RateLimiter:
        """Create a RateLimiter from YAML config dicts.

        Expected format:
        ```yaml
        rate_limits:
          - tool: web_fetch
            max_calls: 10
            window_seconds: 60
            per_session: true
            message: "Too many web fetches"
        ```
        """
        configs = []
        for i, item in enumerate(data):
            # Issue #150: Validate required keys and values
            if "max_calls" not in item:
                raise ValueError(f"Rate limit entry #{i}: missing required key 'max_calls'")
            max_calls = int(item["max_calls"])
            if max_calls <= 0:
                raise ValueError(f"Rate limit entry #{i}: max_calls must be > 0, got {max_calls}")
            window_seconds = float(item.get("window_seconds", 60))
            if window_seconds <= 0:
                raise ValueError(f"Rate limit entry #{i}: window_seconds must be > 0, got {window_seconds}")
            configs.append(
                RateLimitConfig(
                    tool=item.get("tool", "*"),
                    max_calls=max_calls,
                    window_seconds=window_seconds,
                    per_session=item.get("per_session", True),
                    message=item.get("message", "Rate limit exceeded"),
                )
            )
        return cls(configs)

    def check(self, tool_name: str, session_id: str = "default") -> RateLimitResult:
        """Check if a tool call is within rate limits (read-only).

        .. note:: Prefer :meth:`check_and_record` for thread-safe usage.

        Args:
            tool_name: Name of the tool being called.
            session_id: Session identifier.

        Returns:
            RateLimitResult indicating whether the call is allowed.
        """
        now = time.monotonic()

        with self._lock:
            self._cleanup_stale_windows(now)
            for config in self._configs:
                if config.tool != "*" and config.tool != tool_name:
                    continue

                key = (
                    config.tool,
                    session_id if config.per_session else "__global__",
                )
                window = self._windows[key]
                count = window._count_and_prune(now, config.window_seconds)

                if count >= config.max_calls:
                    return RateLimitResult(
                        allowed=False,
                        tool=tool_name,
                        limit=config.max_calls,
                        window_seconds=config.window_seconds,
                        current_count=count,
                        message=config.message,
                    )

        return RateLimitResult(allowed=True, tool=tool_name)

    def check_and_record(self, tool_name: str, session_id: str = "default") -> RateLimitResult:
        """Atomically check and record a tool call.

        Prevents TOCTOU races where concurrent threads could both pass
        ``check()`` before either calls ``record()``.
        """
        now = time.monotonic()

        with self._lock:
            self._cleanup_stale_windows(now)
            for config in self._configs:
                if config.tool != "*" and config.tool != tool_name:
                    continue

                key = (
                    config.tool,
                    session_id if config.per_session else "__global__",
                )
                window = self._windows[key]
                count = window._count_and_prune(now, config.window_seconds)

                if count >= config.max_calls:
                    return RateLimitResult(
                        allowed=False,
                        tool=tool_name,
                        limit=config.max_calls,
                        window_seconds=config.window_seconds,
                        current_count=count,
                        message=config.message,
                    )

            # Record under same lock — atomic with check
            for config in self._configs:
                if config.tool != "*" and config.tool != tool_name:
                    continue
                key = (
                    config.tool,
                    session_id if config.per_session else "__global__",
                )
                self._windows[key].add(now)

        return RateLimitResult(allowed=True, tool=tool_name)

    def record(self, tool_name: str, session_id: str = "default") -> None:
        """Record a tool call for rate limiting.

        Args:
            tool_name: Name of the tool called.
            session_id: Session identifier.
        """
        now = time.monotonic()

        with self._lock:
            for config in self._configs:
                if config.tool != "*" and config.tool != tool_name:
                    continue
                key = (
                    config.tool,
                    session_id if config.per_session else "__global__",
                )
                self._windows[key].add(now)

    def reset(self, session_id: str | None = None) -> None:
        """Reset counters.

        Args:
            session_id: If provided, only reset for this session. Otherwise reset all.
        """
        with self._lock:
            if session_id is None:
                self._windows.clear()
            else:
                keys_to_remove = [k for k in self._windows if k[1] == session_id]
                for k in keys_to_remove:
                    del self._windows[k]


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    tool: str = ""
    limit: int = 0
    window_seconds: float = 0
    current_count: int = 0
    message: str = ""
