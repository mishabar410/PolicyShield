"""Rate limiter engine for PolicyShield — sliding window per-tool/per-session limits."""

from __future__ import annotations

import logging
import time
import threading
from collections import defaultdict
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

    timestamps: list[float] = field(default_factory=list)

    def add(self, now: float) -> None:
        self.timestamps.append(now)

    def count_in_window(self, now: float, window: float) -> int:
        cutoff = now - window
        self.timestamps = [t for t in self.timestamps if t > cutoff]
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
        for item in data:
            configs.append(
                RateLimitConfig(
                    tool=item.get("tool", "*"),
                    max_calls=int(item["max_calls"]),
                    window_seconds=float(item.get("window_seconds", 60)),
                    per_session=item.get("per_session", True),
                    message=item.get("message", "Rate limit exceeded"),
                )
            )
        return cls(configs)

    def check(self, tool_name: str, session_id: str = "default") -> RateLimitResult:
        """Check if a tool call is within rate limits.

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
                count = window.count_in_window(now, config.window_seconds)

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


_logger = logging.getLogger(__name__)


class GlobalRateLimiter:
    """Rate limiter across all tools for a session."""

    def __init__(self, max_calls: int = 1000, window: float = 3600.0) -> None:
        self._max_calls = max_calls
        self._window = window
        self._counters: dict[str, _SlidingWindow] = {}
        self._lock = threading.Lock()

    def check(self, session_id: str) -> bool:
        """Returns True if the call is allowed."""
        now = time.monotonic()
        with self._lock:
            if session_id not in self._counters:
                self._counters[session_id] = _SlidingWindow()
            counter = self._counters[session_id]
            count = counter.count_in_window(now, self._window)
            if count >= self._max_calls:
                return False
            counter.add(now)
            return True


class AdaptiveRateLimiter:
    """Automatically tightens rate limits on anomalous behavior."""

    def __init__(
        self,
        base_limit: int = 100,
        window: float = 60.0,
        burst_threshold: float = 3.0,
        tighten_factor: float = 0.5,
        cooldown: float = 300.0,
    ) -> None:
        self._base_limit = base_limit
        self._window = window
        self._burst_threshold = burst_threshold
        self._tighten_factor = tighten_factor
        self._cooldown = cooldown
        self._effective_limit = base_limit
        self._call_history: list[float] = []
        self._last_tighten: float = 0
        self._lock = threading.Lock()

    @property
    def effective_limit(self) -> int:
        with self._lock:
            if self._effective_limit < self._base_limit:
                if time.monotonic() - self._last_tighten > self._cooldown:
                    self._effective_limit = self._base_limit
            return self._effective_limit

    def check_and_adapt(self, session_id: str) -> tuple[bool, dict]:
        """Check rate limit and adapt if necessary."""
        now = time.monotonic()

        with self._lock:
            cutoff = now - self._window
            self._call_history = [t for t in self._call_history if t > cutoff]
            current_rate = len(self._call_history)

            # Detect burst
            if current_rate > self._base_limit * self._burst_threshold:
                self._effective_limit = max(1, int(self._base_limit * self._tighten_factor))
                self._last_tighten = now
                _logger.warning(
                    "Adaptive rate limit tightened: %d → %d",
                    self._base_limit,
                    self._effective_limit,
                )

            if current_rate >= self._effective_limit:
                return False, {"rate": current_rate, "limit": self._effective_limit, "adapted": True}

            self._call_history.append(now)
            return True, {"rate": current_rate + 1, "limit": self._effective_limit}
