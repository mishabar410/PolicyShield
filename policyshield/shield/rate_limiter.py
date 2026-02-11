"""Rate limiter engine for PolicyShield — sliding window per-tool/per-session limits."""

from __future__ import annotations

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
