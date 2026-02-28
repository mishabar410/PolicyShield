"""Approval cache for batch approve strategies."""

from __future__ import annotations

import threading
from enum import Enum

from policyshield.approval.base import ApprovalResponse


class ApprovalStrategy(str, Enum):
    """How to cache approval decisions."""

    ONCE = "once"  # approve only this exact call
    PER_SESSION = "per_session"  # approve all such calls in this session
    PER_RULE = "per_rule"  # approve all calls of this rule globally
    PER_TOOL = "per_tool"  # approve all calls of this tool in session


class ApprovalCache:
    """Cache for approval decisions to avoid repeated prompts."""

    def __init__(self, strategy: ApprovalStrategy = ApprovalStrategy.PER_RULE):
        self._strategy = strategy
        self._cache: dict[str, ApprovalResponse] = {}
        self._lock = threading.Lock()

    @property
    def strategy(self) -> ApprovalStrategy:
        return self._strategy

    def get(
        self,
        tool_name: str,
        rule_id: str,
        session_id: str,
        strategy: ApprovalStrategy | None = None,
    ) -> ApprovalResponse | None:
        """Check if there's a cached approval for this combination."""
        s = strategy or self._strategy
        if s == ApprovalStrategy.ONCE:
            return None  # never cache for ONCE
        key = self._make_key(tool_name, rule_id, session_id, s)
        with self._lock:
            return self._cache.get(key)

    def put(
        self,
        tool_name: str,
        rule_id: str,
        session_id: str,
        response: ApprovalResponse,
        strategy: ApprovalStrategy | None = None,
    ) -> None:
        """Cache an approval response."""
        s = strategy or self._strategy
        if s == ApprovalStrategy.ONCE:
            return  # don't cache for ONCE
        key = self._make_key(tool_name, rule_id, session_id, s)
        with self._lock:
            self._cache[key] = response

    def clear(self, session_id: str | None = None) -> None:
        """Clear cache, optionally for a specific session only.

        Note: PER_RULE approvals (global) are NOT cleared when clearing
        a specific session. Use :meth:`clear_global` for that.
        """
        with self._lock:
            if session_id is None:
                self._cache.clear()
                return

            keys_to_remove = []
            for key in self._cache:
                # PER_RULE keys are global ("__global__:rule_id") —
                # skip when clearing a specific session
                if key.startswith("__global__:"):
                    continue
                # PER_SESSION: "{session_id}:{rule_id}"
                # PER_TOOL: "{session_id}:{tool_name}"
                # ONCE fallback: "{session_id}:{rule_id}:{tool_name}"
                if key.startswith(f"{session_id}:"):
                    keys_to_remove.append(key)

            for k in keys_to_remove:
                del self._cache[k]

    def clear_global(self) -> None:
        """Clear all global (PER_RULE) cached approvals."""
        with self._lock:
            keys_to_remove = [k for k in self._cache if k.startswith("__global__:")]
            for k in keys_to_remove:
                del self._cache[k]

    def _make_key(
        self,
        tool_name: str,
        rule_id: str,
        session_id: str,
        strategy: ApprovalStrategy,
    ) -> str:
        """Generate cache key based on strategy."""
        if strategy == ApprovalStrategy.PER_SESSION:
            return f"{session_id}:{rule_id}"
        elif strategy == ApprovalStrategy.PER_RULE:
            return f"__global__:{rule_id}"
        elif strategy == ApprovalStrategy.PER_TOOL:
            return f"{session_id}:{tool_name}"
        else:
            return f"{session_id}:{rule_id}:{tool_name}"
