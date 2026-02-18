"""Budget caps for PolicyShield — cost-based limits per session/hour."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from time import monotonic


@dataclass
class BudgetConfig:
    max_per_session: float = 0  # 0 = disabled
    max_per_hour: float = 0
    currency: str = "USD"


# Default tool cost estimates (override via config)
DEFAULT_TOOL_COSTS: dict[str, float] = {
    "exec": 0.01,
    "write_file": 0.005,
    "read_file": 0.002,
    "search": 0.01,
    "create": 0.01,
}


class BudgetTracker:
    """Tracks cumulative cost per session and globally."""

    def __init__(
        self,
        config: BudgetConfig,
        tool_costs: dict[str, float] | None = None,
    ) -> None:
        self._config = config
        self._tool_costs = {**DEFAULT_TOOL_COSTS, **(tool_costs or {})}
        self._session_spend: dict[str, float] = {}
        self._hourly_entries: list[tuple[float, float]] = []  # (timestamp, cost)
        self._lock = threading.Lock()

    def get_tool_cost(self, tool_name: str) -> float:
        """Estimate cost for a tool call."""
        return self._tool_costs.get(tool_name, 0.001)  # Default 0.1 cent

    def check_budget(self, session_id: str, tool_name: str) -> tuple[bool, str]:
        """Check if budget allows this tool call.

        Returns:
            (allowed, reason)
        """
        cost = self.get_tool_cost(tool_name)

        with self._lock:
            # Per-session check
            if self._config.max_per_session > 0:
                current_session = self._session_spend.get(session_id, 0)
                if current_session + cost > self._config.max_per_session:
                    return False, (
                        f"Session budget exceeded: "
                        f"${current_session:.2f} + ${cost:.3f} > "
                        f"${self._config.max_per_session:.2f}"
                    )

            # Per-hour check
            if self._config.max_per_hour > 0:
                now = monotonic()
                cutoff = now - 3600
                self._hourly_entries = [(ts, c) for ts, c in self._hourly_entries if ts > cutoff]
                hourly_total = sum(c for _, c in self._hourly_entries)
                if hourly_total + cost > self._config.max_per_hour:
                    return False, (
                        f"Hourly budget exceeded: ${hourly_total:.2f} + ${cost:.3f} > ${self._config.max_per_hour:.2f}"
                    )

        return True, ""

    def record_spend(self, session_id: str, tool_name: str) -> float:
        """Record a tool call spend. Returns the cost."""
        cost = self.get_tool_cost(tool_name)
        with self._lock:
            self._session_spend[session_id] = self._session_spend.get(session_id, 0) + cost
            self._hourly_entries.append((monotonic(), cost))
        return cost

    def session_balance(self, session_id: str) -> dict:
        """Get remaining budget for a session."""
        with self._lock:
            spent = self._session_spend.get(session_id, 0)
        return {
            "spent": round(spent, 4),
            "limit": self._config.max_per_session,
            "remaining": round(max(0, self._config.max_per_session - spent), 4),
            "currency": self._config.currency,
        }
