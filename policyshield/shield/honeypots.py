"""Honeypot tools — decoy tools that signal prompt injection or anomalous behavior.

Honeypots are fake tool names that should never be called in normal operation.
If an LLM agent tries to call a honeypot, it signals prompt injection,
jailbreaking, or abnormal behavior.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any


logger = logging.getLogger("policyshield.honeypot")


@dataclass(frozen=True)
class HoneypotConfig:
    """A configured honeypot tool."""

    name: str
    alert: str = ""
    severity: str = "critical"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HoneypotConfig:
        # Accept both 'tool' and 'name' keys for the honeypot tool name
        tool_name = data.get("name") or data.get("tool")
        if not tool_name:
            raise ValueError("Honeypot config must have 'name' or 'tool' key")
        return cls(
            name=tool_name,
            alert=data.get("alert", f"Honeypot triggered: {tool_name}"),
            severity=data.get("severity", "critical"),
        )


@dataclass(frozen=True)
class HoneypotMatch:
    """Result when a honeypot is triggered."""

    honeypot: HoneypotConfig
    tool_name: str

    @property
    def message(self) -> str:
        return self.honeypot.alert or f"Honeypot triggered: {self.tool_name}"


class HoneypotChecker:
    """Checks tool calls against configured honeypots."""

    def __init__(self, honeypots: list[HoneypotConfig]) -> None:
        self._lookup: dict[str, HoneypotConfig] = {h.name: h for h in honeypots}

    @classmethod
    def from_config(cls, config_list: list[dict[str, Any]]) -> HoneypotChecker:
        """Create from YAML config list."""
        return cls([HoneypotConfig.from_dict(d) for d in config_list])

    def check(self, tool_name: str) -> HoneypotMatch | None:
        """Check if a tool name matches a honeypot.

        Args:
            tool_name: The tool being called.

        Returns:
            HoneypotMatch if triggered, None otherwise.
        """
        if tool_name in self._lookup:
            match = HoneypotMatch(
                honeypot=self._lookup[tool_name],
                tool_name=tool_name,
            )
            logger.critical(
                "🍯 HONEYPOT TRIGGERED: tool=%s alert=%s",
                tool_name,
                match.message,
            )
            return match
        return None

    @property
    def names(self) -> set[str]:
        """Set of configured honeypot tool names."""
        return set(self._lookup.keys())

    def __len__(self) -> int:
        return len(self._lookup)
