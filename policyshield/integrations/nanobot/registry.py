"""Shielded tool registry for nanobot integration."""

from __future__ import annotations

import logging
from typing import Any

from policyshield.core.models import ShieldResult, Verdict
from policyshield.integrations.nanobot.context import session_id_var
from policyshield.shield.engine import ShieldEngine

logger = logging.getLogger("policyshield.nanobot")


class PolicyViolation(Exception):
    """Raised when a tool call is blocked by a policy."""

    def __init__(self, result: ShieldResult):
        self.result = result
        super().__init__(result.message)


class ShieldedToolRegistry:
    """A tool registry wrapper that enforces PolicyShield rules.

    Works with or without nanobot. When nanobot is not available,
    provides standalone tool registration and execution.
    """

    def __init__(
        self,
        engine: ShieldEngine,
        fail_open: bool = True,
    ):
        self._engine = engine
        self._fail_open = fail_open
        self._tools: dict[str, Any] = {}

    def register(self, name: str, func: Any) -> None:
        """Register a tool function.

        Args:
            name: Tool name.
            func: Tool callable.
        """
        self._tools[name] = func

    def execute(self, tool_name: str, args: dict | None = None) -> Any:
        """Execute a tool after policy check.

        Args:
            tool_name: Name of the tool to execute.
            args: Arguments for the tool.

        Returns:
            Tool result (modified args used if REDACT).

        Raises:
            PolicyViolation: If tool call is blocked.
            KeyError: If tool is not registered.
        """
        args = args or {}
        session_id = session_id_var.get()

        # Pre-check
        try:
            result = self._engine.check(
                tool_name=tool_name,
                args=args,
                session_id=session_id,
            )
        except Exception as e:
            if self._fail_open:
                logger.warning("Shield check error (fail-open): %s", e)
                result = ShieldResult(verdict=Verdict.ALLOW)
            else:
                raise

        # Handle verdict
        if result.verdict == Verdict.BLOCK:
            raise PolicyViolation(result)
        elif result.verdict == Verdict.APPROVE:
            raise PolicyViolation(result)
        elif result.verdict == Verdict.REDACT:
            # Use modified (redacted) args
            args = result.modified_args or args

        # Execute tool
        if tool_name not in self._tools:
            raise KeyError(f"Tool not registered: {tool_name}")

        tool_result = self._tools[tool_name](**args)

        # Post-check
        try:
            self._engine.post_check(tool_name, tool_result, session_id)
        except Exception as e:
            if self._fail_open:
                logger.warning("Post-check error (fail-open): %s", e)
            else:
                raise

        return tool_result

    @property
    def tool_names(self) -> list[str]:
        """Return list of registered tool names."""
        return list(self._tools.keys())
