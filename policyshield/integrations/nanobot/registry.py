"""Shielded tool registry for nanobot integration.

Extends nanobot's ToolRegistry with PolicyShield enforcement.
On BLOCK/APPROVE, returns a shield message string instead of executing the tool.
On REDACT, modifies params before delegation.
On ALLOW, passes through unchanged.
"""

from __future__ import annotations

import logging
from typing import Any

from policyshield.core.models import ShieldResult, Verdict
from policyshield.integrations.nanobot.context import session_id_var
from policyshield.shield.engine import ShieldEngine

try:
    from nanobot.agent.tools.registry import ToolRegistry as _NanobotToolRegistry

    _HAS_NANOBOT = True
except ImportError:
    _HAS_NANOBOT = False
    _NanobotToolRegistry = object  # type: ignore[assignment,misc]

logger = logging.getLogger("policyshield.nanobot")


class PolicyViolation(Exception):
    """Raised when a tool call is blocked by a policy."""

    def __init__(self, result: ShieldResult):
        self.result = result
        super().__init__(result.message)


class ShieldedToolRegistry(_NanobotToolRegistry):  # type: ignore[misc]
    """Tool registry with PolicyShield enforcement.

    Extends nanobot's ``ToolRegistry``.  Every ``execute()`` call runs
    a PolicyShield pre-check.  If the verdict is ``BLOCK`` or ``APPROVE``
    a shield message is returned *instead* of running the tool.

    When nanobot is not installed the class still imports (inherits from
    ``object``), but ``execute`` falls back to a simple sync path for
    standalone / testing use.
    """

    def __init__(
        self,
        engine: ShieldEngine,
        *,
        fail_open: bool = True,
    ) -> None:
        if _HAS_NANOBOT:
            super().__init__()
        self._engine = engine
        self._fail_open = fail_open
        # Standalone fallback (no nanobot)
        if not _HAS_NANOBOT:
            self._tools: dict[str, Any] = {}

    # ── nanobot-compatible async execute ─────────────────────────────

    async def execute(self, name: str, params: dict[str, Any]) -> str:  # type: ignore[override]
        """Execute a tool after PolicyShield pre-check.

        Returns a shield message string on BLOCK / APPROVE instead of
        executing the tool.
        """
        params = params or {}
        session_id = session_id_var.get()

        # Pre-check
        try:
            result = self._engine.check(
                tool_name=name,
                args=params,
                session_id=session_id,
            )
        except Exception as exc:
            if self._fail_open:
                logger.warning("Shield check error (fail-open): %s", exc)
                result = ShieldResult(verdict=Verdict.ALLOW)
            else:
                return f"🛡️ SHIELD ERROR: {exc}"

        # Handle verdict
        if result.verdict == Verdict.BLOCK:
            logger.info("BLOCKED %s: %s", name, result.message)
            return f"🛡️ BLOCKED: {result.message}"

        if result.verdict == Verdict.APPROVE:
            logger.info("APPROVAL REQUIRED %s: %s", name, result.message)
            return f"⏳ APPROVAL REQUIRED: {result.message}"

        if result.verdict == Verdict.REDACT:
            params = result.modified_args or params

        # Delegate to parent's execute (nanobot) or standalone fallback
        if _HAS_NANOBOT:
            return await super().execute(name, params)

        # Standalone fallback
        func = self._tools.get(name)
        if not func:
            return f"Error: Tool '{name}' not found"
        try:
            return str(func(**params))
        except Exception as exc:
            return f"Error executing {name}: {exc}"

    # ── standalone helpers (when nanobot not installed) ───────────────

    def register_func(self, name: str, func: Any) -> None:
        """Register a plain callable (standalone mode, no nanobot)."""
        if _HAS_NANOBOT:
            raise RuntimeError(
                "Use register(tool) with a nanobot Tool object, "
                "not register_func()."
            )
        self._tools[name] = func

    @property
    def tool_names(self) -> list[str]:
        """Return registered tool names."""
        if _HAS_NANOBOT:
            return super().tool_names  # type: ignore[return-value]
        return list(self._tools.keys())
