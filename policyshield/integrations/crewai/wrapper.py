"""CrewAI BaseTool adapter for PolicyShield.

Wraps CrewAI tools with shield enforcement (pre-check, post-check).
Works with both ShieldEngine (sync) and AsyncShieldEngine.
"""

from __future__ import annotations

from typing import Any, Literal

from policyshield.core.exceptions import PolicyShieldError
from policyshield.core.models import Verdict


class ToolCallBlockedError(PolicyShieldError):
    """Raised when a tool call is blocked by PolicyShield."""


class CrewAIShieldTool:
    """Wraps a CrewAI BaseTool with PolicyShield enforcement.

    Does **not** inherit from ``crewai.tools.BaseTool`` so that crewai
    is truly optional.  Instead it duck-types the interface that CrewAI
    agents expect (``name``, ``description``, ``_run``).

    Usage::

        from policyshield.integrations.crewai import CrewAIShieldTool

        safe_tool = CrewAIShieldTool(
            wrapped_tool=my_crewai_tool,
            engine=engine,
            session_id="sess-1",
        )
        result = safe_tool._run(query="SELECT * FROM users")
    """

    def __init__(
        self,
        wrapped_tool: Any,
        engine: Any,
        session_id: str = "default",
        on_block: Literal["raise", "return_message"] = "return_message",
    ) -> None:
        """Initialize CrewAIShieldTool.

        Args:
            wrapped_tool: Original CrewAI tool to wrap.
            engine: ShieldEngine or AsyncShieldEngine instance.
            session_id: Session identifier for PolicyShield.
            on_block: Behavior on BLOCK verdict – raise or return message.
        """
        self.wrapped_tool = wrapped_tool
        self.engine = engine
        self.session_id = session_id
        self.on_block = on_block

    @property
    def name(self) -> str:
        """Proxy tool name from wrapped tool."""
        return getattr(self.wrapped_tool, "name", type(self.wrapped_tool).__name__)

    @property
    def description(self) -> str:
        """Proxy description from wrapped tool."""
        return getattr(self.wrapped_tool, "description", "")

    def _run(self, *args: Any, **kwargs: Any) -> str:
        """Run the tool with PolicyShield check.

        Args:
            *args: Positional arguments (converted to kwargs dict).
            **kwargs: Arguments forwarded to the wrapped tool.

        Returns:
            Tool output string, or block message.

        Raises:
            ToolCallBlockedError: When on_block='raise' and verdict is BLOCK/APPROVE.
        """
        # Issue #81: Merge positional args into kwargs
        if args:
            if len(args) == 1 and isinstance(args[0], str):
                kwargs.setdefault("input", args[0])
            elif len(args) == 1 and isinstance(args[0], dict):
                kwargs.update(args[0])

        result = self.engine.check(
            tool_name=self.name,
            args=kwargs,
            session_id=self.session_id,
        )

        if result.verdict == Verdict.BLOCK:
            if self.on_block == "raise":
                raise ToolCallBlockedError(f"PolicyShield BLOCKED: {result.message}")
            return f"BLOCKED: {result.message}"

        # Issue #47/#64: Handle APPROVE — don't fall through to execution
        if result.verdict == Verdict.APPROVE:
            approval_id = getattr(result, "approval_id", "") or ""
            if self.on_block == "raise":
                raise ToolCallBlockedError(f"PolicyShield requires approval: {result.message} (id={approval_id})")
            return f"APPROVAL REQUIRED: {result.message} (approval_id={approval_id})"

        if result.verdict == Verdict.REDACT:
            kwargs = result.modified_args or kwargs

        output = self.wrapped_tool._run(**kwargs)

        # Post-check on output
        # Issue #176: Handle async engine post_check coroutine
        import inspect

        post_result = {"output": output} if isinstance(output, str) else output
        if hasattr(self.engine, "post_check"):
            if inspect.iscoroutinefunction(self.engine.post_check):
                import asyncio

                try:
                    asyncio.get_running_loop()
                    # Already in async context — can't do asyncio.run(), skip
                except RuntimeError:
                    asyncio.run(
                        self.engine.post_check(
                            tool_name=self.name,
                            result=post_result,
                            session_id=self.session_id,
                        )
                    )
            else:
                self.engine.post_check(
                    tool_name=self.name,
                    result=post_result,
                    session_id=self.session_id,
                )

        return output

    def run(self, *args: Any, **kwargs: Any) -> str:
        """Public run method (alias for ``_run``)."""
        return self._run(*args, **kwargs)


def shield_all_crewai_tools(
    tools: list[Any],
    engine: Any,
    session_id: str = "default",
    on_block: Literal["raise", "return_message"] = "return_message",
) -> list[CrewAIShieldTool]:
    """Wrap all CrewAI tools with PolicyShield enforcement.

    Args:
        tools: List of CrewAI BaseTool instances.
        engine: ShieldEngine or AsyncShieldEngine.
        session_id: Session identifier.
        on_block: Behavior on BLOCK verdict.

    Returns:
        List of wrapped CrewAIShieldTool instances.
    """
    return [
        CrewAIShieldTool(
            wrapped_tool=t,
            engine=engine,
            session_id=session_id,
            on_block=on_block,
        )
        for t in tools
    ]
