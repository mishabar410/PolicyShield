"""LangChain BaseTool adapter for PolicyShield."""

from __future__ import annotations

try:
    from langchain_core.tools import BaseTool, ToolException
except ImportError as e:
    raise ImportError(
        "langchain-core is required for LangChain integration. "
        "Install it with: pip install policyshield[langchain]"
    ) from e

from typing import Any

from pydantic import Field

from policyshield.core.models import Verdict
from policyshield.shield.engine import ShieldEngine


class PolicyShieldTool(BaseTool):
    """Wraps a LangChain tool with PolicyShield enforcement.

    Usage:
        from langchain_community.tools import ShellTool
        from policyshield.integrations.langchain import PolicyShieldTool

        engine = ShieldEngine("policies/rules.yaml")
        shell = ShellTool()
        safe_shell = PolicyShieldTool(wrapped_tool=shell, engine=engine)

        # Now use safe_shell instead of shell — PolicyShield checks every call
        result = safe_shell.invoke({"command": "ls -la"})  # ALLOW → executes
        result = safe_shell.invoke({"command": "rm -rf /"})  # BLOCK → ToolException
    """

    name: str = ""
    description: str = ""
    wrapped_tool: Any = Field(default=None, exclude=True)
    engine: Any = Field(default=None, exclude=True)
    session_id: str = "default"
    block_behavior: str = "raise"  # "raise" | "return_message"

    def __init__(self, wrapped_tool: BaseTool, engine: ShieldEngine, **kwargs: Any) -> None:
        super().__init__(
            name=wrapped_tool.name,
            description=wrapped_tool.description,
            wrapped_tool=wrapped_tool,
            engine=engine,
            **kwargs,
        )

    def _run(self, *args: Any, **kwargs: Any) -> str:
        """Run the tool with PolicyShield check."""
        tool_input = kwargs or (args[0] if args else {})
        if isinstance(tool_input, str):
            tool_input = {"input": tool_input}

        result = self.engine.check(
            tool_name=self.name,
            args=tool_input,
            session_id=self.session_id,
        )

        if result.verdict == Verdict.BLOCK:
            if self.block_behavior == "raise":
                raise ToolException(f"🛡️ PolicyShield BLOCKED: {result.message}")
            return f"🛡️ BLOCKED: {result.message}"

        if result.verdict == Verdict.REDACT:
            tool_input = result.modified_args or tool_input

        if isinstance(tool_input, dict):
            return self.wrapped_tool._run(**tool_input)
        return self.wrapped_tool._run(tool_input)

    async def _arun(self, *args: Any, **kwargs: Any) -> str:
        """Async version — delegates to sync for now."""
        return self._run(*args, **kwargs)


def shield_all_tools(
    tools: list[BaseTool], engine: ShieldEngine, **kwargs: Any
) -> list[PolicyShieldTool]:
    """Wrap all LangChain tools with PolicyShield.

    Usage:
        tools = [ShellTool(), WikipediaTool(), ...]
        safe_tools = shield_all_tools(tools, engine)
    """
    return [PolicyShieldTool(wrapped_tool=t, engine=engine, **kwargs) for t in tools]
