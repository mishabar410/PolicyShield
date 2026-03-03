"""LangChain BaseTool adapter for PolicyShield."""

from __future__ import annotations

try:
    from langchain_core.tools import BaseTool, ToolException
except ImportError as e:
    raise ImportError(
        "langchain-core is required for LangChain integration. Install it with: pip install policyshield[langchain]"
    ) from e

from typing import Any

from pydantic import Field

from policyshield.core.models import Verdict


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
    async_engine: Any = Field(default=None, exclude=True)
    session_id: str = "default"
    block_behavior: str = "raise"  # "raise" | "return_message"

    def __init__(
        self,
        wrapped_tool: BaseTool,
        engine: Any = None,
        async_engine: Any = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            name=wrapped_tool.name,
            description=wrapped_tool.description,
            wrapped_tool=wrapped_tool,
            engine=engine,
            async_engine=async_engine,
            **kwargs,
        )

    def _run(self, *args: Any, **kwargs: Any) -> str:
        """Run the tool with PolicyShield check."""
        tool_input = kwargs or (args[0] if args else {})
        if isinstance(tool_input, str):
            tool_input = {"input": tool_input}

        check_engine = self.engine or self.async_engine
        result = check_engine.check(
            tool_name=self.name,
            args=tool_input,
            session_id=self.session_id,
        )

        if result.verdict == Verdict.BLOCK:
            if self.block_behavior == "raise":
                raise ToolException(f"PolicyShield BLOCKED: {result.message}")
            return f"BLOCKED: {result.message}"

        # Issue #65: Handle APPROVE — don't fall through to execution
        if result.verdict == Verdict.APPROVE:
            approval_id = getattr(result, "approval_id", "") or ""
            if self.block_behavior == "raise":
                raise ToolException(f"PolicyShield requires approval: {result.message} (id={approval_id})")
            return f"APPROVAL REQUIRED: {result.message} (approval_id={approval_id})"

        if result.verdict == Verdict.REDACT:
            tool_input = result.modified_args or tool_input

        if isinstance(tool_input, dict):
            output = self.wrapped_tool._run(**tool_input)
        else:
            output = self.wrapped_tool._run(tool_input)

        # Issue #114: Post-check for output PII scanning (matches CrewAI wrapper)
        if self.engine and hasattr(self.engine, "post_check"):
            try:
                self.engine.post_check(
                    tool_name=self.name,
                    result={"output": output} if isinstance(output, str) else output,
                    session_id=self.session_id,
                )
            except Exception:
                pass  # fail-open on post_check

        return output

    async def _arun(self, *args: Any, **kwargs: Any) -> str:
        """Async version — uses async engine natively if available."""
        import asyncio

        # Issue #19/#46/#82: Native async engine support
        if self.async_engine is not None:
            tool_input = kwargs or (args[0] if args else {})
            if isinstance(tool_input, str):
                tool_input = {"input": tool_input}

            result = await self.async_engine.check(
                tool_name=self.name,
                args=tool_input,
                session_id=self.session_id,
            )

            if result.verdict == Verdict.BLOCK:
                if self.block_behavior == "raise":
                    raise ToolException(f"PolicyShield BLOCKED: {result.message}")
                return f"BLOCKED: {result.message}"

            if result.verdict == Verdict.APPROVE:
                approval_id = getattr(result, "approval_id", "") or ""
                if self.block_behavior == "raise":
                    raise ToolException(f"PolicyShield requires approval: {result.message} (id={approval_id})")
                return f"APPROVAL REQUIRED: {result.message} (approval_id={approval_id})"

            if result.verdict == Verdict.REDACT:
                tool_input = result.modified_args or tool_input

            # Issue #159/#184: Use native _arun() if wrapped tool overrides it
            has_native_arun = type(self.wrapped_tool)._arun is not BaseTool._arun
            if has_native_arun:
                if isinstance(tool_input, dict):
                    output = await self.wrapped_tool._arun(**tool_input)
                else:
                    output = await self.wrapped_tool._arun(tool_input)
            else:
                if isinstance(tool_input, dict):
                    output = await asyncio.to_thread(self.wrapped_tool._run, **tool_input)
                else:
                    output = await asyncio.to_thread(self.wrapped_tool._run, tool_input)

            # Issue #114: Post-check for output PII scanning
            if self.async_engine and hasattr(self.async_engine, "post_check"):
                try:
                    await self.async_engine.post_check(
                        tool_name=self.name,
                        result={"output": output} if isinstance(output, str) else output,
                        session_id=self.session_id,
                    )
                except Exception:
                    pass  # fail-open on post_check

            return output

        # Fallback: sync engine in thread
        return await asyncio.to_thread(self._run, *args, **kwargs)


def shield_all_tools(
    tools: list[BaseTool],
    engine: Any = None,
    async_engine: Any = None,
    **kwargs: Any,
) -> list[PolicyShieldTool]:
    """Wrap all LangChain tools with PolicyShield.

    Usage:
        tools = [ShellTool(), WikipediaTool(), ...]
        safe_tools = shield_all_tools(tools, engine)
    """
    return [PolicyShieldTool(wrapped_tool=t, engine=engine, async_engine=async_engine, **kwargs) for t in tools]
