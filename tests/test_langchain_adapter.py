"""Tests for LangChain adapter."""

from __future__ import annotations

import pytest

langchain_core = pytest.importorskip("langchain_core")

from langchain_core.tools import BaseTool, ToolException  # noqa: E402
from pydantic import Field  # noqa: E402

from policyshield.core.models import RuleConfig, RuleSet, Verdict  # noqa: E402
from policyshield.integrations.langchain import PolicyShieldTool, shield_all_tools  # noqa: E402
from policyshield.shield.engine import ShieldEngine  # noqa: E402


class FakeTool(BaseTool):
    """A fake tool for testing."""

    name: str = "fake_tool"
    description: str = "A fake tool for testing"
    return_value: str = Field(default="executed")

    def _run(self, **kwargs) -> str:
        return self.return_value


class AnotherFakeTool(BaseTool):
    """Another fake tool for testing."""

    name: str = "another_tool"
    description: str = "Another fake tool"

    def _run(self, **kwargs) -> str:
        return "another result"


def _make_engine(rules: list[RuleConfig]) -> ShieldEngine:
    rs = RuleSet(shield_name="test", version=1, rules=rules)
    return ShieldEngine(rs)


class TestPolicyShieldTool:
    def test_wrap_tool_preserves_name(self):
        tool = FakeTool()
        engine = _make_engine([])
        wrapped = PolicyShieldTool(wrapped_tool=tool, engine=engine)
        assert wrapped.name == "fake_tool"

    def test_wrap_tool_preserves_description(self):
        tool = FakeTool()
        engine = _make_engine([])
        wrapped = PolicyShieldTool(wrapped_tool=tool, engine=engine)
        assert wrapped.description == "A fake tool for testing"

    def test_allow_executes_wrapped(self):
        tool = FakeTool(return_value="success")
        engine = _make_engine([])
        wrapped = PolicyShieldTool(wrapped_tool=tool, engine=engine)
        result = wrapped._run(input="test")
        assert result == "success"

    def test_block_raises_exception(self):
        tool = FakeTool()
        engine = _make_engine(
            [
                RuleConfig(
                    id="block-fake",
                    when={"tool": "fake_tool"},
                    then=Verdict.BLOCK,
                    message="Tool blocked",
                )
            ]
        )
        wrapped = PolicyShieldTool(wrapped_tool=tool, engine=engine)
        with pytest.raises(ToolException, match="BLOCKED"):
            wrapped._run(input="test")

    def test_block_return_message(self):
        tool = FakeTool()
        engine = _make_engine(
            [
                RuleConfig(
                    id="block-fake",
                    when={"tool": "fake_tool"},
                    then=Verdict.BLOCK,
                    message="Tool blocked",
                )
            ]
        )
        wrapped = PolicyShieldTool(wrapped_tool=tool, engine=engine, block_behavior="return_message")
        result = wrapped._run(input="test")
        assert "BLOCKED" in result

    def test_redact_passes_modified_args(self):
        tool = FakeTool()
        engine = _make_engine(
            [
                RuleConfig(
                    id="redact-fake",
                    when={"tool": "fake_tool"},
                    then=Verdict.REDACT,
                )
            ]
        )
        wrapped = PolicyShieldTool(wrapped_tool=tool, engine=engine)
        # REDACT will still execute the tool with potentially modified args
        result = wrapped._run(input="test@example.com")
        assert result == "executed"

    def test_string_input_wrapped(self):
        tool = FakeTool(return_value="got it")
        engine = _make_engine([])
        wrapped = PolicyShieldTool(wrapped_tool=tool, engine=engine)
        result = wrapped._run("hello")
        assert result == "got it"

    def test_session_id_passed(self):
        tool = FakeTool()
        engine = _make_engine([])
        wrapped = PolicyShieldTool(wrapped_tool=tool, engine=engine, session_id="custom-session")
        assert wrapped.session_id == "custom-session"


class TestShieldAllTools:
    def test_shield_all_tools_count(self):
        tools = [FakeTool(), AnotherFakeTool(), FakeTool(name="third")]
        engine = _make_engine([])
        wrapped = shield_all_tools(tools, engine)
        assert len(wrapped) == 3
        assert all(isinstance(t, PolicyShieldTool) for t in wrapped)

    def test_shield_all_tools_names(self):
        tools = [FakeTool(), AnotherFakeTool()]
        engine = _make_engine([])
        wrapped = shield_all_tools(tools, engine)
        assert wrapped[0].name == "fake_tool"
        assert wrapped[1].name == "another_tool"
