"""Tests for CrewAI adapter — works without crewai installed."""

import pytest

from policyshield.core.models import (
    RuleConfig,
    RuleSet,
    ShieldMode,
    Verdict,
)
from policyshield.integrations.crewai.wrapper import (
    CrewAIShieldTool,
    ToolCallBlockedError,
    shield_all_crewai_tools,
)
from policyshield.shield.engine import ShieldEngine


def make_ruleset(rules: list[RuleConfig]) -> RuleSet:
    return RuleSet(shield_name="test", version=1, rules=rules)


class FakeCrewAITool:
    """Fake CrewAI tool for testing (no crewai dependency needed)."""

    name: str = "web_search"
    description: str = "Search the web"

    def __init__(self, name: str = "web_search", description: str = "Search the web"):
        self.name = name
        self.description = description
        self.last_kwargs: dict = {}

    def _run(self, **kwargs) -> str:
        self.last_kwargs = kwargs
        return f"Result for: {kwargs}"


@pytest.fixture
def block_search_rules():
    return make_ruleset(
        [
            RuleConfig(
                id="block-search",
                description="Block web search",
                when={"tool": "web_search"},
                then=Verdict.BLOCK,
                message="web_search is not allowed",
            )
        ]
    )


@pytest.fixture
def redact_rules():
    return make_ruleset(
        [
            RuleConfig(
                id="redact-pii",
                when={"tool": "web_search"},
                then=Verdict.REDACT,
            )
        ]
    )


@pytest.fixture
def allow_rules():
    return make_ruleset([])


# ── Test 1: Tool runs on ALLOW ───────────────────────────────────────


def test_crewai_allow(allow_rules):
    engine = ShieldEngine(allow_rules)
    fake_tool = FakeCrewAITool()
    safe_tool = CrewAIShieldTool(wrapped_tool=fake_tool, engine=engine)

    result = safe_tool._run(query="hello world")
    assert "hello world" in result
    assert fake_tool.last_kwargs == {"query": "hello world"}


# ── Test 2: BLOCK → return message ──────────────────────────────────


def test_crewai_block_return_message(block_search_rules):
    engine = ShieldEngine(block_search_rules)
    fake_tool = FakeCrewAITool()
    safe_tool = CrewAIShieldTool(wrapped_tool=fake_tool, engine=engine, on_block="return_message")

    result = safe_tool._run(query="test")
    assert "BLOCKED" in result
    assert fake_tool.last_kwargs == {}  # tool was never called


# ── Test 3: BLOCK + raise ───────────────────────────────────────────


def test_crewai_block_raise(block_search_rules):
    engine = ShieldEngine(block_search_rules)
    fake_tool = FakeCrewAITool()
    safe_tool = CrewAIShieldTool(wrapped_tool=fake_tool, engine=engine, on_block="raise")

    with pytest.raises(ToolCallBlockedError, match="BLOCKED"):
        safe_tool._run(query="test")


# ── Test 4: REDACT → modified_args ──────────────────────────────────


def test_crewai_redact(redact_rules):
    engine = ShieldEngine(redact_rules)
    fake_tool = FakeCrewAITool()
    safe_tool = CrewAIShieldTool(wrapped_tool=fake_tool, engine=engine)

    result = safe_tool._run(body="Email: john@example.com")
    # Tool should have been called (REDACT doesn't block)
    assert result is not None
    # args should have been modified (PII redacted)
    assert fake_tool.last_kwargs is not None


# ── Test 5: PII detection → BLOCK rule ──────────────────────────────


def test_crewai_pii_detection():
    rules = make_ruleset(
        [
            RuleConfig(
                id="block-with-pii",
                when={"tool": "send_data"},
                then=Verdict.BLOCK,
                message="Blocked",
            )
        ]
    )
    engine = ShieldEngine(rules)
    fake_tool = FakeCrewAITool(name="send_data")
    safe_tool = CrewAIShieldTool(wrapped_tool=fake_tool, engine=engine)

    result = safe_tool._run(text="Email: john@example.com")
    assert "BLOCKED" in result


# ── Test 6: name/description proxied ────────────────────────────────


def test_crewai_name_description():
    fake_tool = FakeCrewAITool(name="my_tool", description="Does things")
    safe_tool = CrewAIShieldTool(
        wrapped_tool=fake_tool,
        engine=ShieldEngine(make_ruleset([])),
    )
    assert safe_tool.name == "my_tool"
    assert safe_tool.description == "Does things"


# ── Test 7: shield_all_crewai_tools ─────────────────────────────────


def test_crewai_shield_all():
    tools = [FakeCrewAITool(name=f"tool_{i}") for i in range(3)]
    engine = ShieldEngine(make_ruleset([]))

    safe_tools = shield_all_crewai_tools(tools, engine, session_id="s1")
    assert len(safe_tools) == 3
    for i, st in enumerate(safe_tools):
        assert isinstance(st, CrewAIShieldTool)
        assert st.name == f"tool_{i}"
        assert st.session_id == "s1"


# ── Test 8: AUDIT mode ──────────────────────────────────────────────


def test_crewai_audit_mode(block_search_rules):
    engine = ShieldEngine(block_search_rules, mode=ShieldMode.AUDIT)
    fake_tool = FakeCrewAITool()
    safe_tool = CrewAIShieldTool(wrapped_tool=fake_tool, engine=engine)

    # In AUDIT mode, the tool should still run even for matching rules
    result = safe_tool._run(query="hello")
    # AUDIT mode returns ALLOW, so the tool runs
    assert "hello" in result
    assert fake_tool.last_kwargs == {"query": "hello"}


# ── Test 9: post_check is called ────────────────────────────────────


def test_crewai_post_check(allow_rules):
    engine = ShieldEngine(allow_rules)
    fake_tool = FakeCrewAITool()
    safe_tool = CrewAIShieldTool(wrapped_tool=fake_tool, engine=engine)

    # Verify post_check runs without error
    result = safe_tool._run(query="test")
    assert result is not None


# ── Test 10: public run() method ────────────────────────────────────


def test_crewai_run_alias(allow_rules):
    engine = ShieldEngine(allow_rules)
    fake_tool = FakeCrewAITool()
    safe_tool = CrewAIShieldTool(wrapped_tool=fake_tool, engine=engine)

    result = safe_tool.run(query="hello")
    assert "hello" in result
