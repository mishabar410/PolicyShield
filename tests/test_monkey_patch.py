"""Tests for the monkey-patch integration with vanilla nanobot."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from policyshield.integrations.nanobot.monkey_patch import shield_agent_loop


# ── Fake nanobot objects ──────────────────────────────────────────────


class FakeToolRegistry:
    """Mimics nanobot's ToolRegistry just enough for testing."""

    def __init__(self):
        self._tools: dict = {}

    @property
    def tool_names(self) -> list[str]:
        return list(self._tools.keys())

    def get(self, name: str):
        return self._tools.get(name)

    def register(self, tool):
        self._tools[tool.name] = tool

    async def execute(self, name: str, args: dict) -> str:
        fn = self._tools[name]
        return fn.func(**args)


class FakeContextBuilder:
    """Mimics nanobot's ContextBuilder."""

    def __init__(self):
        pass

    def build_messages(self, **kwargs) -> list[dict]:
        return [
            {"role": "system", "content": "You are a helpful agent."},
            {"role": "user", "content": kwargs.get("current_message", "")},
        ]


class FakeAgentLoop:
    """Mimics a vanilla nanobot AgentLoop — no shield_config parameter."""

    def __init__(self):
        self.tools = FakeToolRegistry()
        self.context = FakeContextBuilder()
        self.subagents = SimpleNamespace()

    async def _process_message(self, msg):
        return await self._process_message_inner(msg)

    async def _process_message_inner(self, msg):
        messages = self.context.build_messages(current_message=msg.content)
        return SimpleNamespace(messages=messages, content="OK")


RULES = Path(__file__).resolve().parent.parent / "examples" / "nanobot_rules.yaml"


# ── Tests ─────────────────────────────────────────────────────────────


class TestShieldAgentLoop:
    """Tests for shield_agent_loop() monkey-patch."""

    def test_wraps_tool_registry(self):
        """After patching, loop.tools is a ShieldedToolRegistry."""
        from policyshield.integrations.nanobot.registry import ShieldedToolRegistry

        loop = FakeAgentLoop()
        assert not isinstance(loop.tools, ShieldedToolRegistry)

        shield_agent_loop(loop, rules_path=RULES)
        assert isinstance(loop.tools, ShieldedToolRegistry)

    def test_blocks_forbidden_tool(self):
        """A tool blocked by rules returns a BLOCKED message."""
        loop = FakeAgentLoop()
        shield_agent_loop(loop, rules_path=RULES)
        loop.tools.register_func("exec", lambda command="": f"Ran: {command}")

        result = asyncio.run(loop.tools.execute("exec", {"command": "rm -rf /"}))
        assert "BLOCKED" in result.upper() or "🛡️" in result

    def test_allows_safe_tool(self):
        """An allowed tool executes normally."""
        loop = FakeAgentLoop()
        shield_agent_loop(loop, rules_path=RULES)
        loop.tools.register_func("echo", lambda message="": f"Echo: {message}")

        result = asyncio.run(loop.tools.execute("echo", {"message": "hello"}))
        assert "Echo: hello" in result

    def test_double_install_raises(self):
        """Installing shield twice on the same loop raises RuntimeError."""
        loop = FakeAgentLoop()
        shield_agent_loop(loop, rules_path=RULES)

        with pytest.raises(RuntimeError, match="already installed"):
            shield_agent_loop(loop, rules_path=RULES)

    def test_rejects_non_agent_loop(self):
        """Passing a random object raises TypeError."""
        with pytest.raises(TypeError, match="Expected a nanobot AgentLoop"):
            shield_agent_loop("not-a-loop", rules_path=RULES)

    def test_session_propagation(self):
        """_process_message sets session_id_var for the duration of the call."""
        from policyshield.integrations.nanobot.registry import session_id_var

        captured_sessions = []

        loop = FakeAgentLoop()

        # Patch _process_message_inner to capture session
        original_inner = loop._process_message_inner

        async def capturing_inner(msg):
            captured_sessions.append(session_id_var.get(None))
            return await original_inner(msg)

        loop._process_message_inner = capturing_inner

        shield_agent_loop(loop, rules_path=RULES)

        msg = SimpleNamespace(
            content="hello",
            session_key="user:42",
            channel="telegram",
            chat_id="123",
            sender_id="alice",
            media=None,
        )
        asyncio.run(loop._process_message(msg))
        assert captured_sessions == ["user:42"]

    def test_context_enrichment(self):
        """After patching, build_messages injects constraint summary."""
        loop = FakeAgentLoop()
        shield_agent_loop(loop, rules_path=RULES)

        messages = loop.context.build_messages(current_message="test")
        system_msg = messages[0]["content"]
        # Should contain something about constraints from the rules
        assert "system" == messages[0]["role"]
        # The constraints summary should be appended
        assert len(system_msg) > len("You are a helpful agent.")

    def test_modes(self):
        """Accepts AUDIT and DISABLED modes."""
        for mode_str in ("AUDIT", "DISABLED"):
            loop = FakeAgentLoop()
            shield_agent_loop(loop, rules_path=RULES, mode=mode_str)
            assert getattr(loop, "_policyshield_installed", False)

    def test_fail_open_default(self):
        """Default fail_open is True."""
        loop = FakeAgentLoop()
        shield_agent_loop(loop, rules_path=RULES)
        assert loop.tools._fail_open is True

    def test_fail_open_false(self):
        """fail_open=False is respected."""
        loop = FakeAgentLoop()
        shield_agent_loop(loop, rules_path=RULES, fail_open=False)
        assert loop.tools._fail_open is False
