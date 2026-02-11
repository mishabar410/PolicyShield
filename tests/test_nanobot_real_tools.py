"""Integration tests with nanobot-like Tool objects.

Tests the ShieldedToolRegistry with Tool objects that match nanobot's
Tool ABC interface. This validates compatibility without requiring
the full nanobot dependency tree (loguru, etc.).
"""

from __future__ import annotations

import asyncio
import sys
import types
from typing import Any


import pytest

from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.integrations.nanobot.registry import ShieldedToolRegistry
from policyshield.shield.engine import ShieldEngine


# ── Lightweight Tool ABC mirroring nanobot ───────────────────────────

class ToolBase:
    """Minimal nanobot-compatible Tool ABC (no external deps)."""

    @property
    def name(self) -> str:
        raise NotImplementedError

    @property
    def description(self) -> str:
        raise NotImplementedError

    @property
    def parameters(self) -> dict[str, Any]:
        raise NotImplementedError

    def to_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def validate_params(self, params: dict[str, Any]) -> list[str]:
        required = self.parameters.get("required", [])
        errors = []
        for r in required:
            if r not in params:
                errors.append(f"missing required parameter '{r}'")
        return errors

    async def execute(self, **kwargs: Any) -> str:
        raise NotImplementedError


# ── Concrete test tools ──────────────────────────────────────────────

class EchoTool(ToolBase):
    @property
    def name(self) -> str:
        return "echo"

    @property
    def description(self) -> str:
        return "Echo back the message"

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        }

    async def execute(self, message: str = "", **kwargs: Any) -> str:
        return f"Echo: {message}"


class ExecTool(ToolBase):
    @property
    def name(self) -> str:
        return "exec"

    @property
    def description(self) -> str:
        return "Execute a command"

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        }

    async def execute(self, command: str = "", **kwargs: Any) -> str:
        return f"Executed: {command}"


class LeakyTool(ToolBase):
    @property
    def name(self) -> str:
        return "read_data"

    @property
    def description(self) -> str:
        return "Read sensitive data"

    @property
    def parameters(self) -> dict[str, Any]:
        return {"type": "object", "properties": {}}

    async def execute(self, **kwargs: Any) -> str:
        return "Contact: user@example.com, Phone: +7-900-123-45-67"


# ── Helpers ───────────────────────────────────────────────────────────

def _make_ruleset(rules: list[RuleConfig]) -> RuleSet:
    return RuleSet(shield_name="test", version=1, rules=rules)


def _make_shielded(rules: list[RuleConfig]) -> ShieldedToolRegistry:
    engine = ShieldEngine(_make_ruleset(rules))
    return ShieldedToolRegistry(engine=engine, fail_open=True)


def _patch_nanobot():
    """Create a minimal mock nanobot.agent.tools module tree."""
    base_mod = types.ModuleType("nanobot.agent.tools.base")
    base_mod.Tool = ToolBase  # type: ignore[attr-defined]

    registry_mod = types.ModuleType("nanobot.agent.tools.registry")

    class FakeToolRegistry:
        def __init__(self) -> None:
            self._tools: dict[str, ToolBase] = {}

        def register(self, tool: ToolBase) -> None:
            self._tools[tool.name] = tool

        def get(self, name: str) -> ToolBase | None:
            return self._tools.get(name)

        def get_definitions(self) -> list[dict[str, Any]]:
            return [t.to_schema() for t in self._tools.values()]

        @property
        def tool_names(self) -> list[str]:
            return list(self._tools.keys())

        async def execute(self, name: str, params: dict[str, Any]) -> str:
            tool = self._tools.get(name)
            if not tool:
                return f"Error: Tool '{name}' not found"
            errors = tool.validate_params(params)
            if errors:
                return f"Error: Invalid parameters for tool '{name}': " + "; ".join(errors)
            try:
                return await tool.execute(**params)
            except Exception as e:
                return f"Error executing {name}: {e}"

    registry_mod.ToolRegistry = FakeToolRegistry  # type: ignore[attr-defined]

    return {
        "nanobot": types.ModuleType("nanobot"),
        "nanobot.agent": types.ModuleType("nanobot.agent"),
        "nanobot.agent.tools": types.ModuleType("nanobot.agent.tools"),
        "nanobot.agent.tools.base": base_mod,
        "nanobot.agent.tools.registry": registry_mod,
    }


@pytest.fixture(autouse=True)
def _mock_nanobot_import(monkeypatch):
    """Inject fake nanobot modules so ShieldedToolRegistry._HAS_NANOBOT=True."""
    mods = _patch_nanobot()
    for name, mod in mods.items():
        monkeypatch.setitem(sys.modules, name, mod)

    # Reload registry module so _HAS_NANOBOT picks up the mock
    import importlib
    import policyshield.integrations.nanobot.registry as reg_mod
    importlib.reload(reg_mod)

    yield

    # Reload again to restore original state
    importlib.reload(reg_mod)


# ── Tests ─────────────────────────────────────────────────────────────

class TestRealToolAllow:
    def test_real_tool_allow(self):
        """EchoTool → no matching rule → ALLOW → tool executes."""
        from policyshield.integrations.nanobot.registry import ShieldedToolRegistry as SR
        registry = SR(ShieldEngine(_make_ruleset([])), fail_open=True)
        registry.register(EchoTool())
        result = asyncio.run(registry.execute("echo", {"message": "hello"}))
        assert result == "Echo: hello"


class TestRealToolBlock:
    def test_real_tool_block(self):
        """ExecTool → BLOCK rule → shield message returned."""
        from policyshield.integrations.nanobot.registry import ShieldedToolRegistry as SR
        registry = SR(
            ShieldEngine(
                _make_ruleset([
                    RuleConfig(
                        id="block-exec",
                        when={"tool": "exec"},
                        then=Verdict.BLOCK,
                        message="exec is blocked",
                    ),
                ])
            ),
            fail_open=True,
        )
        registry.register(ExecTool())
        result = asyncio.run(registry.execute("exec", {"command": "rm -rf /"}))
        assert "BLOCKED" in result
        assert "exec is blocked" in result


class TestRealToolRedact:
    def test_real_tool_redact(self):
        """Redact rule → modified args → tool still executes."""
        from policyshield.integrations.nanobot.registry import ShieldedToolRegistry as SR
        registry = SR(
            ShieldEngine(
                _make_ruleset([
                    RuleConfig(
                        id="redact-echo",
                        when={"tool": "echo"},
                        then=Verdict.REDACT,
                    ),
                ])
            ),
            fail_open=True,
        )
        registry.register(EchoTool())
        result = asyncio.run(
            registry.execute("echo", {"message": "email: user@company.com"})
        )
        # Tool ran, so result starts with "Echo:"
        assert "Echo:" in result


class TestRealToolNotFound:
    def test_real_tool_not_found(self):
        """Unregistered tool → 'not found' error."""
        from policyshield.integrations.nanobot.registry import ShieldedToolRegistry as SR
        registry = SR(ShieldEngine(_make_ruleset([])), fail_open=True)
        result = asyncio.run(registry.execute("nonexistent", {}))
        assert "not found" in result.lower()


class TestRealToolPostCallPII:
    def test_real_tool_postcall_pii(self):
        """LeakyTool returns email → post-check detects PII, session tainted."""
        from policyshield.integrations.nanobot.registry import ShieldedToolRegistry as SR
        engine = ShieldEngine(_make_ruleset([]))
        registry = SR(engine=engine, fail_open=True)
        registry.register(LeakyTool())
        result = asyncio.run(registry.execute("read_data", {}))
        assert "user@example.com" in result
        from policyshield.core.models import PIIType
        session = engine._session_mgr.get_or_create("default")
        assert PIIType.EMAIL in session.taints


class TestRealToolSchema:
    def test_real_tool_schema(self):
        """get_definitions() contains real tool schemas."""
        from policyshield.integrations.nanobot.registry import ShieldedToolRegistry as SR
        registry = SR(ShieldEngine(_make_ruleset([])), fail_open=True)
        registry.register(EchoTool())
        registry.register(ExecTool())
        defs = registry.get_definitions()
        names = [d["function"]["name"] for d in defs]
        assert "echo" in names
        assert "exec" in names
        echo_def = next(d for d in defs if d["function"]["name"] == "echo")
        assert echo_def["type"] == "function"
        assert "message" in echo_def["function"]["parameters"]["properties"]


class TestRealToolValidation:
    def test_missing_required_param(self):
        """Missing required param → validation error."""
        from policyshield.integrations.nanobot.registry import ShieldedToolRegistry as SR
        registry = SR(ShieldEngine(_make_ruleset([])), fail_open=True)
        registry.register(EchoTool())
        result = asyncio.run(registry.execute("echo", {}))
        assert "missing required" in result.lower() or "error" in result.lower()
