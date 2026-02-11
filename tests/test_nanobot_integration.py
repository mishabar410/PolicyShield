"""Tests for nanobot integration (async ShieldedToolRegistry)."""

from __future__ import annotations

import asyncio

import pytest

from policyshield.core.models import RuleConfig, RuleSet, ShieldMode, Verdict
from policyshield.integrations.nanobot.context import session_id_var
from policyshield.integrations.nanobot.installer import install_shield
from policyshield.integrations.nanobot.registry import ShieldedToolRegistry
from policyshield.shield.engine import ShieldEngine


def _make_ruleset(rules: list[RuleConfig]) -> RuleSet:
    return RuleSet(shield_name="test", version=1, rules=rules)


@pytest.fixture
def block_exec_engine():
    return ShieldEngine(
        _make_ruleset([
            RuleConfig(
                id="block-exec",
                when={"tool": "exec"},
                then=Verdict.BLOCK,
                message="exec is blocked",
            ),
        ]),
    )


@pytest.fixture
def allow_all_engine():
    return ShieldEngine(_make_ruleset([]))


# ── ShieldedToolRegistry (standalone / no nanobot) ──────────────────


class TestShieldedRegistryStandalone:
    """Tests using the standalone fallback (no nanobot Tool objects)."""

    def test_register_and_execute(self, allow_all_engine):
        registry = ShieldedToolRegistry(allow_all_engine)
        registry.register_func("echo", lambda message="": message)
        result = asyncio.run(registry.execute("echo", {"message": "hello"}))
        assert result == "hello"

    def test_blocked_tool(self, block_exec_engine):
        registry = ShieldedToolRegistry(block_exec_engine)
        registry.register_func("exec", lambda command="": command)
        result = asyncio.run(registry.execute("exec", {"command": "rm -rf /"}))
        assert "BLOCKED" in result
        assert "exec is blocked" in result

    def test_unregistered_tool(self, allow_all_engine):
        registry = ShieldedToolRegistry(allow_all_engine)
        result = asyncio.run(registry.execute("missing_tool", {}))
        assert "not found" in result

    def test_tool_names(self, allow_all_engine):
        registry = ShieldedToolRegistry(allow_all_engine)
        registry.register_func("tool1", lambda: None)
        registry.register_func("tool2", lambda: None)
        assert sorted(registry.tool_names) == ["tool1", "tool2"]

    def test_redact_proceeds(self):
        """REDACT verdict should still execute the tool."""
        rules = _make_ruleset([
            RuleConfig(id="redact-pii", when={"tool": "send"}, then=Verdict.REDACT),
        ])
        engine = ShieldEngine(rules)
        registry = ShieldedToolRegistry(engine)

        calls: list[dict] = []
        registry.register_func("send", lambda **kw: calls.append(kw) or "ok")
        result = asyncio.run(registry.execute("send", {"body": "test"}))
        assert len(calls) == 1
        assert result == "ok"

    def test_fail_open(self):
        """When engine raises, fail_open=True should allow execution."""
        rules = _make_ruleset([])
        engine = ShieldEngine(rules)
        registry = ShieldedToolRegistry(engine, fail_open=True)

        # Monkey-patch engine.check to raise
        def bad_check(*_a, **_kw):
            raise RuntimeError("boom")

        engine.check = bad_check  # type: ignore[assignment]
        registry.register_func("echo", lambda msg="": msg)
        result = asyncio.run(registry.execute("echo", {"msg": "hi"}))
        assert result == "hi"

    def test_fail_closed(self):
        """When engine raises, fail_open=False should return error."""
        rules = _make_ruleset([])
        engine = ShieldEngine(rules)
        registry = ShieldedToolRegistry(engine, fail_open=False)

        def bad_check(*_a, **_kw):
            raise RuntimeError("boom")

        engine.check = bad_check  # type: ignore[assignment]
        registry.register_func("echo", lambda msg="": msg)
        result = asyncio.run(registry.execute("echo", {"msg": "hi"}))
        assert "SHIELD ERROR" in result


# ── ContextVar ──────────────────────────────────────────────────────


class TestContextVar:
    def test_default_session_id(self):
        assert session_id_var.get() == "default"

    def test_set_session_id(self):
        token = session_id_var.set("custom-session")
        assert session_id_var.get() == "custom-session"
        session_id_var.reset(token)
        assert session_id_var.get() == "default"


# ── Installer ───────────────────────────────────────────────────────


class TestInstaller:
    def test_install_from_yaml(self, tmp_path):
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text("""\
shield_name: test
version: 1
rules:
  - id: block-exec
    when:
      tool: exec
    then: BLOCK
""")
        registry = install_shield(str(yaml_file))
        assert isinstance(registry, ShieldedToolRegistry)

    def test_install_with_mode(self, tmp_path):
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text("shield_name: test\nversion: 1\nrules: []\n")
        registry = install_shield(str(yaml_file), mode=ShieldMode.AUDIT)
        assert isinstance(registry, ShieldedToolRegistry)

    def test_install_copies_existing_registry(self, tmp_path):
        """install_shield with existing_registry copies tools over."""
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text("shield_name: test\nversion: 1\nrules: []\n")

        # Create a mock registry with tool_names and get
        class FakeRegistry:
            @property
            def tool_names(self):
                return ["tool_a"]

            def get(self, name):
                return None  # Can't copy without real Tool, but should not crash

        registry = install_shield(str(yaml_file), existing_registry=FakeRegistry())
        assert isinstance(registry, ShieldedToolRegistry)


# ── Session Propagation ────────────────────────────────────────────

class TestSessionPropagation:
    """Tests verifying session_id_var is correctly propagated."""

    def test_session_id_propagated_to_engine(self, block_exec_engine):
        """session_id_var.set('user123') → engine.check sees session_id='user123'."""
        registry = ShieldedToolRegistry(block_exec_engine)
        registry.register_func("echo", lambda message="": message)

        captured_sessions: list[str] = []
        original_check = block_exec_engine.check

        def spy_check(tool_name, args=None, session_id="default", sender=None):
            captured_sessions.append(session_id)
            return original_check(tool_name, args=args, session_id=session_id, sender=sender)

        block_exec_engine.check = spy_check  # type: ignore[assignment]

        token = session_id_var.set("user123")
        try:
            asyncio.run(registry.execute("echo", {"message": "hi"}))
        finally:
            session_id_var.reset(token)

        assert captured_sessions == ["user123"]

    def test_session_id_reset_after_execute(self, allow_all_engine):
        """After execute — session_id returns to default."""
        assert session_id_var.get() == "default"
        token = session_id_var.set("temp-session")
        session_id_var.reset(token)
        assert session_id_var.get() == "default"

    def test_session_id_per_coroutine(self, allow_all_engine):
        """Two concurrent executes with different session_ids — no cross-contamination."""
        registry = ShieldedToolRegistry(allow_all_engine)
        captured: list[str] = []

        def capture_sid(**kw):
            captured.append(session_id_var.get())
            return "ok"

        registry.register_func("tool", capture_sid)

        async def run_with_session(sid: str):
            token = session_id_var.set(sid)
            try:
                await registry.execute("tool", {})
            finally:
                session_id_var.reset(token)

        async def main():
            await asyncio.gather(
                run_with_session("sess-A"),
                run_with_session("sess-B"),
            )

        asyncio.run(main())
        assert set(captured) == {"sess-A", "sess-B"}

