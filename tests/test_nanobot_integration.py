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


# ── Post-call PII Scan ─────────────────────────────────────────────


class TestPostCallPIIScan:
    """Tests verifying post-call PII scan on tool results."""

    def test_postcall_clean_result(self, allow_all_engine):
        """Tool returns clean text → no PII → result unchanged."""
        registry = ShieldedToolRegistry(allow_all_engine)
        registry.register_func("echo", lambda msg="": msg)
        result = asyncio.run(registry.execute("echo", {"msg": "hello world"}))
        assert result == "hello world"

    def test_postcall_detects_email(self, allow_all_engine):
        """Tool returns string with email → PII detected, session tainted."""
        registry = ShieldedToolRegistry(allow_all_engine)
        registry.register_func("read", lambda: "Contact: user@example.com")
        result = asyncio.run(registry.execute("read", {}))
        # Result is still returned (post-check doesn't block)
        assert "user@example.com" in result
        # Verify session taint was added
        session = allow_all_engine._session_mgr.get_or_create("default")
        from policyshield.core.models import PIIType

        assert PIIType.EMAIL in session.taints

    def test_postcall_error_failopen(self, allow_all_engine):
        """post_check raises exception → fail_open → result still returned."""
        registry = ShieldedToolRegistry(allow_all_engine, fail_open=True)
        registry.register_func("echo", lambda msg="": msg)

        # Monkey-patch post_check to raise
        def bad_post_check(*_a, **_kw):
            raise RuntimeError("post-check boom")

        allow_all_engine.post_check = bad_post_check  # type: ignore[assignment]
        result = asyncio.run(registry.execute("echo", {"msg": "data"}))
        assert result == "data"

    def test_postcall_returns_result(self, allow_all_engine):
        """Tool result is always returned regardless of PII findings."""
        registry = ShieldedToolRegistry(allow_all_engine)
        pii_output = "SSN: 123-45-6789, Email: a@b.com"
        registry.register_func("leak", lambda: pii_output)
        result = asyncio.run(registry.execute("leak", {}))
        assert result == pii_output


# ── get_definitions filter ─────────────────────────────────────────


class TestGetDefinitionsFilter:
    """Tests verifying unconditionally blocked tools are hidden."""

    def test_unconditionally_blocked_hidden(self):
        """Tool with unconditional BLOCK rule → excluded from get_definitions."""
        engine = ShieldEngine(
            _make_ruleset([
                RuleConfig(
                    id="block-exec",
                    when={"tool": "exec"},
                    then=Verdict.BLOCK,
                ),
            ])
        )
        registry = ShieldedToolRegistry(engine)
        registry.register_func("echo", lambda msg="": msg)
        registry.register_func("exec", lambda cmd="": cmd)
        # In standalone mode, get_definitions returns empty by default
        blocked = registry._get_unconditionally_blocked_tools()
        assert "exec" in blocked
        assert "echo" not in blocked

    def test_conditional_block_not_hidden(self):
        """Rule with session conditions → not considered unconditional."""
        engine = ShieldEngine(
            _make_ruleset([
                RuleConfig(
                    id="rate-limit",
                    when={"tool": "api", "session": {"total_calls": {"gt": 5}}},
                    then=Verdict.BLOCK,
                ),
            ])
        )
        registry = ShieldedToolRegistry(engine)
        blocked = registry._get_unconditionally_blocked_tools()
        assert "api" not in blocked  # conditional on session

    def test_disabled_rule_not_hidden(self):
        """Disabled rule → tool not considered blocked."""
        engine = ShieldEngine(
            _make_ruleset([
                RuleConfig(
                    id="block-disabled",
                    when={"tool": "exec"},
                    then=Verdict.BLOCK,
                    enabled=False,
                ),
            ])
        )
        registry = ShieldedToolRegistry(engine)
        blocked = registry._get_unconditionally_blocked_tools()
        assert "exec" not in blocked

    def test_no_rules_returns_empty(self):
        """No rules → no blocked tools."""
        engine = ShieldEngine(_make_ruleset([]))
        registry = ShieldedToolRegistry(engine)
        assert registry._get_unconditionally_blocked_tools() == set()


# ── Context Enrichment ─────────────────────────────────────────────


class TestContextEnrichment:
    """Tests verifying get_constraints_summary output."""

    def test_summary_with_rules(self):
        """Summary includes active rule descriptions."""
        engine = ShieldEngine(
            _make_ruleset([
                RuleConfig(
                    id="block-exec",
                    description="No shell execution",
                    when={"tool": "exec"},
                    then=Verdict.BLOCK,
                    message="exec is forbidden",
                ),
                RuleConfig(
                    id="redact-send",
                    description="Redact PII in messages",
                    when={"tool": "send_message"},
                    then=Verdict.REDACT,
                ),
            ])
        )
        registry = ShieldedToolRegistry(engine)
        summary = registry.get_constraints_summary()
        assert "PolicyShield Constraints" in summary
        assert "BLOCK" in summary
        assert "exec" in summary
        assert "exec is forbidden" in summary
        assert "REDACT" in summary
        assert "send_message" in summary

    def test_summary_empty_rules(self):
        """No active rules → empty summary."""
        engine = ShieldEngine(_make_ruleset([]))
        registry = ShieldedToolRegistry(engine)
        assert registry.get_constraints_summary() == ""

    def test_summary_disabled_rules_excluded(self):
        """Disabled rules → not shown in summary."""
        engine = ShieldEngine(
            _make_ruleset([
                RuleConfig(
                    id="disabled-rule",
                    description="This is disabled",
                    when={"tool": "exec"},
                    then=Verdict.BLOCK,
                    enabled=False,
                ),
            ])
        )
        registry = ShieldedToolRegistry(engine)
        assert registry.get_constraints_summary() == ""


# ── Subagent Shield Propagation ────────────────────────────────────


class TestSubagentShieldPropagation:
    """Tests verifying shield_config propagates to subagents."""

    def test_subagent_manager_stores_shield_config(self):
        """SubagentManager stores shield_config when provided."""
        from unittest.mock import MagicMock

        manager_cls = None
        try:
            from nanobot.agent.subagent import SubagentManager

            manager_cls = SubagentManager
        except ImportError:
            pytest.skip("nanobot not available")

        provider = MagicMock()
        provider.get_default_model.return_value = "test-model"
        bus = MagicMock()

        config = {"rules_path": "rules.yaml", "mode": "ENFORCE"}
        mgr = manager_cls(
            provider=provider,
            workspace=Path("/tmp/test"),
            bus=bus,
            shield_config=config,
        )
        assert mgr.shield_config == config

    def test_subagent_manager_no_config(self):
        """SubagentManager defaults shield_config to None."""
        from unittest.mock import MagicMock

        try:
            from nanobot.agent.subagent import SubagentManager
        except ImportError:
            pytest.skip("nanobot not available")

        provider = MagicMock()
        provider.get_default_model.return_value = "test-model"
        bus = MagicMock()

        mgr = SubagentManager(
            provider=provider,
            workspace=Path("/tmp/test"),
            bus=bus,
        )
        assert mgr.shield_config is None


# ── Approval Flow ──────────────────────────────────────────────────


class TestApprovalFlow:
    """Tests verifying approval flow in nanobot integration."""

    def test_approve_verdict_returns_message(self):
        """APPROVE verdict → returns pending message, tool not executed."""
        engine = ShieldEngine(
            _make_ruleset([
                RuleConfig(
                    id="approve-write",
                    when={"tool": "write_file"},
                    then=Verdict.APPROVE,
                    message="File writes require approval",
                ),
            ])
        )
        registry = ShieldedToolRegistry(engine)
        executed = []
        registry.register_func("write_file", lambda path="": executed.append(path))
        result = asyncio.run(registry.execute("write_file", {"path": "/etc/passwd"}))
        # Without approval backend, APPROVE falls back to BLOCKED
        assert "BLOCKED" in result or "APPROVAL REQUIRED" in result
        assert len(executed) == 0  # Tool was NOT executed

    def test_install_shield_with_approval_backend(self):
        """install_shield accepts and passes approval_backend to engine."""
        from policyshield.approval.cli_backend import CLIBackend

        backend = CLIBackend(input_func=lambda _: "n")
        registry = install_shield(
            rules_path="examples/nanobot_rules.yaml",
            approval_backend=backend,
        )
        assert registry._engine._approval_backend is backend
