"""Tests for nanobot integration."""

import pytest

from policyshield.core.models import RuleConfig, RuleSet, ShieldMode, Verdict
from policyshield.integrations.nanobot.context import session_id_var
from policyshield.integrations.nanobot.installer import install_shield
from policyshield.integrations.nanobot.registry import PolicyViolation, ShieldedToolRegistry
from policyshield.shield.engine import ShieldEngine


def make_ruleset(rules: list[RuleConfig]) -> RuleSet:
    return RuleSet(shield_name="test", version=1, rules=rules)


@pytest.fixture
def block_exec_engine():
    rules = make_ruleset([
        RuleConfig(
            id="block-exec",
            when={"tool": "exec"},
            then=Verdict.BLOCK,
            message="exec is blocked",
        )
    ])
    return ShieldEngine(rules)


@pytest.fixture
def allow_all_engine():
    rules = make_ruleset([])
    return ShieldEngine(rules)


class TestShieldedToolRegistry:
    def test_register_and_execute(self, allow_all_engine):
        registry = ShieldedToolRegistry(allow_all_engine)
        registry.register("echo", lambda message="": message)
        result = registry.execute("echo", {"message": "hello"})
        assert result == "hello"

    def test_blocked_tool(self, block_exec_engine):
        registry = ShieldedToolRegistry(block_exec_engine)
        registry.register("exec", lambda command="": None)
        with pytest.raises(PolicyViolation) as exc_info:
            registry.execute("exec", {"command": "rm -rf /"})
        assert exc_info.value.result.verdict == Verdict.BLOCK

    def test_unregistered_tool(self, allow_all_engine):
        registry = ShieldedToolRegistry(allow_all_engine)
        with pytest.raises(KeyError, match="Tool not registered"):
            registry.execute("missing_tool")

    def test_tool_names(self, allow_all_engine):
        registry = ShieldedToolRegistry(allow_all_engine)
        registry.register("tool1", lambda: None)
        registry.register("tool2", lambda: None)
        assert sorted(registry.tool_names) == ["tool1", "tool2"]

    def test_redact_uses_modified_args(self):
        rules = make_ruleset([
            RuleConfig(id="redact-pii", when={"tool": "send"}, then=Verdict.REDACT)
        ])
        engine = ShieldEngine(rules)
        registry = ShieldedToolRegistry(engine)

        calls = []
        registry.register("send", lambda **kwargs: calls.append(kwargs))
        # Even with REDACT, execution proceeds with potentially modified args
        registry.execute("send", {"body": "test"})
        assert len(calls) == 1


class TestContextVar:
    def test_default_session_id(self):
        assert session_id_var.get() == "default"

    def test_set_session_id(self):
        token = session_id_var.set("custom-session")
        assert session_id_var.get() == "custom-session"
        session_id_var.reset(token)
        assert session_id_var.get() == "default"


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
