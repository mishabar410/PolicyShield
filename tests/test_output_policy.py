"""Tests for output/response policy pipeline."""

from __future__ import annotations

from policyshield.core.models import OutputRule, RuleConfig, RuleSet, Verdict
from policyshield.shield.engine import ShieldEngine


def _make_rules(*output_rules):
    return RuleSet(
        shield_name="test",
        version=1,
        rules=[RuleConfig(id="allow-all", tool=".*", then=Verdict.ALLOW)],
        default_verdict=Verdict.ALLOW,
        output_rules=list(output_rules),
    )


class TestOutputPolicy:
    def test_output_size_limit_blocks(self):
        rules = _make_rules(OutputRule(id="size", max_size=100))
        engine = ShieldEngine(rules=rules)
        result = engine.post_check("test", "x" * 200)
        assert result.blocked
        assert "max_size" in (result.block_reason or "")

    def test_output_pattern_block(self):
        rules = _make_rules(OutputRule(id="pat", block_patterns=["password"]))
        engine = ShieldEngine(rules=rules)
        result = engine.post_check("db", "user: admin, password: secret123")
        assert result.blocked

    def test_output_no_match_passes(self):
        rules = _make_rules(OutputRule(id="pat", block_patterns=["secret"]))
        engine = ShieldEngine(rules=rules)
        result = engine.post_check("test", "hello world")
        assert not result.blocked

    def test_output_tool_filter(self):
        rules = _make_rules(OutputRule(id="pat", tool="read_db", block_patterns=["password"]))
        engine = ShieldEngine(rules=rules)
        # Different tool — should pass
        result = engine.post_check("exec", "password: abc")
        assert not result.blocked
        # Matching tool — should block
        result = engine.post_check("read_db", "password: abc")
        assert result.blocked

    def test_output_size_within_limit_passes(self):
        rules = _make_rules(OutputRule(id="size", max_size=1000))
        engine = ShieldEngine(rules=rules)
        result = engine.post_check("test", "x" * 100)
        assert not result.blocked

    def test_no_output_rules_passes(self):
        rules = RuleSet(
            shield_name="test",
            version=1,
            rules=[RuleConfig(id="allow-all", tool=".*", then=Verdict.ALLOW)],
        )
        engine = ShieldEngine(rules=rules)
        result = engine.post_check("test", "anything goes")
        assert not result.blocked
