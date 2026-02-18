"""Tests for shadow mode — parallel rule evaluation."""

from __future__ import annotations

import logging

from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.shield.engine import ShieldEngine


def _make_rules(*rule_configs):
    return RuleSet(
        shield_name="test",
        version=1,
        rules=list(rule_configs),
        default_verdict=Verdict.ALLOW,
    )


class TestShadowMode:
    def test_shadow_does_not_affect_verdict(self):
        """Shadow rules should not change the actual verdict."""
        base = _make_rules(RuleConfig(id="allow-all", tool=".*", then=Verdict.ALLOW))
        shadow = _make_rules(RuleConfig(id="block-all", tool=".*", then=Verdict.BLOCK))

        engine = ShieldEngine(rules=base)
        engine.set_shadow_rules(shadow)

        result = engine.check("exec", {"cmd": "ls"})
        assert result.verdict == Verdict.ALLOW  # Not affected by shadow

    def test_shadow_logs_diff(self, caplog):
        """Shadow differences should be logged."""
        base = _make_rules(RuleConfig(id="allow-all", tool=".*", then=Verdict.ALLOW))
        shadow = _make_rules(RuleConfig(id="block-exec", tool="exec", then=Verdict.BLOCK))

        engine = ShieldEngine(rules=base)
        engine.set_shadow_rules(shadow)

        with caplog.at_level(logging.INFO, logger="policyshield"):
            engine.check("exec", {"cmd": "ls"})
        assert "SHADOW" in caplog.text

    def test_clear_shadow(self):
        """Clearing shadow rules should remove the shadow matcher."""
        base = _make_rules(RuleConfig(id="allow-all", tool=".*", then=Verdict.ALLOW))
        shadow = _make_rules(RuleConfig(id="block-all", tool=".*", then=Verdict.BLOCK))

        engine = ShieldEngine(rules=base)
        engine.set_shadow_rules(shadow)
        assert engine._shadow_matcher is not None

        engine.clear_shadow_rules()
        assert engine._shadow_matcher is None

    def test_shadow_no_diff_no_log(self, caplog):
        """When shadow agrees with main verdict, no SHADOW log should appear."""
        base = _make_rules(RuleConfig(id="allow-all", tool=".*", then=Verdict.ALLOW))
        shadow = _make_rules(RuleConfig(id="also-allow", tool=".*", then=Verdict.ALLOW))

        engine = ShieldEngine(rules=base)
        engine.set_shadow_rules(shadow)

        with caplog.at_level(logging.INFO, logger="policyshield"):
            engine.check("exec", {"cmd": "ls"})
        assert "SHADOW" not in caplog.text

    def test_shadow_from_path(self, tmp_path):
        """Shadow rules can be loaded from file path."""
        base = _make_rules(RuleConfig(id="allow-all", tool=".*", then=Verdict.ALLOW))
        shadow_file = tmp_path / "shadow.yaml"
        shadow_file.write_text(
            "shield_name: test\nversion: 1\nrules:\n  - id: block-exec\n    tool: exec\n    then: BLOCK\n"
        )

        engine = ShieldEngine(rules=base)
        engine.set_shadow_rules(str(shadow_file))
        assert engine._shadow_matcher is not None

    def test_shadow_with_block_verdict(self, caplog):
        """Shadow eval should also run when main verdict is BLOCK."""
        base = _make_rules(RuleConfig(id="block-exec", tool="exec", then=Verdict.BLOCK))
        shadow = _make_rules(RuleConfig(id="allow-exec", tool="exec", then=Verdict.ALLOW))

        engine = ShieldEngine(rules=base)
        engine.set_shadow_rules(shadow)

        with caplog.at_level(logging.INFO, logger="policyshield"):
            result = engine.check("exec", {"cmd": "ls"})
        assert result.verdict == Verdict.BLOCK  # Main verdict unchanged
        assert "SHADOW" in caplog.text
