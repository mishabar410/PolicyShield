"""Tests for engine kill switch (Prompt 204)."""

from __future__ import annotations

import threading
import time

import pytest

from policyshield.core.models import RuleSet, ShieldMode, Verdict
from policyshield.shield.engine import ShieldEngine


def _make_engine() -> ShieldEngine:
    """Engine with no rules, default allow."""
    return ShieldEngine(rules=RuleSet(shield_name="test", version=1, rules=[], default_verdict=Verdict.ALLOW))


class TestKillSwitch:
    def test_not_killed_by_default(self):
        engine = _make_engine()
        assert not engine.is_killed

    def test_kill_blocks_all(self):
        engine = _make_engine()
        engine.kill()
        result = engine.check("any_tool", {})
        assert result.verdict == Verdict.BLOCK
        assert result.rule_id == "__kill_switch__"

    def test_kill_with_reason(self):
        engine = _make_engine()
        engine.kill(reason="Active exploit detected")
        result = engine.check("any_tool", {})
        assert "Active exploit" in result.message

    def test_resume_restores(self):
        engine = _make_engine()
        engine.kill()
        engine.resume()
        assert not engine.is_killed
        result = engine.check("any_tool", {})
        assert result.verdict == Verdict.ALLOW

    def test_kill_overrides_rules(self):
        """Kill switch blocks even tools that would be allowed by rules."""
        from policyshield.core.models import RuleConfig

        rules = RuleSet(
            shield_name="test",
            version=1,
            rules=[
                RuleConfig(
                    id="allow-read",
                    when={"tool": "read_file"},
                    then=Verdict.ALLOW,
                ),
            ],
            default_verdict=Verdict.ALLOW,
        )
        engine = ShieldEngine(rules=rules)
        engine.kill()
        result = engine.check("read_file", {})
        assert result.verdict == Verdict.BLOCK
        assert result.rule_id == "__kill_switch__"

    def test_kill_in_audit_mode(self):
        """Kill switch blocks even in AUDIT mode."""
        engine = ShieldEngine(
            rules=RuleSet(shield_name="test", version=1, rules=[], default_verdict=Verdict.ALLOW),
            mode=ShieldMode.AUDIT,
        )
        engine.kill()
        result = engine.check("any_tool", {})
        assert result.verdict == Verdict.BLOCK

    def test_thread_safety(self):
        """Kill switch is safe to use from multiple threads."""
        engine = _make_engine()
        errors: list[Exception] = []

        def checker():
            for _ in range(100):
                try:
                    engine.check("tool", {})
                except Exception as e:
                    errors.append(e)

        def toggler():
            for _ in range(50):
                engine.kill()
                time.sleep(0.001)
                engine.resume()

        t1 = threading.Thread(target=checker)
        t2 = threading.Thread(target=toggler)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert errors == []

    def test_is_killed_property(self):
        engine = _make_engine()
        assert not engine.is_killed
        engine.kill()
        assert engine.is_killed
        engine.resume()
        assert not engine.is_killed
