"""Tests for the plugin system."""

from __future__ import annotations

from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.plugins import (
    DetectorResult,
    clear_registry,
    detector,
    get_detectors,
    get_pre_check_hooks,
    post_check_hook,
    pre_check_hook,
)
from policyshield.shield.engine import ShieldEngine

_allow_all = RuleSet(
    shield_name="test",
    version=1,
    rules=[RuleConfig(id="allow-all", tool=".*", then=Verdict.ALLOW)],
)


class TestPluginSystem:
    def setup_method(self):
        clear_registry()

    def teardown_method(self):
        clear_registry()

    def test_detector_registration(self):
        @detector("test_detector")
        def my_detector(tool_name, args):
            if "dangerous" in str(args):
                return DetectorResult(detected=True, message="Dangerous!")
            return DetectorResult()

        assert "test_detector" in get_detectors()
        result = get_detectors()["test_detector"]("exec", {"cmd": "dangerous"})
        assert result.detected

    def test_detector_integration_blocks(self):
        @detector("blocker")
        def blocker(tool_name, args):
            return DetectorResult(detected=True, message="Blocked by plugin")

        engine = ShieldEngine(rules=_allow_all)
        result = engine.check("test", {})
        assert result.verdict == Verdict.BLOCK
        assert "__plugin__blocker" in result.rule_id

    def test_detector_not_triggered_passes(self):
        @detector("safe")
        def safe_detector(tool_name, args):
            return DetectorResult(detected=False)

        engine = ShieldEngine(rules=_allow_all)
        result = engine.check("test", {})
        assert result.verdict == Verdict.ALLOW

    def test_pre_check_hook(self):
        calls = []

        @pre_check_hook
        def my_hook(tool_name, args):
            calls.append(tool_name)

        hooks = get_pre_check_hooks()
        assert len(hooks) == 1
        hooks[0]("exec", {})
        assert calls == ["exec"]

    def test_post_check_hook(self):
        @post_check_hook
        def my_hook(tool_name, result):
            pass

        from policyshield.plugins import get_post_check_hooks

        assert len(get_post_check_hooks()) == 1

    def test_clear_registry(self):
        @detector("tmp")
        def tmp(tool_name, args):
            return DetectorResult()

        assert len(get_detectors()) == 1
        clear_registry()
        assert len(get_detectors()) == 0
