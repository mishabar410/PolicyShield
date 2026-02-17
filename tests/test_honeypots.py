"""Tests for honeypot tools."""

from policyshield.shield.honeypots import (
    HoneypotChecker,
    HoneypotConfig,
)


class TestHoneypotConfig:
    def test_from_dict(self):
        cfg = HoneypotConfig.from_dict({"name": "admin_panel", "alert": "Alert!"})
        assert cfg.name == "admin_panel"
        assert cfg.alert == "Alert!"

    def test_default_alert(self):
        cfg = HoneypotConfig.from_dict({"name": "admin_panel"})
        assert "admin_panel" in cfg.alert

    def test_default_severity(self):
        cfg = HoneypotConfig.from_dict({"name": "x"})
        assert cfg.severity == "critical"


class TestHoneypotChecker:
    def test_match(self):
        checker = HoneypotChecker([HoneypotConfig(name="secret_tool", alert="CAUGHT")])
        match = checker.check("secret_tool")
        assert match is not None
        assert match.tool_name == "secret_tool"
        assert "CAUGHT" in match.message

    def test_no_match(self):
        checker = HoneypotChecker([HoneypotConfig(name="secret_tool")])
        assert checker.check("read_file") is None

    def test_multiple_honeypots(self):
        checker = HoneypotChecker(
            [
                HoneypotConfig(name="admin_panel"),
                HoneypotConfig(name="export_all"),
                HoneypotConfig(name="disable_security"),
            ]
        )
        assert checker.check("admin_panel") is not None
        assert checker.check("export_all") is not None
        assert checker.check("normal_tool") is None
        assert len(checker) == 3

    def test_from_config(self):
        checker = HoneypotChecker.from_config(
            [
                {"name": "a", "alert": "Alert A"},
                {"name": "b"},
            ]
        )
        assert len(checker) == 2
        assert checker.check("a") is not None

    def test_names(self):
        checker = HoneypotChecker(
            [
                HoneypotConfig(name="a"),
                HoneypotConfig(name="b"),
            ]
        )
        assert checker.names == {"a", "b"}


class TestHoneypotE2E:
    """Test honeypots through the engine pipeline."""

    def test_engine_blocks_honeypot(self):
        from policyshield.core.models import RuleSet, Verdict
        from policyshield.shield.engine import ShieldEngine

        ruleset = RuleSet(
            shield_name="test",
            version=1,
            rules=[],
            default_verdict=Verdict.ALLOW,
            honeypots=[{"name": "internal_admin", "alert": "Admin access attempted!"}],
        )
        engine = ShieldEngine(rules=ruleset)
        result = engine.check("internal_admin", {})
        assert result.verdict == Verdict.BLOCK
        assert "__honeypot__" in (result.rule_id or "")

    def test_engine_allows_normal_tool(self):
        from policyshield.core.models import RuleSet, Verdict
        from policyshield.shield.engine import ShieldEngine

        ruleset = RuleSet(
            shield_name="test",
            version=1,
            rules=[],
            default_verdict=Verdict.ALLOW,
            honeypots=[{"name": "internal_admin"}],
        )
        engine = ShieldEngine(rules=ruleset)
        result = engine.check("read_file", {"path": "test.txt"})
        assert result.verdict == Verdict.ALLOW

    def test_honeypot_overrides_audit_mode(self):
        from policyshield.core.models import RuleSet, ShieldMode, Verdict
        from policyshield.shield.engine import ShieldEngine

        ruleset = RuleSet(
            shield_name="test",
            version=1,
            rules=[],
            default_verdict=Verdict.ALLOW,
            honeypots=[{"name": "bad_tool"}],
        )
        engine = ShieldEngine(rules=ruleset, mode=ShieldMode.AUDIT)
        result = engine.check("bad_tool", {})
        assert result.verdict == Verdict.BLOCK  # Always block, even in audit
