"""Extra tests to push coverage above 85% threshold."""

import pytest

from policyshield.core.models import RuleConfig, RuleSet, ShieldMode, Verdict


class TestApprovalLazyImports:
    """Cover lazy __getattr__ in policyshield.approval.__init__."""

    def test_telegram_backend_lazy_import(self):
        from policyshield.approval import TelegramApprovalBackend

        assert TelegramApprovalBackend is not None

    def test_webhook_backend_lazy_import(self):
        from policyshield.approval import WebhookApprovalBackend

        assert WebhookApprovalBackend is not None

    def test_compute_signature_lazy_import(self):
        from policyshield.approval import compute_signature

        assert callable(compute_signature)

    def test_verify_signature_lazy_import(self):
        from policyshield.approval import verify_signature

        assert callable(verify_signature)

    def test_unknown_attr_raises(self):
        with pytest.raises(AttributeError):
            from policyshield import approval

            approval.__getattr__("nonexistent_thing")


class TestShieldEngineFailOpen:
    """Cover fail-open and fail-closed paths in ShieldEngine.check."""

    def test_check_fail_open_on_error(self):
        """When fail_open=True, engine errors produce ALLOW."""
        from unittest.mock import patch

        from policyshield.shield.engine import ShieldEngine

        rules = RuleSet(
            shield_name="t",
            version=1,
            rules=[
                RuleConfig(id="r1", when={"tool": "exec"}, then=Verdict.BLOCK),
            ],
        )
        engine = ShieldEngine(rules, fail_open=True)

        with patch.object(engine, "_do_check_sync", side_effect=RuntimeError("boom")):
            result = engine.check("exec", {"cmd": "test"})
        assert result.verdict == Verdict.ALLOW

    def test_check_fail_closed_on_error(self):
        """When fail_open=False, engine errors raise PolicyShieldError."""
        from unittest.mock import patch

        from policyshield.core.exceptions import PolicyShieldError
        from policyshield.shield.engine import ShieldEngine

        rules = RuleSet(
            shield_name="t",
            version=1,
            rules=[
                RuleConfig(id="r1", when={"tool": "exec"}, then=Verdict.BLOCK),
            ],
        )
        engine = ShieldEngine(rules, fail_open=False)

        with patch.object(engine, "_do_check_sync", side_effect=RuntimeError("boom")):
            with pytest.raises(PolicyShieldError):
                engine.check("exec", {"cmd": "test"})


class TestShieldEngineDisabled:
    """Cover disabled mode in ShieldEngine."""

    def test_disabled_mode_allows_all(self):
        from policyshield.shield.engine import ShieldEngine

        rules = RuleSet(
            shield_name="t",
            version=1,
            rules=[
                RuleConfig(id="r1", when={"tool": "exec"}, then=Verdict.BLOCK),
            ],
        )
        engine = ShieldEngine(rules, mode=ShieldMode.DISABLED)
        result = engine.check("exec", {"cmd": "rm -rf /"})
        assert result.verdict == Verdict.ALLOW


class TestRuleConfigPriority:
    """Cover priority field serialization."""

    def test_priority_in_model_dump(self):
        r = RuleConfig(id="test", when={"tool": "t"}, then=Verdict.BLOCK, priority=5)
        d = r.model_dump()
        assert d["priority"] == 5

    def test_priority_default_in_dump(self):
        r = RuleConfig(id="test", when={"tool": "t"}, then=Verdict.ALLOW)
        d = r.model_dump()
        assert d["priority"] == 1
