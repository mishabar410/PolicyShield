"""Tests for verdict builder."""

import pytest

from policyshield.core.models import PIIMatch, PIIType, RuleConfig, Severity, Verdict
from policyshield.shield.verdict import VerdictBuilder


@pytest.fixture
def builder():
    return VerdictBuilder()


@pytest.fixture
def block_rule():
    return RuleConfig(
        id="block-exec",
        description="Block exec calls",
        when={"tool": "exec"},
        then=Verdict.BLOCK,
        message="exec is not allowed",
        severity=Severity.HIGH,
    )


class TestVerdictBuilder:
    def test_allow(self, builder):
        result = builder.allow()
        assert result.verdict == Verdict.ALLOW
        assert result.rule_id is None
        assert "allowed" in result.message.lower()

    def test_allow_with_rule(self, builder, block_rule):
        result = builder.allow(rule=block_rule, args={"command": "ls"})
        assert result.verdict == Verdict.ALLOW
        assert result.rule_id == "block-exec"
        assert result.original_args == {"command": "ls"}

    def test_block(self, builder, block_rule):
        result = builder.block(rule=block_rule, tool_name="exec", args={"command": "rm -rf /"})
        assert result.verdict == Verdict.BLOCK
        assert result.rule_id == "block-exec"
        assert "[BLOCK]" in result.message
        assert "exec" in result.message
        assert "block-exec" in result.message
        assert "Suggestion:" in result.message

    def test_block_with_pii(self, builder, block_rule):
        pii = [PIIMatch(pii_type=PIIType.EMAIL, field="data", span=(0, 10), masked_value="j***@x.com")]
        result = builder.block(rule=block_rule, tool_name="exec", pii_matches=pii)
        assert result.verdict == Verdict.BLOCK
        assert len(result.pii_matches) == 1
        assert "PII detected:" in result.message
        assert "EMAIL" in result.message

    def test_redact(self, builder):
        rule = RuleConfig(id="redact-pii", description="Redact PII", then=Verdict.REDACT)
        result = builder.redact(
            rule=rule,
            tool_name="send_email",
            args={"body": "SSN: 123-45-6789"},
            modified_args={"body": "SSN: 12*-**-**89"},
        )
        assert result.verdict == Verdict.REDACT
        assert result.original_args is not None
        assert result.modified_args is not None
        assert "[REDACT]" in result.message

    def test_approve(self, builder):
        rule = RuleConfig(id="approve-delete", description="Requires approval", then=Verdict.APPROVE)
        result = builder.approve(rule=rule, tool_name="delete_user")
        assert result.verdict == Verdict.APPROVE
        assert "[APPROVE]" in result.message
        assert "approval" in result.message.lower()

    def test_counterexample_format(self, builder, block_rule):
        result = builder.block(rule=block_rule, tool_name="exec")
        lines = result.message.split("\n")
        assert lines[0].startswith("[BLOCK]")
        assert any("Rule:" in line for line in lines)
        assert any("Reason:" in line for line in lines)
        assert any("Suggestion:" in line for line in lines)
