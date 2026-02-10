"""Tests for core data models."""

from datetime import datetime

import pytest

from policyshield.core.models import (
    ArgsMatcherConfig,
    PIIMatch,
    PIIType,
    RuleConfig,
    RuleSet,
    SessionState,
    Severity,
    ShieldMode,
    ShieldResult,
    TraceRecord,
    Verdict,
)


class TestEnums:
    def test_verdict_values(self):
        assert Verdict.ALLOW == "ALLOW"
        assert Verdict.BLOCK == "BLOCK"
        assert Verdict.APPROVE == "APPROVE"
        assert Verdict.REDACT == "REDACT"

    def test_severity_values(self):
        assert Severity.LOW == "LOW"
        assert Severity.CRITICAL == "CRITICAL"

    def test_pii_type_values(self):
        assert PIIType.EMAIL == "EMAIL"
        assert PIIType.CREDIT_CARD == "CREDIT_CARD"
        assert PIIType.CUSTOM == "CUSTOM"

    def test_shield_mode_values(self):
        assert ShieldMode.ENFORCE == "ENFORCE"
        assert ShieldMode.AUDIT == "AUDIT"
        assert ShieldMode.DISABLED == "DISABLED"


class TestArgsMatcherConfig:
    def test_create_minimal(self):
        config = ArgsMatcherConfig(field="command", predicate="regex", value="rm\\s+-rf")
        assert config.field == "command"
        assert config.predicate == "regex"
        assert config.value == "rm\\s+-rf"

    def test_frozen(self):
        config = ArgsMatcherConfig(field="x", predicate="y", value="z")
        with pytest.raises(Exception):
            config.field = "changed"


class TestRuleConfig:
    def test_create_with_block(self):
        rule = RuleConfig(id="test-rule", then=Verdict.BLOCK)
        assert rule.then == Verdict.BLOCK
        assert rule.id == "test-rule"
        assert rule.description == ""
        assert rule.enabled is True
        assert rule.severity == Severity.LOW

    def test_create_full(self):
        rule = RuleConfig(
            id="full-rule",
            description="A test rule",
            when={"tool": "exec"},
            then=Verdict.BLOCK,
            message="Blocked!",
            severity=Severity.CRITICAL,
            enabled=False,
        )
        assert rule.description == "A test rule"
        assert rule.severity == Severity.CRITICAL
        assert rule.enabled is False

    def test_frozen(self):
        rule = RuleConfig(id="r", then=Verdict.ALLOW)
        with pytest.raises(Exception):
            rule.id = "changed"


class TestRuleSet:
    def test_create_minimal(self):
        rs = RuleSet(shield_name="test", version=1, rules=[])
        assert rs.shield_name == "test"
        assert rs.version == 1
        assert rs.rules == []

    def test_enabled_rules(self):
        rules = [
            RuleConfig(id="r1", then=Verdict.BLOCK, enabled=True),
            RuleConfig(id="r2", then=Verdict.ALLOW, enabled=False),
            RuleConfig(id="r3", then=Verdict.APPROVE, enabled=True),
        ]
        rs = RuleSet(shield_name="test", version=1, rules=rules)
        enabled = rs.enabled_rules()
        assert len(enabled) == 2
        assert enabled[0].id == "r1"
        assert enabled[1].id == "r3"


class TestPIIMatch:
    def test_create(self):
        match = PIIMatch(pii_type=PIIType.EMAIL, field="email", span=(0, 15), masked_value="j***@c***.com")
        assert match.pii_type == PIIType.EMAIL
        assert match.field == "email"
        assert match.span == (0, 15)
        assert match.masked_value == "j***@c***.com"

    def test_frozen(self):
        match = PIIMatch(pii_type=PIIType.EMAIL, field="x", span=(0, 1), masked_value="***")
        with pytest.raises(Exception):
            match.field = "changed"


class TestShieldResult:
    def test_create_allow(self):
        result = ShieldResult(verdict=Verdict.ALLOW)
        assert result.verdict == Verdict.ALLOW
        assert result.pii_matches == []
        assert result.rule_id is None
        assert result.original_args is None
        assert result.modified_args is None

    def test_create_block_with_pii(self):
        pii = PIIMatch(pii_type=PIIType.SSN, field="data", span=(0, 11), masked_value="***-**-6789")
        result = ShieldResult(verdict=Verdict.BLOCK, rule_id="no-pii", pii_matches=[pii])
        assert result.verdict == Verdict.BLOCK
        assert len(result.pii_matches) == 1

    def test_frozen(self):
        result = ShieldResult(verdict=Verdict.ALLOW)
        with pytest.raises(Exception):
            result.verdict = Verdict.BLOCK


class TestSessionState:
    def test_create_minimal(self):
        session = SessionState(session_id="s1", created_at=datetime.now())
        assert session.total_calls == 0
        assert session.tool_counts == {}
        assert session.taints == set()

    def test_increment(self):
        session = SessionState(session_id="s1", created_at=datetime.now())
        session.increment("exec")
        session.increment("exec")
        assert session.tool_counts["exec"] == 2
        assert session.total_calls == 2

    def test_increment_different_tools(self):
        session = SessionState(session_id="s1", created_at=datetime.now())
        session.increment("exec")
        session.increment("read_file")
        session.increment("exec")
        assert session.tool_counts["exec"] == 2
        assert session.tool_counts["read_file"] == 1
        assert session.total_calls == 3

    def test_mutable(self):
        session = SessionState(session_id="s1", created_at=datetime.now())
        session.session_id = "s2"
        assert session.session_id == "s2"


class TestTraceRecord:
    def test_create_minimal(self):
        tr = TraceRecord(
            timestamp=datetime.now(),
            session_id="s1",
            tool="exec",
            verdict=Verdict.ALLOW,
        )
        assert tr.tool == "exec"
        assert tr.verdict == Verdict.ALLOW
        assert tr.pii_types == []
        assert tr.args_hash is None

    def test_frozen(self):
        tr = TraceRecord(
            timestamp=datetime.now(),
            session_id="s1",
            tool="exec",
            verdict=Verdict.ALLOW,
        )
        with pytest.raises(Exception):
            tr.tool = "changed"
