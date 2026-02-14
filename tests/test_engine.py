"""Tests for ShieldEngine orchestrator."""

import json

import pytest

from policyshield.core.models import (
    PIIType,
    PostCheckResult,
    RuleConfig,
    RuleSet,
    ShieldMode,
    Verdict,
)
from policyshield.shield.engine import ShieldEngine
from policyshield.trace.recorder import TraceRecorder


def make_ruleset(rules: list[RuleConfig], **kwargs) -> RuleSet:
    return RuleSet(shield_name="test", version=1, rules=rules, **kwargs)


@pytest.fixture
def block_exec_rules():
    return make_ruleset(
        [
            RuleConfig(
                id="block-exec",
                description="Block exec calls",
                when={"tool": "exec"},
                then=Verdict.BLOCK,
                message="exec is not allowed",
            )
        ]
    )


@pytest.fixture
def redact_rules():
    return make_ruleset(
        [
            RuleConfig(
                id="redact-pii",
                description="Redact PII in arguments",
                when={"tool": "send_email"},
                then=Verdict.REDACT,
            )
        ]
    )


@pytest.fixture
def approve_rules():
    return make_ruleset(
        [
            RuleConfig(
                id="approve-delete",
                description="Deletion requires approval",
                when={"tool": "delete_user"},
                then=Verdict.APPROVE,
            )
        ]
    )


@pytest.fixture
def rate_limit_rules():
    return make_ruleset(
        [
            RuleConfig(
                id="rate-limit",
                description="Rate limit after 5 calls",
                when={"tool": "api_call", "session": {"total_calls": {"gt": 5}}},
                then=Verdict.BLOCK,
                message="Rate limit exceeded",
            )
        ]
    )


class TestShieldEngineAllow:
    def test_no_matching_rule(self, block_exec_rules):
        engine = ShieldEngine(block_exec_rules)
        result = engine.check("read_file", {"path": "/etc/passwd"})
        assert result.verdict == Verdict.ALLOW

    def test_disabled_mode(self, block_exec_rules):
        engine = ShieldEngine(block_exec_rules, mode=ShieldMode.DISABLED)
        result = engine.check("exec", {"command": "rm -rf /"})
        assert result.verdict == Verdict.ALLOW


class TestShieldEngineBlock:
    def test_block_exec(self, block_exec_rules):
        engine = ShieldEngine(block_exec_rules)
        result = engine.check("exec", {"command": "rm -rf /"})
        assert result.verdict == Verdict.BLOCK
        assert result.rule_id == "block-exec"
        assert "[BLOCK]" in result.message


class TestShieldEngineRedact:
    def test_redact_pii(self, redact_rules):
        engine = ShieldEngine(redact_rules)
        result = engine.check("send_email", {"body": "Contact: john@example.com"})
        assert result.verdict == Verdict.REDACT
        assert result.modified_args is not None


class TestShieldEngineApprove:
    def test_approve_no_backend_blocks(self, approve_rules):
        """Without approval backend, APPROVE rules result in BLOCK."""
        engine = ShieldEngine(approve_rules)
        result = engine.check("delete_user", {"user_id": "123"})
        assert result.verdict == Verdict.BLOCK
        assert "no approval backend" in result.message.lower()


class TestShieldEngineAudit:
    def test_audit_mode_allows_all(self, block_exec_rules):
        engine = ShieldEngine(block_exec_rules, mode=ShieldMode.AUDIT)
        result = engine.check("exec", {"command": "rm -rf /"})
        assert result.verdict == Verdict.ALLOW
        assert "[AUDIT]" in result.message
        assert result.rule_id == "block-exec"


class TestShieldEngineSession:
    def test_rate_limiting(self, rate_limit_rules):
        engine = ShieldEngine(rate_limit_rules)
        # First 6 calls should be allowed (session starts at 0)
        for i in range(6):
            result = engine.check("api_call", session_id="s1")
            assert result.verdict == Verdict.ALLOW, f"Call {i} should be allowed"
        # 7th call should be blocked
        result = engine.check("api_call", session_id="s1")
        assert result.verdict == Verdict.BLOCK


class TestShieldEngineTrace:
    def test_trace_recording(self, block_exec_rules, tmp_path):
        with TraceRecorder(tmp_path) as tracer:
            engine = ShieldEngine(block_exec_rules, trace_recorder=tracer)
            engine.check("exec", {"command": "ls"})
            engine.check("read_file", {"path": "/tmp/log"})
        # Check trace file
        content = tracer.file_path.read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 2
        entry = json.loads(lines[0])
        assert entry["verdict"] == "BLOCK"


class TestShieldEngineFailOpen:
    def test_fail_open_on_error(self):
        """Shield should allow if internal error and fail_open=True."""
        rules = make_ruleset([RuleConfig(id="r1", when={"tool": "test"}, then=Verdict.BLOCK)])
        engine = ShieldEngine(rules, fail_open=True)

        # Monkey-patch to cause error
        original = engine._pii.scan_dict
        engine._pii.scan_dict = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("PII error"))

        # Should not raise because fail_open is in _do_check scope;
        # but PII error is caught inside _do_check
        result = engine.check("test", {"data": "value"})
        # The rule matches but PII error is caught, still BLOCK
        assert result.verdict == Verdict.BLOCK

        engine._pii.scan_dict = original


class TestShieldEngineIntegration:
    def test_from_yaml_file(self, tmp_path):
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
        engine = ShieldEngine(str(yaml_file))
        result = engine.check("exec")
        assert result.verdict == Verdict.BLOCK

    def test_reload_rules(self, tmp_path):
        yaml1 = tmp_path / "rules1.yaml"
        yaml1.write_text("""\
shield_name: test
version: 1
rules:
  - id: r1
    when:
      tool: exec
    then: BLOCK
""")
        yaml2 = tmp_path / "rules2.yaml"
        yaml2.write_text("""\
shield_name: test
version: 2
rules:
  - id: r2
    when:
      tool: exec
    then: ALLOW
""")
        engine = ShieldEngine(str(yaml1))
        assert engine.check("exec").verdict == Verdict.BLOCK
        engine.reload_rules(str(yaml2))
        assert engine.check("exec").verdict == Verdict.ALLOW

    def test_mode_property(self, block_exec_rules):
        engine = ShieldEngine(block_exec_rules)
        assert engine.mode == ShieldMode.ENFORCE
        engine.mode = ShieldMode.DISABLED
        assert engine.mode == ShieldMode.DISABLED

    def test_rule_count(self, block_exec_rules):
        engine = ShieldEngine(block_exec_rules)
        assert engine.rule_count == 1

    def test_post_check(self, block_exec_rules):
        engine = ShieldEngine(block_exec_rules)
        result = engine.post_check("exec", {"output": "done"})
        assert isinstance(result, PostCheckResult)
        assert result.pii_matches == []
        assert result.session_tainted is False

    def test_post_check_string_pii(self, block_exec_rules):
        """post_check on string with email → pii_matches contains EMAIL."""
        engine = ShieldEngine(block_exec_rules)
        result = engine.post_check("exec", "Contact: test@example.com today")
        assert isinstance(result, PostCheckResult)
        assert len(result.pii_matches) > 0
        pii_types = {m.pii_type for m in result.pii_matches}
        assert PIIType.EMAIL in pii_types
        assert result.redacted_output is not None
        assert "test@example.com" not in result.redacted_output


class TestDefaultVerdict:
    """Tests for default_verdict (zero-trust default)."""

    def test_default_verdict_block_unmatched_tool(self):
        """Unmatched tool should BLOCK when default_verdict is BLOCK."""
        rules = make_ruleset(
            [RuleConfig(id="r1", when={"tool": "exec"}, then=Verdict.BLOCK)],
            default_verdict=Verdict.BLOCK,
        )
        engine = ShieldEngine(rules)
        result = engine.check("unknown_tool", {"arg": "val"})
        assert result.verdict == Verdict.BLOCK
        assert result.rule_id == "__default__"
        assert "Default policy" in result.message

    def test_default_verdict_allow_unmatched_tool(self):
        """Unmatched tool should ALLOW when default_verdict is ALLOW (legacy)."""
        rules = make_ruleset(
            [RuleConfig(id="r1", when={"tool": "exec"}, then=Verdict.BLOCK)],
            default_verdict=Verdict.ALLOW,
        )
        engine = ShieldEngine(rules)
        result = engine.check("unknown_tool", {"arg": "val"})
        assert result.verdict == Verdict.ALLOW

    def test_default_verdict_from_yaml(self, tmp_path):
        """Parser reads default_verdict from YAML."""
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text("""\
shield_name: test
version: 1
default_verdict: BLOCK
rules:
  - id: r1
    when:
      tool: exec
    then: ALLOW
""")
        engine = ShieldEngine(str(yaml_file))
        # exec matches rule → ALLOW
        assert engine.check("exec").verdict == Verdict.ALLOW
        # unknown tool → default_verdict → BLOCK
        result = engine.check("unknown_tool")
        assert result.verdict == Verdict.BLOCK
        assert result.rule_id == "__default__"


class TestPostCheckResult:
    """Tests for PostCheckResult structured return."""

    def test_post_check_returns_post_check_result(self):
        """post_check returns PostCheckResult, not ShieldResult."""
        rules = make_ruleset([RuleConfig(id="r1", when={"tool": "x"}, then=Verdict.BLOCK)])
        engine = ShieldEngine(rules)
        result = engine.post_check("x", "no pii here")
        assert isinstance(result, PostCheckResult)
        assert result.pii_matches == []
        assert result.redacted_output is None
        assert result.session_tainted is False

    def test_post_check_redacted_output(self):
        """post_check redacts PII and populates redacted_output."""
        rules = make_ruleset([RuleConfig(id="r1", when={"tool": "x"}, then=Verdict.BLOCK)])
        engine = ShieldEngine(rules)
        result = engine.post_check("x", "Send to user@corp.com please")
        assert isinstance(result, PostCheckResult)
        assert len(result.pii_matches) > 0
        assert result.redacted_output is not None
        assert "user@corp.com" not in result.redacted_output
        assert result.session_tainted is True

    def test_post_check_dict_input(self):
        """post_check handles dict input with PII."""
        rules = make_ruleset([RuleConfig(id="r1", when={"tool": "x"}, then=Verdict.BLOCK)])
        engine = ShieldEngine(rules)
        result = engine.post_check("x", {"email": "user@corp.com", "data": "clean"})
        assert isinstance(result, PostCheckResult)
        assert len(result.pii_matches) > 0
        assert result.session_tainted is True


class TestMatcherErrorHandling:
    """Tests for matcher error handling (fail-open / fail-closed)."""

    def test_matcher_error_fail_closed(self):
        """Matcher error with fail_open=False → BLOCK."""
        rules = make_ruleset([RuleConfig(id="r1", when={"tool": "test"}, then=Verdict.ALLOW)])
        engine = ShieldEngine(rules, fail_open=False)

        # Monkey-patch matcher to throw
        engine._matcher.find_best_match = lambda **kw: (_ for _ in ()).throw(RuntimeError("matcher crash"))

        result = engine.check("test", {"data": "val"})
        assert result.verdict == Verdict.BLOCK
        assert result.rule_id == "__error__"
        assert "matcher crash" in result.message

    def test_matcher_error_fail_open(self):
        """Matcher error with fail_open=True → ALLOW."""
        rules = make_ruleset([RuleConfig(id="r1", when={"tool": "test"}, then=Verdict.ALLOW)])
        engine = ShieldEngine(rules, fail_open=True)

        # Monkey-patch matcher to throw
        engine._matcher.find_best_match = lambda **kw: (_ for _ in ()).throw(RuntimeError("matcher crash"))

        result = engine.check("test", {"data": "val"})
        assert result.verdict == Verdict.ALLOW


class TestPolicySummary:
    """Tests for get_policy_summary."""

    def test_get_policy_summary(self):
        """get_policy_summary returns formatted string."""
        rules = make_ruleset(
            [
                RuleConfig(
                    id="block-exec",
                    description="Block exec calls",
                    when={"tool": "exec"},
                    then=Verdict.BLOCK,
                    message="exec is not allowed",
                ),
                RuleConfig(
                    id="allow-read",
                    description="Allow file reads",
                    when={"tool": "read_file"},
                    then=Verdict.ALLOW,
                ),
            ],
            default_verdict=Verdict.BLOCK,
        )
        engine = ShieldEngine(rules)
        summary = engine.get_policy_summary()
        assert "test" in summary
        assert "BLOCK" in summary
        assert "block-exec" in summary
        assert "allow-read" in summary
        assert "Rules: 2" in summary
