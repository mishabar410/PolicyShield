"""End-to-end tests for PolicyShield v0.2 features."""

from __future__ import annotations

import time


from policyshield.approval.cache import ApprovalCache, ApprovalStrategy
from policyshield.approval.memory import InMemoryBackend
from policyshield.cli.main import app as cli_main
from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.lint.linter import RuleLinter
from policyshield.shield.engine import ShieldEngine
from policyshield.shield.rate_limiter import RateLimitConfig, RateLimiter
from policyshield.trace.analyzer import TraceAnalyzer
from policyshield.trace.recorder import TraceRecorder


class TestE2ELinter:
    def test_e2e_lint_catches_errors(self, tmp_path):
        yaml_file = tmp_path / "bad_rules.yaml"
        yaml_file.write_text("""\
shield_name: test
version: 1
rules:
  - id: ""
    when: {}
    then: BLOCK
  - id: dup-id
    when:
      tool: exec
    then: BLOCK
  - id: dup-id
    when:
      tool: read
    then: ALLOW
""")
        linter = RuleLinter()
        # Build RuleSet directly to skip parser validation
        ruleset = RuleSet(
            shield_name="test",
            version=1,
            rules=[
                RuleConfig(id="", when={}, then=Verdict.BLOCK),
                RuleConfig(id="dup-id", when={"tool": "exec"}, then=Verdict.BLOCK),
                RuleConfig(id="dup-id", when={"tool": "read"}, then=Verdict.ALLOW),
            ],
        )
        warnings = linter.lint(ruleset)
        checks = [w.check for w in warnings]
        assert "duplicate_ids" in checks
        # Empty ID generates no specific check but the rule has empty "when"
        assert len(warnings) >= 1


class TestE2EHotReload:
    def test_e2e_hot_reload_updates_engine(self, tmp_path):
        yaml1 = tmp_path / "rules.yaml"
        yaml1.write_text("""\
shield_name: test
version: 1
rules:
  - id: block-exec
    when:
      tool: exec
    then: BLOCK
""")
        engine = ShieldEngine(str(yaml1))
        assert engine.check("exec").verdict == Verdict.BLOCK

        yaml1.write_text("""\
shield_name: test
version: 2
rules:
  - id: allow-all
    when:
      tool: exec
    then: ALLOW
""")
        engine.reload_rules(str(yaml1))
        assert engine.check("exec").verdict == Verdict.ALLOW


class TestE2EPII:
    def test_e2e_inn_blocked_by_pii_rule(self):
        rules = RuleSet(
            shield_name="test",
            version=1,
            rules=[
                RuleConfig(
                    id="no-pii",
                    when={"tool": "web_fetch"},
                    then=Verdict.BLOCK,
                )
            ],
        )
        engine = ShieldEngine(rules)
        result = engine.check("web_fetch", {"url": "https://example.com/inn/7707083893"})
        assert result.verdict == Verdict.BLOCK

    def test_e2e_custom_pii_pattern(self, tmp_path):
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text("""\
shield_name: test
version: 1
pii_patterns:
  - name: CUSTOM_ID
    pattern: "CUST-\\\\d{6}"
rules:
  - id: block-pii
    when:
      tool: send
    then: REDACT
""")
        engine = ShieldEngine(str(yaml_file))
        result = engine.check("send", {"data": "ID: CUST-123456"})
        assert result.verdict == Verdict.REDACT


class TestE2ERateLimit:
    def test_e2e_rate_limit_blocks_excess(self):
        config = RateLimitConfig(tool="exec", max_calls=3, window_seconds=10.0)
        limiter = RateLimiter([config])
        for _ in range(3):
            r = limiter.check("exec")
            assert r.allowed
            limiter.record("exec")
        r = limiter.check("exec")
        assert not r.allowed

    def test_e2e_rate_limit_window_reset(self):
        config = RateLimitConfig(tool="exec", max_calls=1, window_seconds=0.1)
        limiter = RateLimiter([config])
        assert limiter.check("exec").allowed
        limiter.record("exec")
        assert not limiter.check("exec").allowed
        time.sleep(0.15)
        assert limiter.check("exec").allowed


class TestE2EApproval:
    def test_e2e_approval_approved(self):
        rules = RuleSet(
            shield_name="test",
            version=1,
            rules=[RuleConfig(id="approve-it", when={"tool": "delete"}, then=Verdict.APPROVE)],
        )
        backend = InMemoryBackend()
        engine = ShieldEngine(rules, approval_backend=backend)

        result = engine.check("delete", {"id": "123"})
        assert result.verdict == Verdict.APPROVE
        assert result.approval_id is not None

        # Simulate async approval
        backend.respond(result.approval_id, approved=True)
        status = engine.get_approval_status(result.approval_id)
        assert status["status"] == "approved"

    def test_e2e_approval_denied(self):
        rules = RuleSet(
            shield_name="test",
            version=1,
            rules=[RuleConfig(id="approve-it", when={"tool": "delete"}, then=Verdict.APPROVE)],
        )
        backend = InMemoryBackend()
        engine = ShieldEngine(rules, approval_backend=backend)

        result = engine.check("delete", {"id": "123"})
        assert result.verdict == Verdict.APPROVE
        assert result.approval_id is not None

        # Simulate async denial
        backend.respond(result.approval_id, approved=False)
        status = engine.get_approval_status(result.approval_id)
        assert status["status"] == "denied"

    def test_e2e_approval_pending(self):
        rules = RuleSet(
            shield_name="test",
            version=1,
            rules=[RuleConfig(id="approve-it", when={"tool": "delete"}, then=Verdict.APPROVE)],
        )
        backend = InMemoryBackend()
        engine = ShieldEngine(rules, approval_backend=backend)
        result = engine.check("delete", {"id": "123"})
        assert result.verdict == Verdict.APPROVE
        # No response yet → pending
        status = engine.get_approval_status(result.approval_id)
        assert status["status"] == "pending"

    def test_e2e_batch_approve_auto(self):
        rules = RuleSet(
            shield_name="test",
            version=1,
            rules=[
                RuleConfig(
                    id="approve-exec",
                    when={"tool": "exec"},
                    then=Verdict.APPROVE,
                    approval_strategy="per_rule",
                )
            ],
        )
        backend = InMemoryBackend()
        cache = ApprovalCache(strategy=ApprovalStrategy.PER_RULE)
        engine = ShieldEngine(rules, approval_backend=backend, approval_cache=cache)

        # First call: returns APPROVE
        result1 = engine.check("exec", {"cmd": "ls"})
        assert result1.verdict == Verdict.APPROVE
        assert result1.approval_id is not None

        # Simulate approval and cache it
        backend.respond(result1.approval_id, approved=True)
        from policyshield.approval.base import ApprovalResponse

        cache.put(
            "exec",
            "approve-exec",
            "default",
            ApprovalResponse(request_id=result1.approval_id, approved=True),
            strategy=ApprovalStrategy.PER_RULE,
        )

        # Second call auto-approved from cache
        result2 = engine.check("exec", {"cmd": "ls"})
        assert result2.verdict == Verdict.ALLOW


class TestE2ETraceStats:
    def test_e2e_trace_stats_output(self, tmp_path):
        with TraceRecorder(tmp_path) as tracer:
            rules = RuleSet(
                shield_name="test",
                version=1,
                rules=[RuleConfig(id="block-exec", when={"tool": "exec"}, then=Verdict.BLOCK)],
            )
            engine = ShieldEngine(rules, trace_recorder=tracer)
            engine.check("exec", {"cmd": "rm"})
            engine.check("read_file", {"path": "/tmp/log"})

        stats = TraceAnalyzer.from_file(tracer.file_path)
        assert stats.total_calls == 2
        assert stats.verdict_counts.get("BLOCK", 0) >= 1
        assert stats.verdict_counts.get("ALLOW", 0) >= 1


class TestE2EFullPipeline:
    def test_e2e_full_pipeline(self, tmp_path):
        # 1. Create YAML rules
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text("""\
shield_name: integration-test
version: 1
rules:
  - id: block-exec
    when:
      tool: exec
    then: BLOCK
    message: "Exec is forbidden"
  - id: redact-email
    when:
      tool: send_email
    then: REDACT
""")
        # 2. Lint
        from policyshield.core.parser import load_rules

        ruleset = load_rules(str(yaml_file))
        linter = RuleLinter()
        warnings = linter.lint(ruleset)
        # Should not have critical issues
        assert all(w.code != "EMPTY_ID" for w in warnings)

        # 3. Check through engine with trace
        with TraceRecorder(tmp_path) as tracer:
            engine = ShieldEngine(str(yaml_file), trace_recorder=tracer)

            r1 = engine.check("exec", {"cmd": "rm -rf /"})
            assert r1.verdict == Verdict.BLOCK

            r2 = engine.check("send_email", {"body": "Contact: john@example.com"})
            assert r2.verdict == Verdict.REDACT

            r3 = engine.check("read_file", {"path": "/tmp/safe"})
            assert r3.verdict == Verdict.ALLOW

        # 4. Analyze trace
        stats = TraceAnalyzer.from_file(tracer.file_path)
        assert stats.total_calls == 3
        assert stats.block_rate > 0

        # 5. CLI trace stats
        from io import StringIO
        import sys

        old_stdout = sys.stdout
        sys.stdout = StringIO()
        rc = cli_main(["trace", "stats", str(tracer.file_path)])
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        assert rc == 0
        assert "Trace Statistics" in output
