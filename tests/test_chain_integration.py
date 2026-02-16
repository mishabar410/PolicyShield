"""Tests for chain integration into the shield engine — prompt 107."""

import textwrap
import tempfile
from pathlib import Path

from policyshield.shield.engine import ShieldEngine
from policyshield.lint.linter import RuleLinter
from policyshield.core.models import RuleConfig, RuleSet, Verdict


# ── Integration: engine records events and evaluates chain rules ─────────


def _write_rules(tmp, yaml_text):
    p = Path(tmp) / "rules.yaml"
    p.write_text(textwrap.dedent(yaml_text))
    return str(p)


def test_chain_blocks_after_prerequisite():
    """Engine should BLOCK send_email only after read_file was called."""
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_rules(
            tmp,
            """\
            shield_name: test
            version: 1
            rules:
              - id: exfil
                when:
                  tool: send_email
                  chain:
                    - tool: read_file
                      within_seconds: 300
                then: BLOCK
                message: "Exfiltration detected"
        """,
        )
        engine = ShieldEngine(rules=path)

        # send_email without read_file — should ALLOW (no chain match)
        r1 = engine.check("send_email", session_id="s1")
        assert r1.verdict == Verdict.ALLOW

        # read_file — ALLOW (no rule matching it)
        r2 = engine.check("read_file", session_id="s1")
        assert r2.verdict == Verdict.ALLOW

        # Now send_email should BLOCK (read_file is in the buffer)
        r3 = engine.check("send_email", session_id="s1")
        assert r3.verdict == Verdict.BLOCK


def test_chain_different_sessions_isolated():
    """Chain events in session s1 should NOT affect session s2."""
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_rules(
            tmp,
            """\
            shield_name: test
            version: 1
            rules:
              - id: exfil
                when:
                  tool: send_email
                  chain:
                    - tool: read_file
                      within_seconds: 300
                then: BLOCK
                message: "Exfiltration detected"
        """,
        )
        engine = ShieldEngine(rules=path)

        # read_file in session s1
        engine.check("read_file", session_id="s1")

        # send_email in session s2 — should ALLOW (no read_file in s2)
        r = engine.check("send_email", session_id="s2")
        assert r.verdict == Verdict.ALLOW


# ── Linter: chain rule checks ───────────────────────────────────────────


def test_lint_chain_allow_warning():
    """Linter should warn about chain rules with ALLOW verdict."""
    rule = RuleConfig(
        id="suspicious",
        when={"tool": "x"},
        then=Verdict.ALLOW,
        chain=[{"tool": "y", "within_seconds": 60}],
    )
    rs = RuleSet(shield_name="t", version=1, rules=[rule])
    linter = RuleLinter()
    warnings = linter.check_chain_rules(rs)
    assert any(w.check == "chain_allow_verdict" for w in warnings)


def test_lint_chain_missing_tool():
    """Linter should error on chain step without 'tool' key."""
    rule = RuleConfig(
        id="bad-chain",
        when={"tool": "x"},
        then=Verdict.BLOCK,
        chain=[{"within_seconds": 60}],
    )
    rs = RuleSet(shield_name="t", version=1, rules=[rule])
    linter = RuleLinter()
    warnings = linter.check_chain_rules(rs)
    assert any(w.check == "chain_missing_tool" for w in warnings)


def test_lint_clean_chain():
    """Well-formed chain rule should produce no warnings."""
    rule = RuleConfig(
        id="good",
        when={"tool": "x"},
        then=Verdict.BLOCK,
        chain=[{"tool": "y", "within_seconds": 60}],
    )
    rs = RuleSet(shield_name="t", version=1, rules=[rule])
    linter = RuleLinter()
    warnings = linter.check_chain_rules(rs)
    assert len(warnings) == 0
