"""Tests for PII taint chain mechanism."""

from __future__ import annotations

import pytest

from policyshield.core.models import (
    RuleConfig,
    RuleSet,
    TaintChainConfig,
    Verdict,
)
from policyshield.shield.engine import ShieldEngine


def _make_engine(
    taint_enabled: bool = True,
    outgoing_tools: list[str] | None = None,
) -> ShieldEngine:
    """Build a ShieldEngine with taint chain config."""
    rules = RuleSet(
        shield_name="taint-test",
        version=1,
        rules=[
            RuleConfig(
                id="allow-all",
                description="allow everything",
                then=Verdict.ALLOW,
            ),
        ],
        taint_chain=TaintChainConfig(
            enabled=taint_enabled,
            outgoing_tools=outgoing_tools or ["send_message", "web_fetch", "email_send"],
        ),
    )
    return ShieldEngine(rules=rules)


class TestTaintChain:
    """Test suite for PII taint chain."""

    def test_taint_blocks_outgoing_after_pii(self) -> None:
        """After PII in output, outgoing tools should be blocked."""
        engine = _make_engine()

        # Normal call passes
        r1 = engine.check("web_search", {"query": "test"}, session_id="s1")
        assert r1.verdict == Verdict.ALLOW

        # PII detected in tool output → taint
        engine.post_check("web_search", "user email is john@corp.com", session_id="s1")

        # Outgoing call is now blocked
        r2 = engine.check("send_message", {"text": "hello"}, session_id="s1")
        assert r2.verdict == Verdict.BLOCK
        assert "tainted" in r2.message.lower()
        assert r2.rule_id == "__pii_taint__"

    def test_non_outgoing_still_allowed(self) -> None:
        """Non-outgoing tools should pass even when session is tainted."""
        engine = _make_engine()
        engine.post_check("web_search", "john@corp.com", session_id="s1")

        # Non-outgoing tool still works
        r = engine.check("read_file", {"path": "/tmp/x"}, session_id="s1")
        assert r.verdict == Verdict.ALLOW

    def test_clear_taint_re_enables_outgoing(self) -> None:
        """After clearing taint, outgoing calls should work again."""
        engine = _make_engine()
        engine.post_check("tool", "john@corp.com output", session_id="s1")

        session = engine.session_manager.get("s1")
        assert session is not None
        assert session.pii_tainted

        session.clear_taint()

        r = engine.check("send_message", {"text": "hello"}, session_id="s1")
        assert r.verdict == Verdict.ALLOW

    def test_taint_disabled_by_default(self) -> None:
        """When taint chain is disabled, PII in output doesn't block outgoing."""
        engine = _make_engine(taint_enabled=False)
        engine.post_check("tool", "john@corp.com output", session_id="s1")

        r = engine.check("send_message", {"text": "hello"}, session_id="s1")
        assert r.verdict == Verdict.ALLOW

    def test_session_tainted_flag_in_post_check_result(self) -> None:
        """Post-check result should indicate session was tainted."""
        engine = _make_engine()
        result = engine.post_check("tool", "call me at 555-123-4567", session_id="s2")
        assert result.session_tainted is True

    def test_taint_details_contain_pii_types(self) -> None:
        """Taint details should mention the detected PII types."""
        engine = _make_engine()
        engine.post_check("web_search", "john@corp.com", session_id="s3")

        session = engine.session_manager.get("s3")
        assert session is not None
        assert session.pii_tainted
        assert "EMAIL" in (session.taint_details or "")

    def test_multiple_pii_types_in_taint(self) -> None:
        """Multiple PII types should be tracked."""
        engine = _make_engine()
        engine.post_check(
            "search", "email: john@corp.com, phone: 555-123-4567", session_id="s4"
        )

        session = engine.session_manager.get("s4")
        assert session is not None
        assert session.pii_tainted
        assert "EMAIL" in (session.taint_details or "")
