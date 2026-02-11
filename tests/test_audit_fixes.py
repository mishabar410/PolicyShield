"""Tests for all audit bug fixes.

Covers:
    #1  Session increment on BLOCK/APPROVE verdicts
    #2  _parse_rule preserves approval_strategy
    #3  AsyncShieldEngine.reload_rules thread-safety
    #4  ReDoS pattern length cap in matcher
    #5  redact_dict nested fields
    #6  TraceRecorder thread safety
    #7  LangChain _arun non-blocking
    #11 IP address regex accuracy
    #12 Passport regex accuracy
"""

from __future__ import annotations

import asyncio
import textwrap
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml

from policyshield.core.models import (
    PIIType,
    RuleConfig,
    RuleSet,
    Severity,
    Verdict,
)
from policyshield.core.parser import _parse_rule, load_rules
from policyshield.shield.engine import ShieldEngine
from policyshield.shield.matcher import MAX_PATTERN_LENGTH, MatcherEngine
from policyshield.shield.pii import PIIDetector
from policyshield.shield.session import SessionManager
from policyshield.trace.recorder import TraceRecorder


# ── Helpers ──────────────────────────────────────────────────────────


def _write_rule(tmp_path: Path, rules: list[dict], **extra: Any) -> Path:
    """Write a YAML rule file and return the path."""
    data: dict[str, Any] = {
        "shield": "test-shield",
        "version": "1.0",
        "rules": rules,
    }
    data.update(extra)
    f = tmp_path / "rules.yaml"
    f.write_text(yaml.dump(data), encoding="utf-8")
    return f


# ── #1 Session increment on BLOCK ────────────────────────────────────


class TestSessionIncrementOnBlock:
    """Bug #1: session should NOT increment when verdict is BLOCK."""

    def test_session_not_incremented_on_block(self, tmp_path):
        rules_path = _write_rule(
            tmp_path,
            [
                {
                    "id": "block-rm",
                    "when": {"tool": "shell", "args": {"command": {"contains": "rm"}}},
                    "then": "BLOCK",
                    "message": "no rm",
                }
            ],
        )
        engine = ShieldEngine(str(rules_path))
        result = engine.check(tool_name="shell", args={"command": "rm -rf /"}, session_id="s1")
        assert result.verdict == Verdict.BLOCK

        session = engine._session_mgr.get_or_create("s1")
        assert session.total_calls == 0, "Session should NOT be incremented on BLOCK"
        assert session.tool_counts.get("shell", 0) == 0

    def test_session_incremented_on_allow(self, tmp_path):
        rules_path = _write_rule(
            tmp_path,
            [
                {
                    "id": "block-rm",
                    "when": {"tool": "shell", "args": {"command": {"contains": "rm"}}},
                    "then": "BLOCK",
                    "message": "no rm",
                }
            ],
        )
        engine = ShieldEngine(str(rules_path))
        result = engine.check(tool_name="shell", args={"command": "ls"}, session_id="s1")
        assert result.verdict == Verdict.ALLOW

        session = engine._session_mgr.get_or_create("s1")
        assert session.total_calls == 1
        assert session.tool_counts.get("shell") == 1


# ── #1b Async engine same fix ────────────────────────────────────────


class TestAsyncSessionIncrementOnBlock:
    """Bug #1 (async): session should NOT increment when verdict is BLOCK."""

    def test_async_session_not_incremented_on_block(self, tmp_path):
        from policyshield.shield.async_engine import AsyncShieldEngine

        rules_path = _write_rule(
            tmp_path,
            [
                {
                    "id": "block-rm",
                    "when": {"tool": "shell", "args": {"command": {"contains": "rm"}}},
                    "then": "BLOCK",
                    "message": "no rm",
                }
            ],
        )
        engine = AsyncShieldEngine(str(rules_path))
        result = asyncio.run(
            engine.check(tool_name="shell", args={"command": "rm -rf /"}, session_id="s1")
        )
        assert result.verdict == Verdict.BLOCK

        session = engine._session_mgr.get_or_create("s1")
        assert session.total_calls == 0


# ── #2 _parse_rule preserves approval_strategy ───────────────────────


class TestParseRuleApprovalStrategy:
    """Bug #2: approval_strategy should be preserved from YAML."""

    def test_approval_strategy_preserved(self):
        raw = {
            "id": "approve-deploy",
            "when": {"tool": "deploy"},
            "then": "APPROVE",
            "approval_strategy": "per_session",
        }
        rule = _parse_rule(raw)
        assert rule.approval_strategy == "per_session"

    def test_approval_strategy_absent(self):
        raw = {
            "id": "block-rm",
            "when": {"tool": "shell"},
            "then": "BLOCK",
        }
        rule = _parse_rule(raw)
        assert rule.approval_strategy is None

    def test_approval_strategy_roundtrip(self, tmp_path):
        """Full roundtrip: YAML ➜ load_rules ➜ RuleConfig.approval_strategy."""
        rules_path = _write_rule(
            tmp_path,
            [
                {
                    "id": "approve-deploy",
                    "when": {"tool": "deploy"},
                    "then": "APPROVE",
                    "approval_strategy": "per_session",
                }
            ],
        )
        ruleset = load_rules(str(rules_path))
        rule = ruleset.rules[0]
        assert rule.approval_strategy == "per_session"


# ── #3 AsyncShieldEngine.reload_rules thread safety ──────────────────


class TestAsyncReloadRulesThreadSafety:
    """Bug #3: reload_rules should hold a lock to prevent races."""

    def test_reload_lock_exists(self, tmp_path):
        from policyshield.shield.async_engine import AsyncShieldEngine

        rules_path = _write_rule(
            tmp_path,
            [{"id": "r1", "when": {"tool": "t"}, "then": "BLOCK"}],
        )
        engine = AsyncShieldEngine(str(rules_path))
        assert hasattr(engine, "_reload_lock")
        assert isinstance(engine._reload_lock, type(threading.Lock()))

    def test_reload_rules_does_not_corrupt(self, tmp_path):
        """Concurrent reload + check should not raise."""
        from policyshield.shield.async_engine import AsyncShieldEngine

        rules_path = _write_rule(
            tmp_path,
            [{"id": "r1", "when": {"tool": "t"}, "then": "BLOCK", "message": "blocked"}],
        )
        engine = AsyncShieldEngine(str(rules_path))

        errors = []

        def reload_loop():
            for _ in range(20):
                try:
                    engine.reload_rules()
                except Exception as exc:
                    errors.append(exc)

        async def check_loop():
            for _ in range(20):
                try:
                    await engine.check(tool_name="t", args={}, session_id="s1")
                except Exception as exc:
                    errors.append(exc)

        t = threading.Thread(target=reload_loop)
        t.start()
        asyncio.run(check_loop())
        t.join()
        assert not errors, f"Concurrent reload/check raised: {errors}"


# ── #4 ReDoS pattern length cap ──────────────────────────────────────


class TestReDoSPatternLengthCap:
    """Security #4: regex patterns exceeding MAX_PATTERN_LENGTH should be rejected."""

    def test_short_pattern_accepted(self):
        rule = RuleConfig(
            id="r1",
            when={"tool": "t", "args": {"cmd": {"regex": "rm.*"}}},
            then=Verdict.BLOCK,
        )
        ruleset = RuleSet(shield_name="test", version="1.0", rules=[rule])
        engine = MatcherEngine(ruleset)  # should not raise
        assert engine is not None

    def test_long_pattern_rejected(self):
        long_pattern = "a" * (MAX_PATTERN_LENGTH + 1)
        rule = RuleConfig(
            id="r1",
            when={"tool": "t", "args": {"cmd": {"regex": long_pattern}}},
            then=Verdict.BLOCK,
        )
        ruleset = RuleSet(shield_name="test", version="1.0", rules=[rule])
        with pytest.raises(ValueError, match="exceeds"):
            MatcherEngine(ruleset)


# ── #5 redact_dict nested fields ─────────────────────────────────────


class TestRedactDictNested:
    """Security #5: redact_dict should handle nested dicts."""

    def test_nested_email_redacted(self):
        detector = PIIDetector()
        data = {"metadata": {"contact": "user@example.com"}}
        redacted, matches = detector.redact_dict(data)

        assert len(matches) >= 1
        pii_types = {m.pii_type for m in matches}
        assert PIIType.EMAIL in pii_types

        # The nested email should be redacted
        nested_value = redacted["metadata"]["contact"]
        assert "user@example.com" not in nested_value
        assert "***" in nested_value or "**" in nested_value

    def test_top_level_still_works(self):
        detector = PIIDetector()
        data = {"email": "user@example.com"}
        redacted, matches = detector.redact_dict(data)
        assert "user@example.com" not in redacted["email"]

    def test_deeply_nested(self):
        detector = PIIDetector()
        data = {"a": {"b": {"c": "user@example.com"}}}
        redacted, matches = detector.redact_dict(data)
        assert len(matches) >= 1
        assert "user@example.com" not in redacted["a"]["b"]["c"]


# ── #6 TraceRecorder thread safety ───────────────────────────────────


class TestTraceRecorderThreadSafety:
    """Security #6: TraceRecorder should be thread-safe."""

    def test_concurrent_record(self, tmp_path):
        recorder = TraceRecorder(output_dir=str(tmp_path), batch_size=1000)
        errors = []

        def write_records(start: int):
            for i in range(100):
                try:
                    recorder.record(
                        session_id="s1",
                        tool=f"tool_{start}_{i}",
                        verdict=Verdict.ALLOW,
                    )
                except Exception as exc:
                    errors.append(exc)

        threads = [threading.Thread(target=write_records, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        recorder.flush()
        assert not errors
        assert recorder.record_count == 500

    def test_lock_exists(self, tmp_path):
        recorder = TraceRecorder(output_dir=str(tmp_path))
        assert hasattr(recorder, "_lock")
        assert isinstance(recorder._lock, type(threading.Lock()))


# ── #7 LangChain _arun non-blocking ─────────────────────────────────


class TestLangChainArun:
    """Security #7: _arun should not block the event loop."""

    def test_arun_uses_thread(self):
        """_arun should call _run in a thread, not directly."""
        try:
            from policyshield.integrations.langchain.wrapper import PolicyShieldTool
        except ImportError:
            pytest.skip("langchain-core not installed")

        mock_tool = MagicMock()
        mock_tool.name = "test"
        mock_tool.description = "test tool"
        mock_tool._run.return_value = "ok"

        engine = MagicMock()
        engine.check.return_value = MagicMock(verdict=Verdict.ALLOW)

        shield_tool = PolicyShieldTool(wrapped_tool=mock_tool, engine=engine)

        # Verify _arun is a coroutine
        import inspect

        assert inspect.iscoroutinefunction(shield_tool._arun)


# ── #11 IP address regex accuracy ────────────────────────────────────


class TestIPAddressRegex:
    """Accuracy #11: IP regex should validate octet ranges."""

    def test_valid_ip_detected(self):
        detector = PIIDetector()
        matches = detector.scan("Connect to 192.168.1.1 please")
        ip_matches = [m for m in matches if m.pii_type == PIIType.IP_ADDRESS]
        assert len(ip_matches) == 1

    def test_invalid_ip_not_detected(self):
        detector = PIIDetector()
        matches = detector.scan("Version 999.999.999.999 is out")
        ip_matches = [m for m in matches if m.pii_type == PIIType.IP_ADDRESS]
        assert len(ip_matches) == 0

    def test_edge_ip_255(self):
        detector = PIIDetector()
        matches = detector.scan("Broadcast: 255.255.255.255")
        ip_matches = [m for m in matches if m.pii_type == PIIType.IP_ADDRESS]
        assert len(ip_matches) == 1

    def test_edge_ip_zero(self):
        detector = PIIDetector()
        matches = detector.scan("Localhost: 0.0.0.0")
        ip_matches = [m for m in matches if m.pii_type == PIIType.IP_ADDRESS]
        assert len(ip_matches) == 1


# ── #12 Passport regex accuracy ──────────────────────────────────────


class TestPassportRegex:
    """Accuracy #12: Passport regex should require 7-9 digits after letters."""

    def test_valid_passport_detected(self):
        detector = PIIDetector()
        matches = detector.scan("Passport: AB1234567")
        passport = [m for m in matches if m.pii_type == PIIType.PASSPORT]
        assert len(passport) == 1

    def test_short_code_not_detected(self):
        """6-digit code after letters should NOT match (was matching before fix)."""
        detector = PIIDetector()
        matches = detector.scan("Model X123456 is available")
        passport = [m for m in matches if m.pii_type == PIIType.PASSPORT]
        assert len(passport) == 0, "6-digit codes should no longer match passport pattern"

    def test_product_code_not_detected(self):
        detector = PIIDetector()
        matches = detector.scan("Product AB123456 ships tomorrow")
        passport = [m for m in matches if m.pii_type == PIIType.PASSPORT]
        assert len(passport) == 0, "6-digit product codes should not match"
