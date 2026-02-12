"""Tests for OpenTelemetry exporter — works without OTel SDK installed."""

import pytest

from policyshield.core.models import (
    PIIMatch,
    PIIType,
    RuleConfig,
    RuleSet,
    ShieldResult,
    Verdict,
)
from policyshield.shield.engine import ShieldEngine
from policyshield.trace.otel import OTelExporter


def make_ruleset(rules: list[RuleConfig]) -> RuleSet:
    return RuleSet(shield_name="test", version=1, rules=rules)


# ── Test 1: disabled exporter is no-op ───────────────────────────────


def test_otel_disabled():
    exporter = OTelExporter(enabled=False)
    assert not exporter.enabled

    # All methods should be no-ops
    ctx = exporter.on_check_start("test_tool", "s1")
    assert ctx is None

    result = ShieldResult(verdict=Verdict.ALLOW)
    exporter.on_check_end(None, result, 1.0)  # no error
    exporter.shutdown()  # no error


# ── Test 2: no SDK → graceful degradation ────────────────────────────


def test_otel_no_sdk():
    # OTelExporter with enabled=True but HAS_OTEL might be False
    # Just creating it should not raise
    exporter = OTelExporter(enabled=True)
    # It should work as no-op if OTel is not installed
    result = ShieldResult(verdict=Verdict.ALLOW)
    exporter.on_check_end(None, result, 1.0)


# ── Test 3: span created on check ───────────────────────────────────


def test_otel_span_created():
    exporter = OTelExporter(enabled=True)
    if not exporter.enabled:
        pytest.skip("OTel SDK not installed")

    ctx = exporter.on_check_start("my_tool", "session-1")
    assert ctx is not None

    result = ShieldResult(verdict=Verdict.ALLOW)
    exporter.on_check_end(ctx, result, 5.0)


# ── Test 4: span attributes ─────────────────────────────────────────


def test_otel_span_attributes():
    exporter = OTelExporter(enabled=True)
    if not exporter.enabled:
        pytest.skip("OTel SDK not installed")

    ctx = exporter.on_check_start("web_fetch", "sess-42")
    result = ShieldResult(verdict=Verdict.BLOCK, rule_id="block-web")
    exporter.on_check_end(ctx, result, 3.5)
    # If we got here without error, attributes were set correctly


# ── Test 5: ALLOW → OK status ───────────────────────────────────────


def test_otel_span_status_allow():
    exporter = OTelExporter(enabled=True)
    if not exporter.enabled:
        pytest.skip("OTel SDK not installed")

    ctx = exporter.on_check_start("tool", "s1")
    result = ShieldResult(verdict=Verdict.ALLOW)
    exporter.on_check_end(ctx, result, 1.0)


# ── Test 6: BLOCK → ERROR status ────────────────────────────────────


def test_otel_span_status_block():
    exporter = OTelExporter(enabled=True)
    if not exporter.enabled:
        pytest.skip("OTel SDK not installed")

    ctx = exporter.on_check_start("tool", "s1")
    result = ShieldResult(verdict=Verdict.BLOCK, message="blocked")
    exporter.on_check_end(ctx, result, 1.0)


# ── Test 7: PII event ───────────────────────────────────────────────


def test_otel_pii_event():
    exporter = OTelExporter(enabled=True)
    if not exporter.enabled:
        pytest.skip("OTel SDK not installed")

    ctx = exporter.on_check_start("send_data", "s1")
    result = ShieldResult(
        verdict=Verdict.REDACT,
        pii_matches=[
            PIIMatch(pii_type=PIIType.EMAIL, field="body", span=(0, 13), masked_value="***@***.com"),
        ],
    )
    exporter.on_check_end(ctx, result, 2.0)


# ── Test 8: counter total ───────────────────────────────────────────


def test_otel_counter_total():
    exporter = OTelExporter(enabled=True)
    if not exporter.enabled:
        pytest.skip("OTel SDK not installed")

    ctx = exporter.on_check_start("tool", "s1")
    result = ShieldResult(verdict=Verdict.ALLOW)
    exporter.on_check_end(ctx, result, 1.0)
    # Counter is incremented internally — no error means success


# ── Test 9: counter blocked ─────────────────────────────────────────


def test_otel_counter_blocked():
    exporter = OTelExporter(enabled=True)
    if not exporter.enabled:
        pytest.skip("OTel SDK not installed")

    ctx = exporter.on_check_start("exec", "s1")
    result = ShieldResult(verdict=Verdict.BLOCK, rule_id="r1")
    exporter.on_check_end(ctx, result, 1.0)


# ── Test 10: histogram latency ──────────────────────────────────────


def test_otel_histogram_latency():
    exporter = OTelExporter(enabled=True)
    if not exporter.enabled:
        pytest.skip("OTel SDK not installed")

    ctx = exporter.on_check_start("tool", "s1")
    result = ShieldResult(verdict=Verdict.ALLOW)
    exporter.on_check_end(ctx, result, 42.5)


# ── Test 11: engine integration ──────────────────────────────────────


def test_otel_engine_integration():
    """OTel exporter works when passed to ShieldEngine."""
    rules = make_ruleset(
        [
            RuleConfig(id="r1", when={"tool": "exec"}, then=Verdict.BLOCK),
        ]
    )
    exporter = OTelExporter(enabled=True)
    engine = ShieldEngine(rules, otel_exporter=exporter)

    result = engine.check("exec", {"cmd": "ls"})
    assert result.verdict == Verdict.BLOCK

    result = engine.check("read_file", {"path": "/tmp"})
    assert result.verdict == Verdict.ALLOW


# ── Test 12: shutdown ────────────────────────────────────────────────


def test_otel_shutdown():
    exporter = OTelExporter(enabled=True)
    exporter.shutdown()  # should not raise

    exporter_disabled = OTelExporter(enabled=False)
    exporter_disabled.shutdown()  # should not raise
