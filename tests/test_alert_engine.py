"""Tests for alert engine."""

import json

from policyshield.alerts import (
    Alert,
    AlertConditionType,
    AlertEngine,
    AlertRule,
    AlertSeverity,
)
from policyshield.trace.aggregator import (
    AggregationResult,
    PIIHeatmapEntry,
    ToolStats,
    VerdictBreakdown,
)


def _make_aggregation(
    allow=8,
    block=2,
    redact=0,
    approve=0,
    tools=None,
    pii=None,
):
    total = allow + block + redact + approve
    return AggregationResult(
        verdict_breakdown=VerdictBreakdown(allow=allow, block=block, redact=redact, approve=approve, total=total),
        top_tools=tools
        or [
            ToolStats(tool="exec", call_count=5, block_count=2, block_rate=0.4),
            ToolStats(tool="read_file", call_count=5, block_count=0, block_rate=0.0),
        ],
        pii_heatmap=pii or [],
    )


class TestBlockRateAbove:
    def test_fires_when_rate_exceeded(self):
        engine = AlertEngine(
            rules=[
                AlertRule(
                    id="r1",
                    name="High block rate",
                    condition_type=AlertConditionType.BLOCK_RATE_ABOVE,
                    threshold=0.1,
                    severity=AlertSeverity.CRITICAL,
                ),
            ]
        )
        agg = _make_aggregation(allow=7, block=3)
        alerts = engine.evaluate(agg)
        assert len(alerts) == 1
        assert alerts[0].rule_id == "r1"
        assert "30.0%" in alerts[0].message

    def test_no_fire_below_threshold(self):
        engine = AlertEngine(
            rules=[
                AlertRule(
                    id="r1", name="High block rate", condition_type=AlertConditionType.BLOCK_RATE_ABOVE, threshold=0.5
                ),
            ]
        )
        agg = _make_aggregation(allow=9, block=1)
        assert engine.evaluate(agg) == []


class TestBlockCountAbove:
    def test_fires_when_count_exceeded(self):
        engine = AlertEngine(
            rules=[
                AlertRule(
                    id="r2", name="Too many blocks", condition_type=AlertConditionType.BLOCK_COUNT_ABOVE, threshold=5
                ),
            ]
        )
        agg = _make_aggregation(allow=4, block=6)
        alerts = engine.evaluate(agg)
        assert len(alerts) == 1

    def test_no_fire_below_threshold(self):
        engine = AlertEngine(
            rules=[
                AlertRule(
                    id="r2", name="Too many blocks", condition_type=AlertConditionType.BLOCK_COUNT_ABOVE, threshold=10
                ),
            ]
        )
        agg = _make_aggregation(allow=8, block=2)
        assert engine.evaluate(agg) == []


class TestPIIDetected:
    def test_fires_on_pii(self):
        engine = AlertEngine(
            rules=[
                AlertRule(id="r3", name="PII detected", condition_type=AlertConditionType.PII_DETECTED),
            ]
        )
        agg = _make_aggregation(pii=[PIIHeatmapEntry(pii_type="EMAIL", tool="send", count=3)])
        alerts = engine.evaluate(agg)
        assert len(alerts) == 1
        assert "EMAIL" in alerts[0].message

    def test_fires_on_specific_pii_type(self):
        engine = AlertEngine(
            rules=[
                AlertRule(id="r3", name="SSN detected", condition_type=AlertConditionType.PII_DETECTED, pii_type="SSN"),
            ]
        )
        agg = _make_aggregation(
            pii=[
                PIIHeatmapEntry(pii_type="EMAIL", tool="send", count=3),
                PIIHeatmapEntry(pii_type="SSN", tool="write", count=1),
            ]
        )
        alerts = engine.evaluate(agg)
        assert len(alerts) == 1
        assert "SSN" in alerts[0].message

    def test_no_fire_without_pii(self):
        engine = AlertEngine(
            rules=[
                AlertRule(id="r3", name="PII detected", condition_type=AlertConditionType.PII_DETECTED),
            ]
        )
        agg = _make_aggregation()
        assert engine.evaluate(agg) == []


class TestToolBlocked:
    def test_fires_on_tool_blocked(self):
        engine = AlertEngine(
            rules=[
                AlertRule(id="r4", name="Exec blocked", condition_type=AlertConditionType.TOOL_BLOCKED, tool="exec"),
            ]
        )
        agg = _make_aggregation()
        alerts = engine.evaluate(agg)
        assert len(alerts) == 1
        assert "exec" in alerts[0].message

    def test_no_fire_unblocked_tool(self):
        engine = AlertEngine(
            rules=[
                AlertRule(
                    id="r4", name="Read blocked", condition_type=AlertConditionType.TOOL_BLOCKED, tool="read_file"
                ),
            ]
        )
        agg = _make_aggregation()
        assert engine.evaluate(agg) == []


class TestDisabledRule:
    def test_disabled_rule_skipped(self):
        engine = AlertEngine(
            rules=[
                AlertRule(
                    id="r1",
                    name="Disabled",
                    condition_type=AlertConditionType.BLOCK_COUNT_ABOVE,
                    threshold=0,
                    enabled=False,
                ),
            ]
        )
        agg = _make_aggregation(block=5)
        assert engine.evaluate(agg) == []


class TestCooldown:
    def test_cooldown_prevents_repeat(self):
        engine = AlertEngine(
            rules=[
                AlertRule(
                    id="r1",
                    name="Rate",
                    condition_type=AlertConditionType.BLOCK_RATE_ABOVE,
                    threshold=0.1,
                    cooldown_seconds=60,
                ),
            ]
        )
        agg = _make_aggregation(allow=7, block=3)
        alerts1 = engine.evaluate(agg)
        assert len(alerts1) == 1
        # Second evaluation should be suppressed by cooldown
        alerts2 = engine.evaluate(agg)
        assert len(alerts2) == 0


class TestRuleManagement:
    def test_add_rule(self):
        engine = AlertEngine()
        engine.add_rule(AlertRule(id="r1", name="Test", condition_type=AlertConditionType.BLOCK_COUNT_ABOVE))
        assert len(engine.rules) == 1

    def test_remove_rule(self):
        engine = AlertEngine(
            rules=[
                AlertRule(id="r1", name="Test", condition_type=AlertConditionType.BLOCK_COUNT_ABOVE),
            ]
        )
        assert engine.remove_rule("r1") is True
        assert len(engine.rules) == 0

    def test_remove_nonexistent(self):
        engine = AlertEngine()
        assert engine.remove_rule("nope") is False


class TestFromConfig:
    def test_load_from_config(self):
        config = {
            "rules": [
                {
                    "id": "r1",
                    "name": "High blocks",
                    "condition_type": "block_rate_above",
                    "threshold": 0.2,
                    "severity": "CRITICAL",
                },
                {"id": "r2", "name": "PII", "condition_type": "pii_detected"},
            ]
        }
        engine = AlertEngine.from_config(config)
        assert len(engine.rules) == 2
        assert engine.rules[0].severity == AlertSeverity.CRITICAL


class TestAlertSerialization:
    def test_alert_to_dict(self):
        a = Alert(id="a1", rule_id="r1", rule_name="Test", severity=AlertSeverity.CRITICAL, message="msg")
        d = a.to_dict()
        assert d["id"] == "a1"
        assert d["severity"] == "CRITICAL"


class TestMultipleRules:
    def test_multiple_alerts(self):
        engine = AlertEngine(
            rules=[
                AlertRule(
                    id="r1", name="Block rate", condition_type=AlertConditionType.BLOCK_RATE_ABOVE, threshold=0.1
                ),
                AlertRule(
                    id="r2", name="Block count", condition_type=AlertConditionType.BLOCK_COUNT_ABOVE, threshold=1
                ),
            ]
        )
        agg = _make_aggregation(allow=7, block=3)
        alerts = engine.evaluate(agg)
        assert len(alerts) == 2


class TestEvaluateFromTraces:
    def test_evaluate_from_traces(self, tmp_path):
        d = tmp_path / "traces"
        d.mkdir()
        records = [
            {"timestamp": "2025-01-01T12:00:00", "tool": "exec", "verdict": "BLOCK", "session_id": "s1"},
            {"timestamp": "2025-01-01T12:01:00", "tool": "exec", "verdict": "ALLOW", "session_id": "s1"},
        ]
        with open(d / "trace.jsonl", "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

        engine = AlertEngine(
            rules=[
                AlertRule(id="r1", name="Any block", condition_type=AlertConditionType.BLOCK_COUNT_ABOVE, threshold=0),
            ]
        )
        alerts = engine.evaluate_from_traces(d)
        assert len(alerts) == 1
