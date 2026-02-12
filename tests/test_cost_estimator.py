"""Tests for cost estimator."""

import json

import pytest
import yaml

from policyshield.trace.aggregator import (
    ToolStats,
    VerdictBreakdown,
)
from policyshield.trace.cost import (
    BUILTIN_PRICING,
    DEFAULT_TOOL_PROFILE,
    CostEstimate,
    CostEstimator,
    ModelPricing,
    ToolCostProfile,
    format_cost_estimate,
)

# Reuse helpers from aggregation tests
from datetime import datetime, timedelta


def _make_record(tool="exec", verdict="ALLOW", session_id="s1", timestamp=None, **kw):
    rec = {
        "timestamp": timestamp or datetime.now().isoformat(),
        "tool": tool,
        "verdict": verdict,
        "session_id": session_id,
    }
    rec.update(kw)
    return rec


def _write_jsonl(path, records):
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


@pytest.fixture
def trace_dir(tmp_path):
    d = tmp_path / "traces"
    d.mkdir()
    return d


@pytest.fixture
def sample_records():
    base = datetime(2025, 1, 1, 12, 0, 0)
    return [
        _make_record(tool="exec", verdict="BLOCK", timestamp=(base + timedelta(minutes=0)).isoformat()),
        _make_record(tool="exec", verdict="ALLOW", timestamp=(base + timedelta(minutes=1)).isoformat()),
        _make_record(tool="web_fetch", verdict="ALLOW", timestamp=(base + timedelta(minutes=2)).isoformat()),
        _make_record(tool="web_fetch", verdict="BLOCK", timestamp=(base + timedelta(minutes=3)).isoformat()),
        _make_record(tool="read_file", verdict="ALLOW", timestamp=(base + timedelta(minutes=4)).isoformat()),
        _make_record(tool="read_file", verdict="ALLOW", timestamp=(base + timedelta(minutes=5)).isoformat()),
    ]


@pytest.fixture
def populated_trace_dir(trace_dir, sample_records):
    _write_jsonl(trace_dir / "trace.jsonl", sample_records)
    return trace_dir


def _make_aggregation():
    """Create a mock aggregation result for testing."""
    from policyshield.trace.aggregator import AggregationResult

    return AggregationResult(
        verdict_breakdown=VerdictBreakdown(allow=4, block=2, redact=0, approve=0, total=6),
        top_tools=[
            ToolStats(tool="exec", call_count=2, block_count=1, block_rate=0.5),
            ToolStats(tool="web_fetch", call_count=2, block_count=1, block_rate=0.5),
            ToolStats(tool="read_file", call_count=2, block_count=0, block_rate=0.0),
        ],
    )


class TestEstimateBasic:
    def test_estimate_basic(self):
        estimator = CostEstimator(model="gpt-4o")
        agg = _make_aggregation()
        est = estimator.estimate(agg)
        assert est.total_calls == 6
        assert est.allowed_calls == 4
        assert est.blocked_calls == 2
        assert est.estimated_cost_total > 0
        assert est.estimated_cost_allowed > 0


class TestBlockedSavings:
    def test_blocked_savings(self):
        estimator = CostEstimator(model="gpt-4o")
        agg = _make_aggregation()
        est = estimator.estimate(agg)
        assert est.estimated_cost_blocked > 0
        # blocked savings should be positive and less than or equal to total
        assert est.estimated_cost_blocked <= est.estimated_cost_total


class TestCustomModelPricing:
    def test_custom_model(self):
        custom_pricing = {
            "my-model": ModelPricing("my-model", input_per_1k=0.01, output_per_1k=0.02),
        }
        estimator = CostEstimator(model="my-model", pricing=custom_pricing)
        agg = _make_aggregation()
        est = estimator.estimate(agg)
        assert est.model == "my-model"
        assert est.estimated_cost_total > 0


class TestCustomToolProfiles:
    def test_custom_profiles(self):
        profiles = {
            "web_fetch": ToolCostProfile("web_fetch", avg_input_tokens=500, avg_output_tokens=2000),
            "exec": ToolCostProfile("exec", avg_input_tokens=100, avg_output_tokens=300),
        }
        estimator = CostEstimator(model="gpt-4o", tool_profiles=profiles)
        agg = _make_aggregation()
        est = estimator.estimate(agg)
        # web_fetch should cost more per call than exec
        web_cost = est.cost_by_tool.get("web_fetch", 0)
        exec_cost = est.cost_by_tool.get("exec", 0)
        # web_fetch has more tokens → higher per-call cost, same call count
        assert web_cost > exec_cost


class TestDefaultToolProfile:
    def test_default_profile(self):
        estimator = CostEstimator(model="gpt-4o")
        profile = estimator._get_tool_profile("unknown_tool")
        assert profile.avg_input_tokens == DEFAULT_TOOL_PROFILE.avg_input_tokens
        assert profile.avg_output_tokens == DEFAULT_TOOL_PROFILE.avg_output_tokens


class TestLoadPricingYaml:
    def test_load_pricing(self, tmp_path):
        pricing_yaml = tmp_path / "pricing.yaml"
        pricing_yaml.write_text(
            yaml.dump(
                {
                    "custom-model": {"input_per_1k": 0.005, "output_per_1k": 0.02},
                    "cheap-model": {"input_per_1k": 0.0001, "output_per_1k": 0.0005},
                }
            )
        )
        pricing = CostEstimator.load_pricing_from_yaml(pricing_yaml)
        assert "custom-model" in pricing
        assert "cheap-model" in pricing
        assert pricing["custom-model"].input_per_1k == 0.005


class TestCostByTool:
    def test_cost_by_tool_breakdown(self):
        estimator = CostEstimator(model="gpt-4o")
        agg = _make_aggregation()
        est = estimator.estimate(agg)
        assert "exec" in est.cost_by_tool
        assert "web_fetch" in est.cost_by_tool
        assert "read_file" in est.cost_by_tool


class TestEmptyTraces:
    def test_empty(self, trace_dir):
        estimator = CostEstimator(model="gpt-4o")
        est = estimator.estimate_from_traces(trace_dir)
        assert est.total_calls == 0
        assert est.estimated_cost_total == 0.0
        assert est.estimated_cost_allowed == 0.0
        assert est.estimated_cost_blocked == 0.0


class TestBuiltinModels:
    def test_builtin_models(self):
        assert "gpt-4o" in BUILTIN_PRICING
        assert "gpt-4o-mini" in BUILTIN_PRICING
        assert "claude-3.5-sonnet" in BUILTIN_PRICING
        assert "claude-3-haiku" in BUILTIN_PRICING


class TestCLICost:
    def test_cli_cost_table(self, populated_trace_dir):
        from policyshield.cli.main import app

        code = app(["trace", "cost", "--dir", str(populated_trace_dir)])
        assert code == 0

    def test_cli_cost_json(self, populated_trace_dir):
        from policyshield.cli.main import app

        code = app(["trace", "cost", "--dir", str(populated_trace_dir), "--format", "json"])
        assert code == 0


class TestFormatCostEstimate:
    def test_format(self):
        est = CostEstimate(
            total_calls=100,
            allowed_calls=80,
            blocked_calls=20,
            estimated_cost_allowed=10.0,
            estimated_cost_blocked=2.5,
            estimated_cost_total=12.5,
            cost_by_tool={"exec": 5.0, "web_fetch": 7.5},
            model="gpt-4o",
        )
        text = format_cost_estimate(est)
        assert "gpt-4o" in text
        assert "$10.00" in text
        assert "$2.50" in text
        assert "Per-tool:" in text


class TestSerialization:
    def test_to_dict(self):
        est = CostEstimate(
            total_calls=10,
            allowed_calls=8,
            blocked_calls=2,
            estimated_cost_allowed=1.0,
            estimated_cost_blocked=0.25,
            estimated_cost_total=1.25,
            cost_by_tool={"exec": 1.0},
            model="gpt-4o",
        )
        d = est.to_dict()
        assert d["model"] == "gpt-4o"
        assert d["currency"] == "USD"
        assert d["total_calls"] == 10
