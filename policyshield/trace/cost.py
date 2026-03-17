"""Cost estimator for trace tool calls — token + dollar estimates."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ModelPricing:
    """Pricing per model."""

    name: str
    input_per_1k: float  # $ per 1K input tokens
    output_per_1k: float  # $ per 1K output tokens


@dataclass
class ToolCostProfile:
    """Average token usage per tool call."""

    tool: str
    avg_input_tokens: int  # estimated input tokens
    avg_output_tokens: int  # estimated output tokens


@dataclass
class CostEstimate:
    """Full cost estimate result."""

    total_calls: int
    allowed_calls: int
    blocked_calls: int
    estimated_cost_allowed: float
    estimated_cost_blocked: float
    estimated_cost_total: float
    cost_by_tool: dict[str, float] = field(default_factory=dict)
    model: str = "gpt-4o"
    currency: str = "USD"

    def to_dict(self) -> dict:
        return {
            "total_calls": self.total_calls,
            "allowed_calls": self.allowed_calls,
            "blocked_calls": self.blocked_calls,
            "estimated_cost_allowed": round(self.estimated_cost_allowed, 4),
            "estimated_cost_blocked": round(self.estimated_cost_blocked, 4),
            "estimated_cost_total": round(self.estimated_cost_total, 4),
            "cost_by_tool": {k: round(v, 4) for k, v in self.cost_by_tool.items()},
            "model": self.model,
            "currency": self.currency,
        }


BUILTIN_PRICING: dict[str, ModelPricing] = {
    "gpt-4o": ModelPricing("gpt-4o", 0.0025, 0.010),
    "gpt-4o-mini": ModelPricing("gpt-4o-mini", 0.00015, 0.0006),
    "claude-3.5-sonnet": ModelPricing("claude-3.5-sonnet", 0.003, 0.015),
    "claude-3-haiku": ModelPricing("claude-3-haiku", 0.00025, 0.00125),
}

DEFAULT_TOOL_PROFILE = ToolCostProfile("_default", avg_input_tokens=200, avg_output_tokens=500)


class CostEstimator:
    """Estimates dollar cost of tool calls based on model pricing and token profiles."""

    def __init__(
        self,
        model: str = "gpt-4o",
        pricing: dict[str, ModelPricing] | None = None,
        tool_profiles: dict[str, ToolCostProfile] | None = None,
    ) -> None:
        self._model = model
        self._pricing = pricing or BUILTIN_PRICING
        self._tool_profiles = tool_profiles or {}

    def _get_pricing(self) -> ModelPricing:
        if self._model in self._pricing:
            return self._pricing[self._model]
        raise ValueError(f"No pricing for model '{self._model}'. Available: {list(self._pricing.keys())}")

    def _get_tool_profile(self, tool: str) -> ToolCostProfile:
        return self._tool_profiles.get(tool, DEFAULT_TOOL_PROFILE)

    def _cost_per_call(self, tool: str) -> float:
        """Cost for a single tool call."""
        pricing = self._get_pricing()
        profile = self._get_tool_profile(tool)
        input_cost = (profile.avg_input_tokens / 1000) * pricing.input_per_1k
        output_cost = (profile.avg_output_tokens / 1000) * pricing.output_per_1k
        return input_cost + output_cost

    def estimate(self, aggregation) -> CostEstimate:
        """Estimate costs from an AggregationResult."""
        vb = aggregation.verdict_breakdown
        top_tools = aggregation.top_tools

        allowed_cost = 0.0
        blocked_cost = 0.0
        cost_by_tool: dict[str, float] = {}

        for ts in top_tools:
            per_call = self._cost_per_call(ts.tool)
            allowed_count = ts.call_count - ts.block_count
            tool_allowed_cost = allowed_count * per_call
            tool_blocked_cost = ts.block_count * per_call
            allowed_cost += tool_allowed_cost
            blocked_cost += tool_blocked_cost
            cost_by_tool[ts.tool] = round(tool_allowed_cost, 6)

        return CostEstimate(
            total_calls=vb.total,
            allowed_calls=vb.total - vb.block,
            blocked_calls=vb.block,
            estimated_cost_allowed=allowed_cost,
            estimated_cost_blocked=blocked_cost,
            estimated_cost_total=allowed_cost + blocked_cost,
            cost_by_tool=cost_by_tool,
            model=self._model,
            currency="USD",
        )

    def estimate_from_traces(self, trace_dir: str | Path, **filters) -> CostEstimate:
        """Convenience: aggregate + estimate cost."""
        from policyshield.trace.aggregator import TraceAggregator

        aggregator = TraceAggregator(trace_dir)
        result = aggregator.aggregate(**filters)
        return self.estimate(result)

    @staticmethod
    def load_pricing_from_yaml(path: str | Path) -> dict[str, ModelPricing]:
        """Load custom pricing from YAML file."""
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f)

        pricing: dict[str, ModelPricing] = {}
        for name, vals in data.items():
            pricing[name] = ModelPricing(
                name=name,
                input_per_1k=float(vals["input_per_1k"]),
                output_per_1k=float(vals["output_per_1k"]),
            )
        return pricing


def format_cost_estimate(est: CostEstimate) -> str:
    """Format cost estimate for CLI display."""
    lines: list[str] = []
    lines.append(f"Cost Estimate (model: {est.model})")
    lines.append(f"  Allowed calls:  {est.allowed_calls:>6,d}  →  ${est.estimated_cost_allowed:.2f}")
    lines.append(f"  Blocked calls:  {est.blocked_calls:>6,d}  →  ${est.estimated_cost_blocked:.2f} saved")
    lines.append(f"  Total (without shield):  ${est.estimated_cost_total:.2f}")
    lines.append("")

    if est.cost_by_tool:
        lines.append("  Per-tool:")
        for tool, cost in sorted(est.cost_by_tool.items(), key=lambda x: -x[1]):
            lines.append(f"    {tool:<16} ${cost:.2f}")

    return "\n".join(lines)
