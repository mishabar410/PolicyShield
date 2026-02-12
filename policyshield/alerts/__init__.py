"""Alert rules engine — evaluates conditions against trace data and fires alerts."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class AlertSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AlertConditionType(str, Enum):
    BLOCK_RATE_ABOVE = "block_rate_above"
    BLOCK_COUNT_ABOVE = "block_count_above"
    PII_DETECTED = "pii_detected"
    TOOL_BLOCKED = "tool_blocked"
    ERROR_RATE_ABOVE = "error_rate_above"


@dataclass
class AlertRule:
    """An alert rule definition."""

    id: str
    name: str
    condition_type: AlertConditionType
    threshold: float | None = None  # for rate/count conditions
    tool: str | None = None  # for tool_blocked
    pii_type: str | None = None  # for pii_detected
    severity: AlertSeverity = AlertSeverity.WARNING
    enabled: bool = True
    cooldown_seconds: int = 300  # min time between repeat alerts


@dataclass
class Alert:
    """A fired alert."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    rule_id: str = ""
    rule_name: str = ""
    severity: AlertSeverity = AlertSeverity.WARNING
    message: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    context: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context,
        }


class AlertEngine:
    """Evaluates alert rules against aggregation data."""

    def __init__(self, rules: list[AlertRule] | None = None) -> None:
        self._rules = rules or []
        self._last_fired: dict[str, datetime] = {}

    @property
    def rules(self) -> list[AlertRule]:
        return list(self._rules)

    def add_rule(self, rule: AlertRule) -> None:
        self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.id != rule_id]
        return len(self._rules) < before

    def evaluate(self, aggregation) -> list[Alert]:
        """Evaluate all enabled rules against an AggregationResult."""
        alerts: list[Alert] = []
        now = datetime.now()

        for rule in self._rules:
            if not rule.enabled:
                continue

            # Cooldown check
            last = self._last_fired.get(rule.id)
            if last and (now - last).total_seconds() < rule.cooldown_seconds:
                continue

            alert = self._check_rule(rule, aggregation)
            if alert:
                self._last_fired[rule.id] = now
                alerts.append(alert)

        return alerts

    def evaluate_from_traces(self, trace_dir: str | Path, **filters) -> list[Alert]:
        """Convenience: aggregate + evaluate."""
        from policyshield.trace.aggregator import TraceAggregator

        aggregator = TraceAggregator(trace_dir)
        result = aggregator.aggregate(**filters)
        return self.evaluate(result)

    def _check_rule(self, rule: AlertRule, aggregation) -> Alert | None:
        vb = aggregation.verdict_breakdown
        top_tools = aggregation.top_tools

        if rule.condition_type == AlertConditionType.BLOCK_RATE_ABOVE:
            if vb.total == 0:
                return None
            block_rate = vb.block / vb.total
            if block_rate > (rule.threshold or 0):
                return Alert(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Block rate {block_rate:.1%} exceeds threshold {rule.threshold:.1%}",
                    context={"block_rate": block_rate, "total": vb.total},
                )

        elif rule.condition_type == AlertConditionType.BLOCK_COUNT_ABOVE:
            if vb.block > (rule.threshold or 0):
                return Alert(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Block count {vb.block} exceeds threshold {int(rule.threshold or 0)}",
                    context={"block_count": vb.block},
                )

        elif rule.condition_type == AlertConditionType.PII_DETECTED:
            pii_heatmap = aggregation.pii_heatmap
            for entry in pii_heatmap:
                if rule.pii_type is None or entry.pii_type == rule.pii_type:
                    return Alert(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=f"PII type '{entry.pii_type}' detected in tool '{entry.tool}' ({entry.count} occurrences)",
                        context={"pii_type": entry.pii_type, "tool": entry.tool, "count": entry.count},
                    )

        elif rule.condition_type == AlertConditionType.TOOL_BLOCKED:
            for ts in top_tools:
                if rule.tool and ts.tool == rule.tool and ts.block_count > 0:
                    return Alert(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=f"Tool '{ts.tool}' was blocked {ts.block_count} time(s)",
                        context={"tool": ts.tool, "block_count": ts.block_count},
                    )

        elif rule.condition_type == AlertConditionType.ERROR_RATE_ABOVE:
            # Not implemented yet — placeholder for future
            pass

        return None

    @staticmethod
    def from_config(config: dict) -> "AlertEngine":
        """Create AlertEngine from configuration dict."""
        rules = []
        for rule_cfg in config.get("rules", []):
            rules.append(
                AlertRule(
                    id=rule_cfg["id"],
                    name=rule_cfg["name"],
                    condition_type=AlertConditionType(rule_cfg["condition_type"]),
                    threshold=rule_cfg.get("threshold"),
                    tool=rule_cfg.get("tool"),
                    pii_type=rule_cfg.get("pii_type"),
                    severity=AlertSeverity(rule_cfg.get("severity", "WARNING")),
                    enabled=rule_cfg.get("enabled", True),
                    cooldown_seconds=rule_cfg.get("cooldown_seconds", 300),
                )
            )
        return AlertEngine(rules=rules)
