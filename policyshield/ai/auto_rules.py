"""Automatic rule generation from tool classification.

Generates PolicyShield YAML rules based on tool name classification.
No LLM required — uses pattern-based classification from templates.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from policyshield.ai.templates import DangerLevel, classify_tool


# Mapping from DangerLevel → verdict + severity
_VERDICT_MAP: dict[DangerLevel, tuple[str, str]] = {
    DangerLevel.CRITICAL: ("block", "critical"),
    DangerLevel.DANGEROUS: ("approve", "high"),
    DangerLevel.MODERATE: ("allow", "low"),
    DangerLevel.SAFE: ("allow", "low"),
}

_MESSAGE_MAP: dict[DangerLevel, str] = {
    DangerLevel.CRITICAL: "Blocked: critical operation requires policy review",
    DangerLevel.DANGEROUS: "Requires human approval before execution",
    DangerLevel.MODERATE: "Allowed (moderate risk — logged)",
    DangerLevel.SAFE: "Allowed (safe operation)",
}


@dataclass
class GeneratedRule:
    """A rule generated from tool classification."""

    rule_id: str
    tool_name: str
    verdict: str
    severity: str
    danger_level: DangerLevel
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to YAML-serializable dict."""
        d: dict[str, Any] = {
            "id": self.rule_id,
            "description": f"Auto-generated rule for {self.tool_name} ({self.danger_level.value})",
            "when": {"tool": self.tool_name},
            "then": self.verdict,
        }
        if self.severity and self.verdict != "allow":
            d["severity"] = self.severity
        if self.message and self.verdict != "allow":
            d["message"] = self.message
        return d


def generate_rules(
    tool_names: list[str],
    include_safe: bool = False,
    default_verdict: str = "block",
) -> list[GeneratedRule]:
    """Generate rules from a list of tool names.

    Args:
        tool_names: Tool names to classify and generate rules for.
        include_safe: If True, includes ALLOW rules for safe tools.
        default_verdict: The default verdict in the ruleset.

    Returns:
        List of GeneratedRule objects.
    """
    rules = []
    for name in sorted(set(tool_names)):
        level = classify_tool(name)
        verdict, severity = _VERDICT_MAP[level]
        message = _MESSAGE_MAP[level]

        # Skip SAFE/MODERATE allow rules if default is already allow
        if not include_safe and level in (DangerLevel.SAFE, DangerLevel.MODERATE):
            continue

        rules.append(GeneratedRule(
            rule_id=f"auto-{name.replace('_', '-')}",
            tool_name=name,
            verdict=verdict,
            severity=severity,
            danger_level=level,
            message=message,
        ))

    return rules


def rules_to_yaml_dict(
    rules: list[GeneratedRule],
    shield_name: str = "auto-generated-policy",
    default_verdict: str = "block",
) -> dict[str, Any]:
    """Convert generated rules to a full YAML-ready dict.

    Args:
        rules: List of GeneratedRule objects.
        shield_name: Name for the policy.
        default_verdict: Default verdict for unmatched tools.

    Returns:
        Dict ready for yaml.dump().
    """
    return {
        "shield_name": shield_name,
        "version": 1,
        "default_verdict": default_verdict,
        "rules": [r.to_dict() for r in rules],
    }


def rules_to_yaml(
    rules: list[GeneratedRule],
    shield_name: str = "auto-generated-policy",
    default_verdict: str = "block",
) -> str:
    """Convert generated rules to YAML string.

    Args:
        rules: List of GeneratedRule objects.
        shield_name: Name for the policy.
        default_verdict: Default verdict for unmatched tools.

    Returns:
        YAML string.
    """
    import yaml

    data = rules_to_yaml_dict(rules, shield_name, default_verdict)
    return (
        "# Auto-generated PolicyShield rules\n"
        "# Review and adjust as needed before use\n"
        + yaml.dump(data, default_flow_style=False, sort_keys=False)
    )
