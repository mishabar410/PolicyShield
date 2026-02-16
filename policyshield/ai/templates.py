"""Rule templates and tool classification for AI-assisted rule generation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class DangerLevel(Enum):
    """Danger level for a tool."""

    SAFE = "safe"
    MODERATE = "moderate"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"


# Tool name patterns → danger levels
# Ordered from most specific to least specific
_TOOL_PATTERNS: list[tuple[str, DangerLevel]] = [
    # Critical: irreversible, system-level
    (r"(delete|remove|drop|destroy|purge|wipe)_", DangerLevel.CRITICAL),
    (r"(exec|shell|system|eval|run_command)", DangerLevel.CRITICAL),
    (r"(deploy|release|publish|push_to_prod)", DangerLevel.CRITICAL),
    (r"(grant|revoke)_(access|permission|role)", DangerLevel.CRITICAL),
    # Dangerous: data exfiltration, write ops
    (r"(send|email|post|upload|transmit|forward)_", DangerLevel.DANGEROUS),
    (r"(write|update|modify|patch|put)_", DangerLevel.DANGEROUS),
    (r"(create|insert|add)_(user|account|token|key)", DangerLevel.DANGEROUS),
    (r"(http|web|api)_(request|fetch|call)", DangerLevel.DANGEROUS),
    # Moderate: read with side effects, config
    (r"(read|get|fetch|query|list|search)_", DangerLevel.MODERATE),
    (r"(config|setting|env|parameter)_", DangerLevel.MODERATE),
    # Safe: pure reads, UI, logging
    (r"(log|print|display|show|render)_", DangerLevel.SAFE),
    (r"(format|parse|validate|check|verify)_", DangerLevel.SAFE),
    (r"(help|info|status|version|health)$", DangerLevel.SAFE),
]

_COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), level) for p, level in _TOOL_PATTERNS]


def classify_tool(tool_name: str) -> DangerLevel:
    """Classify a tool's danger level by its name.

    Args:
        tool_name: The tool name to classify.

    Returns:
        DangerLevel based on pattern matching. MODERATE if no pattern matches.
    """
    for pattern, level in _COMPILED_PATTERNS:
        if pattern.search(tool_name):
            return level
    return DangerLevel.MODERATE  # Unknown → moderate by default


def classify_tools(tool_names: list[str]) -> dict[str, DangerLevel]:
    """Classify multiple tools."""
    return {name: classify_tool(name) for name in tool_names}


# ─── Rule Templates (few-shot examples for LLM) ─────────────────────

RULE_TEMPLATES: dict[str, str] = {
    "block_dangerous": """\
  - id: block-{tool_name}
    when:
      tool: "{tool_name}"
    then: block
    severity: high
    message: "Dangerous tool '{tool_name}' is blocked by policy\"""",
    "allow_with_args": """\
  - id: allow-{tool_name}-safe
    when:
      tool: "{tool_name}"
      args:
        - key: "path"
          pattern: "^/safe/.*"
    then: allow
    message: "Allowed with safe path\"""",
    "redact_pii": """\
  - id: redact-pii-{tool_name}
    when:
      tool: "{tool_name}"
    then: redact
    severity: medium
    message: "PII redacted in {tool_name} arguments\"""",
    "approve_critical": """\
  - id: approve-{tool_name}
    when:
      tool: "{tool_name}"
    then: approve
    severity: critical
    message: "Critical tool '{tool_name}' requires human approval\"""",
    "chain_anti_exfil": """\
  - id: anti-exfiltration
    when:
      tool: "{outgoing_tool}"
      chain:
        - tool: "{sensitive_tool}"
          within_seconds: 120
    then: block
    severity: critical
    message: "Data exfiltration pattern detected\"""",
}


@dataclass
class RuleRecommendation:
    """A recommended rule based on tool classification."""

    tool_name: str
    danger_level: DangerLevel
    suggested_verdict: str
    template_key: str
    yaml_snippet: str


def recommend_rules(tool_names: list[str]) -> list[RuleRecommendation]:
    """Generate rule recommendations for a list of tools.

    Args:
        tool_names: List of tool names to analyze.

    Returns:
        List of RuleRecommendation, one per tool.
    """
    recommendations = []
    for name in tool_names:
        level = classify_tool(name)
        if level == DangerLevel.CRITICAL:
            verdict, template = "approve", "approve_critical"
        elif level == DangerLevel.DANGEROUS:
            verdict, template = "block", "block_dangerous"
        elif level == DangerLevel.MODERATE:
            verdict, template = "allow", "allow_with_args"
        else:
            continue  # Safe tools don't need rules

        yaml = RULE_TEMPLATES[template].format(tool_name=name)
        recommendations.append(
            RuleRecommendation(
                tool_name=name,
                danger_level=level,
                suggested_verdict=verdict,
                template_key=template,
                yaml_snippet=yaml,
            )
        )
    return recommendations
