# Prompt 108 — Rule Templates

## Цель

Создать библиотеку шаблонов правил и классификатор тулов (safe/dangerous/critical) — основу для AI Rule Writer.

## Контекст

- AI Rule Writer (промпт 109) будет генерировать YAML через LLM
- Но LLM нужен контекст: «что обычно блокируют?», «какие тулы опасны?»
- Шаблоны = few-shot examples для LLM
- Классификатор = список паттернов имён тулов → danger level
- Дополнительно: preset rules из `policyshield/presets/` как примеры реальных конфигов

## Что сделать

### 1. Создать `policyshield/ai/__init__.py`

Пустой, для пакета.

### 2. Создать `policyshield/ai/templates.py`

```python
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
    "block_dangerous": """
  - id: block-{tool_name}
    when:
      tool: "{tool_name}"
    then: block
    severity: high
    message: "Dangerous tool '{tool_name}' is blocked by policy"
""".strip(),

    "allow_with_args": """
  - id: allow-{tool_name}-safe
    when:
      tool: "{tool_name}"
      args:
        - key: "path"
          pattern: "^/safe/.*"
    then: allow
    message: "Allowed with safe path"
""".strip(),

    "redact_pii": """
  - id: redact-pii-{tool_name}
    when:
      tool: "{tool_name}"
    then: redact
    severity: medium
    message: "PII redacted in {tool_name} arguments"
""".strip(),

    "approve_critical": """
  - id: approve-{tool_name}
    when:
      tool: "{tool_name}"
    then: approve
    severity: critical
    message: "Critical tool '{tool_name}' requires human approval"
""".strip(),

    "chain_anti_exfil": """
  - id: anti-exfiltration
    when:
      tool: "{outgoing_tool}"
      chain:
        - tool: "{sensitive_tool}"
          within_seconds: 120
    then: block
    severity: critical
    message: "Data exfiltration pattern detected"
""".strip(),
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
        recommendations.append(RuleRecommendation(
            tool_name=name,
            danger_level=level,
            suggested_verdict=verdict,
            template_key=template,
            yaml_snippet=yaml,
        ))
    return recommendations
```

### 3. Тесты

#### `tests/test_rule_templates.py`

```python
from policyshield.ai.templates import (
    classify_tool, classify_tools, DangerLevel,
    recommend_rules, RULE_TEMPLATES,
)


def test_classify_critical():
    assert classify_tool("delete_file") == DangerLevel.CRITICAL
    assert classify_tool("exec_command") == DangerLevel.CRITICAL
    assert classify_tool("deploy_to_prod") == DangerLevel.CRITICAL


def test_classify_dangerous():
    assert classify_tool("send_email") == DangerLevel.DANGEROUS
    assert classify_tool("write_file") == DangerLevel.DANGEROUS
    assert classify_tool("http_request") == DangerLevel.DANGEROUS


def test_classify_moderate():
    assert classify_tool("read_file") == DangerLevel.MODERATE
    assert classify_tool("query_database") == DangerLevel.MODERATE


def test_classify_safe():
    assert classify_tool("log_event") == DangerLevel.SAFE
    assert classify_tool("format_text") == DangerLevel.SAFE
    assert classify_tool("health") == DangerLevel.SAFE


def test_classify_unknown():
    assert classify_tool("my_custom_tool_xyz") == DangerLevel.MODERATE


def test_classify_tools():
    result = classify_tools(["read_file", "delete_file", "log_event"])
    assert result["read_file"] == DangerLevel.MODERATE
    assert result["delete_file"] == DangerLevel.CRITICAL
    assert result["log_event"] == DangerLevel.SAFE


def test_recommend_rules():
    recs = recommend_rules(["delete_file", "send_email", "read_file", "log_event"])
    assert len(recs) == 3  # log_event is safe → no recommendation
    critical_rec = next(r for r in recs if r.tool_name == "delete_file")
    assert critical_rec.suggested_verdict == "approve"
    assert "approve" in critical_rec.yaml_snippet


def test_templates_valid_yaml():
    """All templates should produce valid YAML when formatted."""
    import yaml
    for key, template in RULE_TEMPLATES.items():
        formatted = template.format(
            tool_name="test_tool",
            outgoing_tool="send_email",
            sensitive_tool="read_database",
        )
        # Should parse as valid YAML
        parsed = yaml.safe_load(formatted)
        assert parsed is not None, f"Template '{key}' produced invalid YAML"
```

## Самопроверка

```bash
pytest tests/test_rule_templates.py -v
pytest tests/ -q
```

## Коммит

```
feat(ai): add rule templates and tool danger classifier

- Add DangerLevel enum: SAFE, MODERATE, DANGEROUS, CRITICAL
- Tool classifier: regex patterns for tool name → danger level
- Rule templates: block, allow, redact, approve, chain (few-shot)
- recommend_rules(): auto-generate rule suggestions from tool list
```
