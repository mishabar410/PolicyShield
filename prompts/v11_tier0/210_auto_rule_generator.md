# Prompt 210 — Auto-Rule Generator

## Цель

Генерировать YAML-правила автоматически на основе списка тулов из OpenClaw — используя `classify_tool()` из `ai/templates.py` (без LLM).

## Контекст

- `classify_tool(name) → DangerLevel` уже существует в `policyshield/ai/templates.py`
- DangerLevel: SAFE → allow, MODERATE → allow (с логом), DANGEROUS → approve, CRITICAL → block
- Нужно: список tool names → classify → generate YAML rules
- Выход: валидный YAML для `rules.yaml`, готовый к использованию
- **Без LLM** — чистая логика на паттернах

## Что сделать

### 1. Создать `policyshield/ai/auto_rules.py`

```python
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
```

### 2. Тесты

#### `tests/test_auto_rules.py`

```python
"""Tests for automatic rule generation."""

import yaml
import pytest

from policyshield.ai.auto_rules import (
    generate_rules,
    rules_to_yaml,
    rules_to_yaml_dict,
    GeneratedRule,
)
from policyshield.ai.templates import DangerLevel


class TestGenerateRules:
    def test_critical_tool_blocked(self):
        rules = generate_rules(["exec"])
        assert len(rules) == 1
        assert rules[0].verdict == "block"
        assert rules[0].danger_level == DangerLevel.CRITICAL

    def test_dangerous_tool_approve(self):
        rules = generate_rules(["send_email"])
        assert len(rules) == 1
        assert rules[0].verdict == "approve"

    def test_safe_tool_skipped_by_default(self):
        rules = generate_rules(["log_message"])
        assert len(rules) == 0  # Safe tools skipped

    def test_safe_tool_included_when_flag(self):
        rules = generate_rules(["log_message"], include_safe=True)
        assert len(rules) == 1
        assert rules[0].verdict == "allow"

    def test_dedup(self):
        rules = generate_rules(["exec", "exec", "exec"])
        assert len(rules) == 1

    def test_sorted(self):
        rules = generate_rules(["write_file", "delete_file", "send_email"])
        names = [r.tool_name for r in rules]
        assert names == sorted(names)

    def test_mixed_tools(self):
        tools = ["read_file", "exec", "write_file", "delete_file", "send_email"]
        rules = generate_rules(tools)
        verdicts = {r.tool_name: r.verdict for r in rules}
        assert verdicts["exec"] == "block"
        assert verdicts["delete_file"] == "block"
        assert verdicts["send_email"] == "approve"
        assert verdicts["write_file"] == "approve"
        # read_file (moderate) → skipped by default

    def test_empty_list(self):
        assert generate_rules([]) == []


class TestRulesToYAML:
    def test_valid_yaml(self):
        rules = generate_rules(["exec", "send_email", "delete_file"])
        yaml_str = rules_to_yaml(rules)
        data = yaml.safe_load(yaml_str)
        assert data["shield_name"] == "auto-generated-policy"
        assert data["default_verdict"] == "block"
        assert len(data["rules"]) == 3

    def test_rule_has_id(self):
        rules = generate_rules(["delete_file"])
        data = rules_to_yaml_dict(rules)
        assert data["rules"][0]["id"] == "auto-delete-file"

    def test_custom_shield_name(self):
        rules = generate_rules(["exec"])
        yaml_str = rules_to_yaml(rules, shield_name="my-policy")
        data = yaml.safe_load(yaml_str)
        assert data["shield_name"] == "my-policy"

    def test_to_dict(self):
        rule = GeneratedRule(
            rule_id="test-id",
            tool_name="exec",
            verdict="block",
            severity="critical",
            danger_level=DangerLevel.CRITICAL,
            message="Blocked",
        )
        d = rule.to_dict()
        assert d["id"] == "test-id"
        assert d["when"]["tool"] == "exec"
        assert d["then"] == "block"
```

## Самопроверка

```bash
pytest tests/test_auto_rules.py -v
pytest tests/ -q
```

## Коммит

```
feat(ai): add automatic rule generation from tool classification

- generate_rules() → classify tools → create YAML rules (no LLM)
- CRITICAL→block, DANGEROUS→approve, SAFE/MODERATE→skip/allow
- rules_to_yaml() → ready-to-use YAML string
- Dedup, sort, include_safe flag, custom default_verdict
```
