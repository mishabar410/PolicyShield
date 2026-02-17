"""Tests for automatic rule generation."""

import yaml

from policyshield.ai.auto_rules import (
    GeneratedRule,
    generate_rules,
    rules_to_yaml,
    rules_to_yaml_dict,
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
