"""Tests for dead rule detection."""

from __future__ import annotations

from policyshield.core.parser import load_rules
from policyshield.lint.dead_rules import find_dead_rules


class TestDeadRuleDetection:
    def test_find_dead_rules(self, tmp_path):
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(
            "shield_name: test\nversion: 1\nrules:\n"
            "  - id: rule-a\n    tool: tool_a\n    then: BLOCK\n"
            "  - id: rule-b\n    tool: tool_b\n    then: ALLOW\n"
            "  - id: rule-c\n    tool: tool_c\n    then: BLOCK\n"
        )
        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()
        (trace_dir / "trace_test.jsonl").write_text('{"rule_id": "rule-a", "tool": "tool_a", "verdict": "BLOCK"}\n')

        ruleset = load_rules(rules_file)
        dead = find_dead_rules(ruleset, trace_dir)
        assert "rule-b" in dead
        assert "rule-c" in dead
        assert "rule-a" not in dead

    def test_no_dead_rules(self, tmp_path):
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text("shield_name: test\nversion: 1\nrules:\n  - id: r1\n    tool: t\n    then: BLOCK\n")
        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()
        (trace_dir / "trace_test.jsonl").write_text('{"rule_id": "r1"}\n')

        ruleset = load_rules(rules_file)
        dead = find_dead_rules(ruleset, trace_dir)
        assert len(dead) == 0

    def test_empty_trace_dir(self, tmp_path):
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text("shield_name: test\nversion: 1\nrules:\n  - id: r1\n    tool: t\n    then: BLOCK\n")
        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()

        ruleset = load_rules(rules_file)
        dead = find_dead_rules(ruleset, trace_dir)
        assert dead == ["r1"]
