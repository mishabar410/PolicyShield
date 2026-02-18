"""Tests for rule composition — include, extends, priority."""

from __future__ import annotations

from policyshield.core.parser import load_rules


class TestRuleComposition:
    def test_include_merges_rules(self, tmp_path):
        (tmp_path / "base.yaml").write_text(
            "shield_name: base\nversion: 1\nrules:\n  - id: r1\n    tool: exec\n    then: BLOCK\n"
        )
        (tmp_path / "main.yaml").write_text(
            "include:\n  - base.yaml\nshield_name: main\nversion: 1\n"
            "rules:\n  - id: r2\n    tool: read\n    then: ALLOW\n"
        )
        rs = load_rules(tmp_path / "main.yaml")
        assert len(rs.rules) == 2
        assert {r.id for r in rs.rules} == {"r1", "r2"}

    def test_extends_inherits_fields(self, tmp_path):
        (tmp_path / "rules.yaml").write_text(
            "shield_name: test\nversion: 1\nrules:\n"
            "  - id: parent\n    tool: exec\n    then: BLOCK\n    message: Base message\n"
            "  - id: child\n    extends: parent\n    then: ALLOW\n"
        )
        rs = load_rules(tmp_path / "rules.yaml")
        child = next(r for r in rs.rules if r.id == "child")
        assert child.then.value == "ALLOW"
        # Inherited tool from parent via when
        assert child.when.get("tool") == "exec"

    def test_include_not_found_error(self, tmp_path):
        (tmp_path / "main.yaml").write_text(
            "include:\n  - nonexistent.yaml\nshield_name: test\nversion: 1\nrules: []\n"
        )
        import pytest

        with pytest.raises(Exception, match="Include not found"):
            load_rules(tmp_path / "main.yaml")

    def test_no_include_no_extends(self, tmp_path):
        (tmp_path / "rules.yaml").write_text(
            "shield_name: test\nversion: 1\nrules:\n  - id: r1\n    tool: exec\n    then: BLOCK\n"
        )
        rs = load_rules(tmp_path / "rules.yaml")
        assert len(rs.rules) == 1
