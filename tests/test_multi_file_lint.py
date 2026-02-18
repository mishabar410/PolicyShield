"""Tests for multi-file rule validation."""

from __future__ import annotations

from policyshield.lint.cross_file import find_cross_file_issues


class TestMultiFileLint:
    def test_detect_duplicate_ids(self, tmp_path):
        (tmp_path / "a.yaml").write_text(
            "shield_name: a\nversion: 1\nrules:\n  - id: rule-1\n    tool: exec\n    then: BLOCK\n"
        )
        (tmp_path / "b.yaml").write_text(
            "shield_name: b\nversion: 1\nrules:\n  - id: rule-1\n    tool: read\n    then: ALLOW\n"
        )
        issues = find_cross_file_issues([tmp_path / "a.yaml", tmp_path / "b.yaml"])
        assert any("Duplicate" in i.message for i in issues)

    def test_detect_conflicting_verdicts(self, tmp_path):
        (tmp_path / "a.yaml").write_text(
            'shield_name: a\nversion: 1\nrules:\n  - id: r1\n    tool: ".*"\n    then: ALLOW\n'
        )
        (tmp_path / "b.yaml").write_text(
            'shield_name: b\nversion: 1\nrules:\n  - id: r2\n    tool: ".*"\n    then: BLOCK\n'
        )
        issues = find_cross_file_issues([tmp_path / "a.yaml", tmp_path / "b.yaml"])
        assert any("Conflicting" in i.message for i in issues)

    def test_no_issues_for_separate_rules(self, tmp_path):
        (tmp_path / "a.yaml").write_text(
            "shield_name: a\nversion: 1\nrules:\n  - id: r1\n    tool: exec\n    then: BLOCK\n"
        )
        (tmp_path / "b.yaml").write_text(
            "shield_name: b\nversion: 1\nrules:\n  - id: r2\n    tool: read\n    then: ALLOW\n"
        )
        issues = find_cross_file_issues([tmp_path / "a.yaml", tmp_path / "b.yaml"])
        errors = [i for i in issues if i.severity == "error"]
        assert len(errors) == 0

    def test_parse_error_reported(self, tmp_path):
        (tmp_path / "bad.yaml").write_text("not: valid: yaml: missing: rules:")
        issues = find_cross_file_issues([tmp_path / "bad.yaml"])
        assert any("Cannot parse" in i.message for i in issues)
