"""Tests for CLI `policyshield init` scaffold command."""

from __future__ import annotations

import yaml

from policyshield.cli.main import app
from policyshield.cli.init_scaffold import scaffold


class TestInitMinimalPreset:
    def test_init_minimal_preset(self, tmp_path):
        """Creates 3 rules, files exist."""
        created = scaffold(str(tmp_path), preset="minimal", interactive=False)
        assert "policies/rules.yaml" in created
        assert "tests/test_rules.yaml" in created
        assert "policyshield.yaml" in created

        rules_file = tmp_path / "policies" / "rules.yaml"
        assert rules_file.exists()
        data = yaml.safe_load(rules_file.read_text())
        assert len(data["rules"]) == 3

    def test_init_security_preset(self, tmp_path):
        """Creates 8+ rules, including shell/net."""
        scaffold(str(tmp_path), preset="security", interactive=False)
        rules_file = tmp_path / "policies" / "rules.yaml"
        data = yaml.safe_load(rules_file.read_text())
        assert len(data["rules"]) >= 8
        rule_ids = [r["id"] for r in data["rules"]]
        assert "block-shell-injection" in rule_ids

    def test_init_compliance_preset(self, tmp_path):
        """Creates 10+ rules including approval."""
        scaffold(str(tmp_path), preset="compliance", interactive=False)
        rules_file = tmp_path / "policies" / "rules.yaml"
        data = yaml.safe_load(rules_file.read_text())
        assert len(data["rules"]) >= 10
        rule_ids = [r["id"] for r in data["rules"]]
        assert "approve-delete-operations" in rule_ids


class TestInitNoInteractive:
    def test_init_no_interactive(self, tmp_path):
        """No interactive prompts, works silently."""
        # Should not hang or request input
        created = scaffold(str(tmp_path), preset="minimal", interactive=False)
        assert len(created) == 3


class TestInitExistingDirectory:
    def test_init_existing_directory(self, tmp_path):
        """Does not overwrite existing files."""
        # First run
        scaffold(str(tmp_path), preset="minimal", interactive=False)
        first_content = (tmp_path / "policies" / "rules.yaml").read_text()

        # Second run — should skip
        created = scaffold(str(tmp_path), preset="security", interactive=False)
        assert len(created) == 0

        # Content should not change
        assert (tmp_path / "policies" / "rules.yaml").read_text() == first_content


class TestInitTestCases:
    def test_init_creates_test_cases(self, tmp_path):
        """test_rules.yaml is valid YAML with test cases."""
        scaffold(str(tmp_path), preset="minimal", interactive=False)
        test_file = tmp_path / "tests" / "test_rules.yaml"
        assert test_file.exists()
        data = yaml.safe_load(test_file.read_text())
        assert "tests" in data
        assert len(data["tests"]) >= 6  # 2 per rule × 3 rules

    def test_init_generated_rules_valid(self, tmp_path):
        """rules.yaml passes policyshield validate."""
        scaffold(str(tmp_path), preset="security", interactive=False)
        rules_path = str(tmp_path / "policies" / "rules.yaml")
        exit_code = app(["validate", rules_path])
        assert exit_code == 0

    def test_init_generated_rules_lint_clean(self, tmp_path):
        """rules.yaml passes policyshield lint."""
        scaffold(str(tmp_path), preset="minimal", interactive=False)
        rules_path = str(tmp_path / "policies" / "rules.yaml")
        exit_code = app(["lint", rules_path])
        assert exit_code == 0


class TestInitDefaultDirectory:
    def test_init_default_directory(self, tmp_path, monkeypatch):
        """Without directory arg — scaffold in current directory."""
        monkeypatch.chdir(tmp_path)
        exit_code = app(["init", "--preset", "minimal", "--no-interactive"])
        assert exit_code == 0
        assert (tmp_path / "policies" / "rules.yaml").exists()
        assert (tmp_path / "tests" / "test_rules.yaml").exists()
        assert (tmp_path / "policyshield.yaml").exists()


class TestInitCLI:
    def test_init_cli_preset_security(self, tmp_path, capsys):
        """CLI init with --preset security works."""
        target = str(tmp_path / "project")
        exit_code = app(["init", target, "--preset", "security", "--no-interactive"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Created" in captured.out


class TestInitOpenclawPreset:
    def test_init_preset_openclaw(self, tmp_path):
        """policyshield init --preset openclaw creates rules.yaml."""
        created = scaffold(str(tmp_path), preset="openclaw", interactive=False)
        assert "policies/rules.yaml" in created
        rules_file = tmp_path / "policies" / "rules.yaml"
        assert rules_file.exists()
        data = yaml.safe_load(rules_file.read_text())
        assert len(data["rules"]) == 11

    def test_openclaw_rules_valid(self, tmp_path):
        """Generated openclaw rules pass policyshield validate."""
        scaffold(str(tmp_path), preset="openclaw", interactive=False)
        rules_path = str(tmp_path / "policies" / "rules.yaml")
        exit_code = app(["validate", rules_path])
        assert exit_code == 0

    def test_openclaw_rules_have_exec_block(self, tmp_path):
        """Openclaw preset has a block rule for exec tool."""
        scaffold(str(tmp_path), preset="openclaw", interactive=False)
        rules_file = tmp_path / "policies" / "rules.yaml"
        data = yaml.safe_load(rules_file.read_text())
        exec_blocks = [r for r in data["rules"] if r.get("tool") == "exec" and r["then"] == "block"]
        assert len(exec_blocks) >= 1

    def test_openclaw_rules_have_pii_redact(self, tmp_path):
        """Openclaw preset has a redact rule for PII."""
        scaffold(str(tmp_path), preset="openclaw", interactive=False)
        rules_file = tmp_path / "policies" / "rules.yaml"
        data = yaml.safe_load(rules_file.read_text())
        redact_rules = [r for r in data["rules"] if r["then"] == "redact"]
        assert len(redact_rules) >= 1

    def test_openclaw_rules_default_verdict(self, tmp_path):
        """Openclaw preset has default_verdict: allow."""
        scaffold(str(tmp_path), preset="openclaw", interactive=False)
        rules_file = tmp_path / "policies" / "rules.yaml"
        data = yaml.safe_load(rules_file.read_text())
        assert data["default_verdict"] == "allow"
