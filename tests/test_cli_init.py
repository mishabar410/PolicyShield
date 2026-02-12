"""Tests for CLI `policyshield init` scaffold command."""

from __future__ import annotations

import yaml

from policyshield.cli.main import app
from policyshield.cli.init_scaffold import scaffold


class TestInitMinimalPreset:
    def test_init_minimal_preset(self, tmp_path):
        """Creates 3 rules, files exist."""
        created = scaffold(str(tmp_path), preset="minimal", nanobot=False, interactive=False)
        assert "policies/rules.yaml" in created
        assert "tests/test_rules.yaml" in created
        assert "policyshield.yaml" in created

        rules_file = tmp_path / "policies" / "rules.yaml"
        assert rules_file.exists()
        data = yaml.safe_load(rules_file.read_text())
        assert len(data["rules"]) == 3

    def test_init_security_preset(self, tmp_path):
        """Creates 8+ rules, including shell/net."""
        scaffold(str(tmp_path), preset="security", nanobot=False, interactive=False)
        rules_file = tmp_path / "policies" / "rules.yaml"
        data = yaml.safe_load(rules_file.read_text())
        assert len(data["rules"]) >= 8
        rule_ids = [r["id"] for r in data["rules"]]
        assert "block-shell-injection" in rule_ids

    def test_init_compliance_preset(self, tmp_path):
        """Creates 10+ rules including approval."""
        scaffold(str(tmp_path), preset="compliance", nanobot=False, interactive=False)
        rules_file = tmp_path / "policies" / "rules.yaml"
        data = yaml.safe_load(rules_file.read_text())
        assert len(data["rules"]) >= 10
        rule_ids = [r["id"] for r in data["rules"]]
        assert "approve-delete-operations" in rule_ids


class TestInitNanobot:
    def test_init_with_nanobot(self, tmp_path):
        """Adds nanobot-specific rules and config section."""
        scaffold(str(tmp_path), preset="minimal", nanobot=True, interactive=False)

        # Check nanobot rules added
        rules_file = tmp_path / "policies" / "rules.yaml"
        data = yaml.safe_load(rules_file.read_text())
        rule_ids = [r["id"] for r in data["rules"]]
        assert any("nanobot" in rid for rid in rule_ids)

        # Check config has nanobot section
        config_file = tmp_path / "policyshield.yaml"
        config = yaml.safe_load(config_file.read_text())
        assert "nanobot" in config
        assert "rules_path" in config["nanobot"]


class TestInitNoInteractive:
    def test_init_no_interactive(self, tmp_path):
        """No interactive prompts, works silently."""
        # Should not hang or request input
        created = scaffold(str(tmp_path), preset="minimal", nanobot=False, interactive=False)
        assert len(created) == 3


class TestInitExistingDirectory:
    def test_init_existing_directory(self, tmp_path):
        """Does not overwrite existing files."""
        # First run
        scaffold(str(tmp_path), preset="minimal", nanobot=False, interactive=False)
        first_content = (tmp_path / "policies" / "rules.yaml").read_text()

        # Second run — should skip
        created = scaffold(str(tmp_path), preset="security", nanobot=False, interactive=False)
        assert len(created) == 0

        # Content should not change
        assert (tmp_path / "policies" / "rules.yaml").read_text() == first_content


class TestInitTestCases:
    def test_init_creates_test_cases(self, tmp_path):
        """test_rules.yaml is valid YAML with test cases."""
        scaffold(str(tmp_path), preset="minimal", nanobot=False, interactive=False)
        test_file = tmp_path / "tests" / "test_rules.yaml"
        assert test_file.exists()
        data = yaml.safe_load(test_file.read_text())
        assert "tests" in data
        assert len(data["tests"]) >= 6  # 2 per rule × 3 rules

    def test_init_generated_rules_valid(self, tmp_path):
        """rules.yaml passes policyshield validate."""
        scaffold(str(tmp_path), preset="security", nanobot=False, interactive=False)
        rules_path = str(tmp_path / "policies" / "rules.yaml")
        exit_code = app(["validate", rules_path])
        assert exit_code == 0

    def test_init_generated_rules_lint_clean(self, tmp_path):
        """rules.yaml passes policyshield lint."""
        scaffold(str(tmp_path), preset="minimal", nanobot=False, interactive=False)
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

    def test_init_cli_with_nanobot(self, tmp_path, capsys):
        """CLI init with --nanobot flag."""
        target = str(tmp_path / "project")
        exit_code = app(["init", target, "--nanobot", "--no-interactive"])
        assert exit_code == 0
        assert (tmp_path / "project" / "policies" / "rules.yaml").exists()
