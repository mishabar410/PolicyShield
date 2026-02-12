"""Tests for reusable GitHub Action (lint-rules)."""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
ACTION_PATH = ROOT / ".github" / "actions" / "lint-rules" / "action.yml"
EXAMPLE_PATH = ROOT / "examples" / "github-actions" / "policy-check.yml"
DOCS_PATH = ROOT / "docs" / "github-action.md"


def _load_yaml(path: Path) -> dict:
    """Load a YAML file."""
    return yaml.safe_load(path.read_text())


class TestLintRulesAction:
    def test_action_exists(self):
        assert ACTION_PATH.exists()

    def test_action_is_composite(self):
        data = _load_yaml(ACTION_PATH)
        assert data["runs"]["using"] == "composite"

    def test_action_has_inputs(self):
        data = _load_yaml(ACTION_PATH)
        inputs = data.get("inputs", {})
        assert "rules-path" in inputs
        assert "python-version" in inputs
        assert "policyshield-version" in inputs

    def test_action_has_validate_step(self):
        data = _load_yaml(ACTION_PATH)
        steps = data["runs"]["steps"]
        run_commands = [s.get("run", "") for s in steps]
        assert any("validate" in cmd for cmd in run_commands)

    def test_action_has_lint_step(self):
        data = _load_yaml(ACTION_PATH)
        steps = data["runs"]["steps"]
        run_commands = [s.get("run", "") for s in steps]
        assert any("lint" in cmd for cmd in run_commands)

    def test_action_has_test_step(self):
        data = _load_yaml(ACTION_PATH)
        steps = data["runs"]["steps"]
        run_commands = [s.get("run", "") for s in steps]
        assert any("test" in cmd for cmd in run_commands)

    def test_action_test_path_input(self):
        data = _load_yaml(ACTION_PATH)
        assert "test-path" in data.get("inputs", {})


class TestExampleWorkflow:
    def test_example_exists(self):
        assert EXAMPLE_PATH.exists()

    def test_example_references_action(self):
        content = EXAMPLE_PATH.read_text()
        assert "lint-rules" in content


class TestActionDocs:
    def test_docs_exist(self):
        assert DOCS_PATH.exists()

    def test_docs_has_inputs_table(self):
        content = DOCS_PATH.read_text()
        assert "rules-path" in content
        assert "policyshield-version" in content
