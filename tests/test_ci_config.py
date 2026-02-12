"""Tests for GitHub Actions CI configuration."""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_PATH = ROOT / ".github" / "workflows" / "release.yml"


def _load_workflow(path: Path) -> dict:
    """Load a GitHub Actions workflow YAML."""
    return yaml.safe_load(path.read_text())


class TestCIWorkflow:
    def test_ci_exists(self):
        assert CI_PATH.exists()

    def test_ci_triggers(self):
        wf = _load_workflow(CI_PATH)
        # PyYAML parses 'on' as True (boolean)
        triggers = wf.get("on") or wf.get(True, {})
        assert "push" in triggers
        assert "pull_request" in triggers

    def test_ci_has_lint_job(self):
        wf = _load_workflow(CI_PATH)
        assert "lint" in wf["jobs"]

    def test_ci_has_test_job(self):
        wf = _load_workflow(CI_PATH)
        assert "test" in wf["jobs"]

    def test_ci_has_build_job(self):
        wf = _load_workflow(CI_PATH)
        assert "build" in wf["jobs"]

    def test_ci_test_matrix(self):
        wf = _load_workflow(CI_PATH)
        matrix = wf["jobs"]["test"]["strategy"]["matrix"]
        versions = matrix["python-version"]
        assert "3.10" in versions
        assert "3.12" in versions

    def test_ci_coverage_check(self):
        wf = _load_workflow(CI_PATH)
        test_steps = wf["jobs"]["test"]["steps"]
        run_commands = [s.get("run", "") for s in test_steps]
        assert any("cov-fail-under" in cmd for cmd in run_commands)

    def test_ci_format_check(self):
        wf = _load_workflow(CI_PATH)
        lint_steps = wf["jobs"]["lint"]["steps"]
        run_commands = [s.get("run", "") for s in lint_steps]
        assert any("ruff format" in cmd for cmd in run_commands)

    def test_ci_build_needs_lint_and_test(self):
        wf = _load_workflow(CI_PATH)
        needs = wf["jobs"]["build"]["needs"]
        assert "lint" in needs
        assert "test" in needs


class TestReleaseWorkflow:
    def test_release_exists(self):
        assert RELEASE_PATH.exists()

    def test_release_triggers_on_tags(self):
        wf = _load_workflow(RELEASE_PATH)
        triggers = wf.get("on") or wf.get(True, {})
        assert "push" in triggers
        tags = triggers["push"]["tags"]
        assert any("v*" in t for t in tags)

    def test_release_has_publish_job(self):
        wf = _load_workflow(RELEASE_PATH)
        assert "publish" in wf["jobs"]

    def test_release_uses_pypi_publish(self):
        wf = _load_workflow(RELEASE_PATH)
        steps = wf["jobs"]["publish"]["steps"]
        uses_list = [s.get("uses", "") for s in steps]
        assert any("pypi-publish" in u for u in uses_list)
