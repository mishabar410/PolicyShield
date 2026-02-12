"""Tests for contributing guide and GitHub templates."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class TestContributing:
    def test_contributing_exists(self):
        assert (ROOT / "CONTRIBUTING.md").exists()

    def test_contributing_has_setup(self):
        content = (ROOT / "CONTRIBUTING.md").read_text()
        assert "pip install" in content

    def test_contributing_has_testing(self):
        content = (ROOT / "CONTRIBUTING.md").read_text()
        assert "pytest" in content

    def test_contributing_has_lint(self):
        content = (ROOT / "CONTRIBUTING.md").read_text()
        assert "ruff" in content


class TestTemplates:
    def test_pr_template_exists(self):
        assert (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").exists()

    def test_bug_report_exists(self):
        assert (ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.md").exists()

    def test_feature_request_exists(self):
        assert (ROOT / ".github" / "ISSUE_TEMPLATE" / "feature_request.md").exists()

    def test_pr_template_has_checklist(self):
        content = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text()
        assert "Checklist" in content
        assert "pytest" in content


class TestCodeOfConduct:
    def test_code_of_conduct_exists(self):
        assert (ROOT / "CODE_OF_CONDUCT.md").exists()

    def test_code_of_conduct_has_pledge(self):
        content = (ROOT / "CODE_OF_CONDUCT.md").read_text()
        assert "Pledge" in content
