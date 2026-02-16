"""End-to-end tests for v0.5 release."""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]

import yaml


ROOT = Path(__file__).resolve().parent.parent


class TestV05VersionConsistency:
    def test_pyproject_version(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text())
        # v0.5 features should still exist at v0.5+
        version = tuple(int(x) for x in data["project"]["version"].split("."))
        assert version >= (0, 5, 0)

    def test_changelog_has_v05(self):
        content = (ROOT / "CHANGELOG.md").read_text()
        assert "[0.5.0]" in content

    def test_readme_v05_complete(self):
        content = (ROOT / "README.md").read_text()
        assert len(content) > 100  # README should be substantial


class TestV05FilesExist:
    """Verify all v0.5 deliverables exist."""

    EXPECTED_FILES = [
        "policyshield/cli/init_scaffold.py",
        "policyshield/py.typed",
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
        ".github/workflows/docs.yml",
        ".github/actions/lint-rules/action.yml",
        "mkdocs.yml",
        "docs/index.md",
        "Dockerfile",
        "docker-compose.yml",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/ISSUE_TEMPLATE/bug_report.md",
        ".github/ISSUE_TEMPLATE/feature_request.md",
        "examples/fastapi_agent/app.py",
        "examples/github-actions/policy-check.yml",
    ]

    def test_all_deliverables_exist(self):
        missing = []
        for f in self.EXPECTED_FILES:
            if not (ROOT / f).exists():
                missing.append(f)
        assert missing == [], f"Missing v0.5 files: {missing}"


class TestV05TestCoverage:
    """Verify v0.5 test files exist."""

    V05_TEST_FILES = [
        "tests/test_cli_init.py",
        "tests/test_packaging.py",
        "tests/test_ci_config.py",
        "tests/test_github_action.py",
        "tests/test_docs_site.py",
        "tests/test_fastapi_example.py",
        "tests/test_docker_config.py",
        "tests/test_contributing.py",
        "tests/test_e2e_v05.py",
    ]

    def test_all_test_files_exist(self):
        missing = []
        for f in self.V05_TEST_FILES:
            if not (ROOT / f).exists():
                missing.append(f)
        assert missing == [], f"Missing v0.5 test files: {missing}"


class TestV05MkDocsIntegrity:
    def test_all_nav_pages_exist(self):
        mkdocs = yaml.safe_load((ROOT / "mkdocs.yml").read_text())
        docs_dir = ROOT / "docs"

        def _extract_pages(obj):
            pages = []
            if isinstance(obj, str):
                pages.append(obj)
            elif isinstance(obj, dict):
                for val in obj.values():
                    pages.extend(_extract_pages(val))
            elif isinstance(obj, list):
                for item in obj:
                    pages.extend(_extract_pages(item))
            return pages

        pages = _extract_pages(mkdocs["nav"])
        missing = [p for p in pages if not (docs_dir / p).exists()]
        assert missing == [], f"Missing doc pages: {missing}"
