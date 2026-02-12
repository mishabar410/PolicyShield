"""Tests for PyPI packaging integrity."""

from __future__ import annotations

from pathlib import Path

import tomllib


ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"


def _load_pyproject() -> dict:
    """Load pyproject.toml as a dict."""
    return tomllib.loads(PYPROJECT.read_text())


class TestPyProjectMetadata:
    def test_project_name(self):
        data = _load_pyproject()
        assert data["project"]["name"] == "policyshield"

    def test_version_is_semver(self):
        data = _load_pyproject()
        version = data["project"]["version"]
        parts = version.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_readme_exists(self):
        data = _load_pyproject()
        readme = data["project"].get("readme", "README.md")
        assert (ROOT / readme).exists()

    def test_license_specified(self):
        data = _load_pyproject()
        assert data["project"].get("license") is not None

    def test_python_requires(self):
        data = _load_pyproject()
        assert ">=3.10" in data["project"]["requires-python"]


class TestOptionalDependencies:
    def test_extras_exist(self):
        data = _load_pyproject()
        extras = data["project"]["optional-dependencies"]
        for group in ["langchain", "crewai", "otel", "dev", "docs", "nanobot", "all"]:
            assert group in extras, f"Missing optional dependency group: {group}"

    def test_dev_includes_pytest(self):
        data = _load_pyproject()
        dev_deps = data["project"]["optional-dependencies"]["dev"]
        assert any("pytest" in d for d in dev_deps)

    def test_dev_includes_ruff(self):
        data = _load_pyproject()
        dev_deps = data["project"]["optional-dependencies"]["dev"]
        assert any("ruff" in d for d in dev_deps)


class TestBuildTargets:
    def test_sdist_excludes_tests(self):
        data = _load_pyproject()
        sdist = data["tool"]["hatch"]["build"]["targets"]["sdist"]
        assert "tests/" in sdist["exclude"]

    def test_wheel_packages(self):
        data = _load_pyproject()
        wheel = data["tool"]["hatch"]["build"]["targets"]["wheel"]
        assert "policyshield" in wheel["packages"]


class TestPackageFiles:
    def test_py_typed_exists(self):
        assert (ROOT / "policyshield" / "py.typed").exists()

    def test_init_exists(self):
        assert (ROOT / "policyshield" / "__init__.py").exists()

    def test_cli_entry_point(self):
        data = _load_pyproject()
        scripts = data["project"].get("scripts", {})
        assert "policyshield" in scripts
        assert "policyshield.cli.main:app" in scripts["policyshield"]

    def test_classifiers_include_typed(self):
        data = _load_pyproject()
        classifiers = data["project"].get("classifiers", [])
        assert any("Typed" in c for c in classifiers)
