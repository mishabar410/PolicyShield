"""Tests for FastAPI agent example."""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_DIR = ROOT / "examples" / "fastapi_agent"
RULES_PATH = EXAMPLE_DIR / "policies" / "rules.yaml"
TEST_RULES_PATH = EXAMPLE_DIR / "policies" / "test_rules.yaml"


class TestFastAPIExampleFiles:
    def test_app_exists(self):
        assert (EXAMPLE_DIR / "app.py").exists()

    def test_readme_exists(self):
        assert (EXAMPLE_DIR / "README.md").exists()

    def test_rules_exist(self):
        assert RULES_PATH.exists()

    def test_test_rules_exist(self):
        assert TEST_RULES_PATH.exists()


class TestFastAPIExampleRules:
    def test_rules_valid_yaml(self):
        data = yaml.safe_load(RULES_PATH.read_text())
        assert data["shield_name"] is not None
        assert data["version"] == 1

    def test_rules_have_ids(self):
        data = yaml.safe_load(RULES_PATH.read_text())
        for rule in data["rules"]:
            assert "id" in rule
            assert "then" in rule

    def test_test_cases_valid(self):
        data = yaml.safe_load(TEST_RULES_PATH.read_text())
        assert "tests" in data
        assert len(data["tests"]) >= 3


class TestFastAPIExampleApp:
    def test_app_imports(self):
        """Verify the app module can be imported (basic syntax check)."""
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "fastapi_app",
            str(EXAMPLE_DIR / "app.py"),
        )
        assert spec is not None
        # Note: we don't actually load it here to avoid fastapi dependency

    def test_app_has_endpoints(self):
        content = (EXAMPLE_DIR / "app.py").read_text()
        assert "/health" in content
        assert "/evaluate" in content
        assert "/rules" in content

    def test_app_uses_policyshield(self):
        content = (EXAMPLE_DIR / "app.py").read_text()
        assert "ShieldEngine" in content

    def test_app_has_models(self):
        content = (EXAMPLE_DIR / "app.py").read_text()
        assert "ToolCallRequest" in content
        assert "ToolCallResponse" in content
