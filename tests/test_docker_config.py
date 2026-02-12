"""Tests for Docker configuration files."""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile"
COMPOSE_FILE = ROOT / "docker-compose.yml"


class TestDockerfile:
    def test_dockerfile_exists(self):
        assert DOCKERFILE.exists()

    def test_uses_python_slim(self):
        content = DOCKERFILE.read_text()
        assert "python:" in content
        assert "slim" in content

    def test_installs_package(self):
        content = DOCKERFILE.read_text()
        assert "pip install" in content

    def test_sets_entrypoint(self):
        content = DOCKERFILE.read_text()
        assert "ENTRYPOINT" in content
        assert "policyshield" in content


class TestDockerCompose:
    def test_compose_exists(self):
        assert COMPOSE_FILE.exists()

    def test_compose_valid_yaml(self):
        data = yaml.safe_load(COMPOSE_FILE.read_text())
        assert "services" in data

    def test_has_policyshield_service(self):
        data = yaml.safe_load(COMPOSE_FILE.read_text())
        assert "policyshield" in data["services"]

    def test_has_lint_service(self):
        data = yaml.safe_load(COMPOSE_FILE.read_text())
        assert "lint" in data["services"]

    def test_has_test_service(self):
        data = yaml.safe_load(COMPOSE_FILE.read_text())
        assert "test" in data["services"]
