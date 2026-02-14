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


DOCKERFILE_SERVER = ROOT / "Dockerfile.server"


class TestDockerfileServer:
    def test_dockerfile_server_exists(self):
        """Dockerfile.server exists and is parseable."""
        assert DOCKERFILE_SERVER.exists()
        content = DOCKERFILE_SERVER.read_text()
        assert len(content) > 0
        assert "FROM" in content

    def test_dockerfile_server_exposes_8100(self):
        """Dockerfile.server exposes port 8100."""
        content = DOCKERFILE_SERVER.read_text()
        assert "EXPOSE 8100" in content

    def test_dockerfile_server_healthcheck(self):
        """Dockerfile.server contains a HEALTHCHECK instruction."""
        content = DOCKERFILE_SERVER.read_text()
        assert "HEALTHCHECK" in content


class TestComposeServerService:
    def test_compose_has_policyshield_server_service(self):
        """docker-compose.yml contains policyshield-server service."""
        data = yaml.safe_load(COMPOSE_FILE.read_text())
        assert "policyshield-server" in data["services"]
        service = data["services"]["policyshield-server"]
        assert service["build"]["dockerfile"] == "Dockerfile.server"
        assert "8100:8100" in service["ports"]
