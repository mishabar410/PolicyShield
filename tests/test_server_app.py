"""Tests for PolicyShield HTTP server (FastAPI app)."""

import pytest
from fastapi.testclient import TestClient

from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.shield.engine import ShieldEngine
from policyshield.server.app import create_app


def _make_engine() -> ShieldEngine:
    """Create a test ShieldEngine with a block-exec and redact-email rule."""
    rules = RuleSet(
        shield_name="test-server",
        version=1,
        rules=[
            RuleConfig(
                id="block-exec",
                description="Block exec calls",
                when={"tool": "exec"},
                then=Verdict.BLOCK,
                message="exec is not allowed",
            ),
            RuleConfig(
                id="redact-email",
                description="Redact PII in send_email",
                when={"tool": "send_email"},
                then=Verdict.REDACT,
            ),
        ],
    )
    return ShieldEngine(rules)


@pytest.fixture
def client() -> TestClient:
    engine = _make_engine()
    app = create_app(engine)
    return TestClient(app)


class TestServerApp:
    def test_health_endpoint(self, client: TestClient):
        """GET /api/v1/health → 200, JSON with shield_name."""
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["shield_name"] == "test-server"
        assert data["version"] == 1
        assert data["rules_count"] == 2
        assert data["mode"] == "ENFORCE"

    def test_check_allow(self, client: TestClient):
        """POST /api/v1/check with safe tool → ALLOW."""
        resp = client.post(
            "/api/v1/check",
            json={"tool_name": "read_file", "args": {"path": "/tmp"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "ALLOW"

    def test_check_block(self, client: TestClient):
        """POST /api/v1/check with blocked tool → BLOCK."""
        resp = client.post(
            "/api/v1/check",
            json={"tool_name": "exec", "args": {"command": "rm -rf /"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "BLOCK"
        assert data["rule_id"] == "block-exec"
        assert data["message"] != ""

    def test_check_redact(self, client: TestClient):
        """POST /api/v1/check with PII → REDACT + modified_args."""
        resp = client.post(
            "/api/v1/check",
            json={
                "tool_name": "send_email",
                "args": {"body": "Contact: john@example.com"},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "REDACT"
        assert data["modified_args"] is not None

    def test_post_check_pii(self, client: TestClient):
        """POST /api/v1/post-check with PII in result → redacted_output."""
        resp = client.post(
            "/api/v1/post-check",
            json={
                "tool_name": "read_file",
                "result": "User email: secret@corp.com is here",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["pii_types"]) > 0
        assert "EMAIL" in data["pii_types"]
        assert data["redacted_output"] is not None
        assert "secret@corp.com" not in data["redacted_output"]

    def test_constraints(self, client: TestClient):
        """GET /api/v1/constraints → summary string."""
        resp = client.get("/api/v1/constraints")
        assert resp.status_code == 200
        data = resp.json()
        assert "test-server" in data["summary"]
        assert "block-exec" in data["summary"]

    def test_check_invalid_body(self, client: TestClient):
        """POST with invalid JSON → 422."""
        resp = client.post(
            "/api/v1/check",
            json={"invalid_field": "nope"},
        )
        assert resp.status_code == 422
