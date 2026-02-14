"""Tests for PolicyShield HTTP server (FastAPI app)."""

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient  # noqa: E402

from policyshield.core.models import RuleConfig, RuleSet, Verdict  # noqa: E402
from policyshield.server.app import create_app  # noqa: E402
from policyshield.shield.engine import ShieldEngine  # noqa: E402


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

    # ── additional integration tests (prompt 44) ──

    def test_check_empty_args(self, client: TestClient):
        """Empty args dict should be handled gracefully."""
        resp = client.post(
            "/api/v1/check",
            json={"tool_name": "read_file", "args": {}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] in ("ALLOW", "BLOCK", "REDACT")

    def test_check_large_args(self, client: TestClient):
        """args with 1000 keys should not crash the server."""
        big_args = {f"key_{i}": f"value_{i}" for i in range(1000)}
        resp = client.post(
            "/api/v1/check",
            json={"tool_name": "read_file", "args": big_args},
        )
        assert resp.status_code == 200

    def test_check_unicode_args(self, client: TestClient):
        """Unicode in args (cyrillic, emoji) should work."""
        resp = client.post(
            "/api/v1/check",
            json={"tool_name": "search", "args": {"query": "Привет мир 🌍🚀"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] in ("ALLOW", "BLOCK", "REDACT")

    def test_check_session_isolation(self, client: TestClient):
        """Two different session IDs should be tracked independently."""
        resp1 = client.post(
            "/api/v1/check",
            json={
                "tool_name": "exec",
                "args": {"command": "rm -rf /"},
                "session_id": "session-a",
            },
        )
        resp2 = client.post(
            "/api/v1/check",
            json={
                "tool_name": "read_file",
                "args": {"path": "/tmp"},
                "session_id": "session-b",
            },
        )
        data1 = resp1.json()
        data2 = resp2.json()
        assert data1["verdict"] == "BLOCK"
        assert data2["verdict"] == "ALLOW"

    def test_post_check_no_pii(self, client: TestClient):
        """Output without PII should return empty pii_types."""
        resp = client.post(
            "/api/v1/post-check",
            json={"tool_name": "read_file", "result": "Hello world, no PII here"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["pii_types"] == []
        assert data["redacted_output"] is None

    def test_post_check_with_email(self, client: TestClient):
        """Output with email should return EMAIL PII and redacted output."""
        resp = client.post(
            "/api/v1/post-check",
            json={"tool_name": "read_file", "result": "Contact: alice@example.com"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "EMAIL" in data["pii_types"]
        assert data["redacted_output"] is not None
        assert "alice@example.com" not in data["redacted_output"]

    def test_health_reflects_mode_change(self):
        """Health endpoint should reflect the engine's mode."""
        from policyshield.core.models import ShieldMode

        engine = _make_engine()
        engine.mode = ShieldMode.AUDIT
        app_local = create_app(engine)
        local_client = TestClient(app_local)

        resp = local_client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["mode"] == "AUDIT"

    def test_constraints_nonempty(self, client: TestClient):
        """Constraints endpoint should return a non-empty summary."""
        resp = client.get("/api/v1/constraints")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["summary"]) > 0
        assert "Rules:" in data["summary"]
