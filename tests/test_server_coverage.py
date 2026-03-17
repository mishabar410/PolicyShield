"""Server endpoint coverage tests for approval, dashboard, and edge paths."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from policyshield.core.models import RuleConfig, RuleSet, Verdict


@pytest.fixture
def _engine():
    """Create a minimal async engine for testing."""
    from policyshield.shield.async_engine import AsyncShieldEngine

    rules = RuleSet(
        shield_name="test",
        version=1,
        rules=[
            RuleConfig(
                id="block-exec", when={"tool": "exec"}, then=Verdict.BLOCK, message="blocked"
            )
        ],
    )
    return AsyncShieldEngine(rules)


@pytest.fixture
def client(_engine):
    """TestClient wired to the engine."""
    from fastapi.testclient import TestClient

    from policyshield.server.app import create_app

    app = create_app(_engine)
    return TestClient(app)


class TestApprovalEndpoints:
    def test_check_approval_no_backend(self, client):
        """check-approval with no approval backend configured."""
        resp = client.post("/api/v1/check-approval", json={"approval_id": "test-123"})
        # Should not crash; returns some status
        assert resp.status_code in (200, 500)

    def test_clear_taint(self, client):
        """Clear taint on a session."""
        resp = client.post("/api/v1/clear-taint", json={"session_id": "sess-1"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == "sess-1"

    def test_respond_approval_no_backend(self, client):
        """respond-approval returns 500 when no backend."""
        resp = client.post(
            "/api/v1/respond-approval",
            json={"approval_id": "test-123", "approved": True, "responder": "admin"},
        )
        assert resp.status_code == 500

    def test_pending_approvals_no_backend(self, client):
        """pending-approvals returns empty list when no backend."""
        resp = client.get("/api/v1/pending-approvals")
        assert resp.status_code == 200
        data = resp.json()
        assert data["approvals"] == []


class TestDashboard:
    def test_dashboard_index(self, client):
        """Dashboard index returns either HTML or 404."""
        resp = client.get("/dashboard")
        assert resp.status_code in (200, 404)

    def test_dashboard_slash(self, client):
        """Dashboard with trailing slash."""
        resp = client.get("/dashboard/")
        assert resp.status_code in (200, 404)

    def test_dashboard_static_nonexistent(self, client):
        """Non-existent static asset returns 404."""
        resp = client.get("/dashboard/nonexistent.js")
        assert resp.status_code == 404

    def test_dashboard_path_traversal_blocked(self, client):
        """Path traversal attempt returns 404."""
        resp = client.get("/dashboard/../../etc/passwd")
        assert resp.status_code in (400, 404)


class TestServerEdgePaths:
    def test_content_type_missing_on_check(self, client):
        """POST without content-type on JSON endpoint returns 415."""
        resp = client.post("/api/v1/check", content=b'{"tool_name":"x","args":{}}')
        assert resp.status_code == 415

    def test_payload_too_large(self, _engine, monkeypatch):
        """Oversized payload returns 413."""
        monkeypatch.setenv("POLICYSHIELD_MAX_REQUEST_SIZE", "10")

        from fastapi.testclient import TestClient

        from policyshield.server.app import create_app

        app = create_app(_engine)
        c = TestClient(app)
        resp = c.post("/api/v1/check", json={"tool_name": "test_tool", "args": {"big": "x" * 100}})
        assert resp.status_code == 413

    def test_health_endpoint(self, client):
        """Health endpoint always returns 200."""
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data

    def test_status_endpoint(self, client):
        """Status endpoint returns running state."""
        resp = client.get("/api/v1/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data

    def test_constraints_endpoint(self, client):
        """Constraints endpoint returns summary."""
        resp = client.get("/api/v1/constraints")
        assert resp.status_code == 200

    def test_list_rules_endpoint(self, client):
        """List rules returns rules."""
        resp = client.get("/api/v1/rules")
        assert resp.status_code == 200


