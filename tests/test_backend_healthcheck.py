"""Tests for approval backend healthcheck."""

from __future__ import annotations

from unittest.mock import Mock, patch

from policyshield.approval.memory import InMemoryBackend
from policyshield.approval.webhook import WebhookApprovalBackend


class TestBaseBackendHealth:
    def test_default_health(self):
        backend = InMemoryBackend()
        health = backend.health()
        assert health["healthy"] is True
        assert health["latency_ms"] == 0
        assert health["error"] is None


class TestWebhookHealth:
    def test_webhook_health_ok(self):
        mock_resp = Mock()
        mock_resp.status_code = 200
        with patch("httpx.Client") as MockClient:
            client_inst = MockClient.return_value.__enter__.return_value
            client_inst.head.return_value = mock_resp
            backend = WebhookApprovalBackend(webhook_url="http://example.com/hook")
            health = backend.health()
        assert health["healthy"] is True
        assert health["latency_ms"] >= 0
        assert health["error"] is None

    def test_webhook_health_server_error(self):
        mock_resp = Mock()
        mock_resp.status_code = 500
        with patch("httpx.Client") as MockClient:
            client_inst = MockClient.return_value.__enter__.return_value
            client_inst.head.return_value = mock_resp
            backend = WebhookApprovalBackend(webhook_url="http://example.com/hook")
            health = backend.health()
        assert health["healthy"] is False
        assert "HTTP 500" in health["error"]

    def test_webhook_health_connection_error(self):
        import httpx

        with patch("httpx.Client") as MockClient:
            client_inst = MockClient.return_value.__enter__.return_value
            client_inst.head.side_effect = httpx.ConnectError("Connection refused")
            backend = WebhookApprovalBackend(webhook_url="http://example.com/hook")
            health = backend.health()
        assert health["healthy"] is False
        assert health["error"] is not None


class TestReadyzApprovalHealth:
    def test_readyz_with_unhealthy_backend(self):
        """When approval backend is unhealthy, /readyz should return 503."""
        from starlette.testclient import TestClient

        from policyshield.core.models import RuleConfig, RuleSet, ShieldMode, Verdict
        from policyshield.shield.async_engine import AsyncShieldEngine

        rules = RuleSet(
            shield_name="test",
            version="1.0",
            rules=[RuleConfig(id="r1", then=Verdict.ALLOW)],
            default_verdict=Verdict.ALLOW,
        )
        engine = AsyncShieldEngine(rules=rules, mode=ShieldMode.ENFORCE)

        # Mock an unhealthy approval backend
        mock_backend = Mock()
        mock_backend.health.return_value = {"healthy": False, "latency_ms": 0, "error": "down"}
        engine._approval_backend = mock_backend

        from policyshield.server.app import create_app

        app = create_app(engine)

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/readyz")
        assert resp.status_code == 503
        assert resp.json()["status"] == "approval_backend_unhealthy"

    def test_readyz_with_healthy_backend(self):
        """When approval backend is healthy, /readyz should include backend info."""
        from starlette.testclient import TestClient

        from policyshield.core.models import RuleConfig, RuleSet, ShieldMode, Verdict
        from policyshield.shield.async_engine import AsyncShieldEngine

        rules = RuleSet(
            shield_name="test",
            version="1.0",
            rules=[RuleConfig(id="r1", then=Verdict.ALLOW)],
            default_verdict=Verdict.ALLOW,
        )
        engine = AsyncShieldEngine(rules=rules, mode=ShieldMode.ENFORCE)

        # Mock a healthy approval backend
        mock_backend = Mock()
        mock_backend.health.return_value = {"healthy": True, "latency_ms": 5.0, "error": None}
        engine._approval_backend = mock_backend

        from policyshield.server.app import create_app

        app = create_app(engine)

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/readyz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"
        assert data["approval_backend"]["healthy"] is True
