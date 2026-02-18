"""Tests for server hardening features (Tier 1.5)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
import uuid

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient  # noqa: E402

from policyshield.core.models import RuleConfig, RuleSet, Verdict  # noqa: E402
from policyshield.server.app import create_app  # noqa: E402
from policyshield.shield.async_engine import AsyncShieldEngine  # noqa: E402


def _make_engine(**kwargs) -> AsyncShieldEngine:
    """Create a test engine with a simple block-exec rule."""
    rules = RuleSet(
        shield_name="hardening-test",
        version=1,
        rules=[
            RuleConfig(
                id="block-exec",
                description="Block exec calls",
                when={"tool": "exec"},
                then=Verdict.BLOCK,
                message="exec is not allowed",
            ),
        ],
    )
    return AsyncShieldEngine(rules, **kwargs)


@pytest.fixture
def client() -> TestClient:
    engine = _make_engine()
    app = create_app(engine)
    return TestClient(app, raise_server_exceptions=False)


# ── Prompt 301: Global Exception Handler ─────────────────────────


class TestGlobalExceptionHandler:
    def test_internal_error_returns_json_verdict(self):
        """Even on 500, response must have 'verdict' key."""
        engine = _make_engine()
        app = create_app(engine)

        with patch.object(engine, "check", new_callable=AsyncMock, side_effect=RuntimeError("boom")):
            c = TestClient(app, raise_server_exceptions=False)
            resp = c.post(
                "/api/v1/check",
                json={"tool_name": "read_file", "args": {"path": "/tmp"}},
            )
        assert resp.status_code == 500
        assert resp.headers["content-type"].startswith("application/json")
        body = resp.json()
        assert "verdict" in body
        assert body["error"] == "internal_error"

    def test_internal_error_fail_open_verdict(self):
        """When engine._fail_open is True, internal error verdict should be ALLOW."""
        engine = _make_engine(fail_open=True)
        app = create_app(engine)

        with patch.object(engine, "check", new_callable=AsyncMock, side_effect=RuntimeError("boom")):
            c = TestClient(app, raise_server_exceptions=False)
            resp = c.post(
                "/api/v1/check",
                json={"tool_name": "x", "args": {}},
            )
        assert resp.json()["verdict"] == "ALLOW"

    def test_internal_error_fail_closed_verdict(self):
        """When engine._fail_open is False, internal error verdict should be BLOCK."""
        engine = _make_engine(fail_open=False)
        app = create_app(engine)

        with patch.object(engine, "check", new_callable=AsyncMock, side_effect=RuntimeError("boom")):
            c = TestClient(app, raise_server_exceptions=False)
            resp = c.post(
                "/api/v1/check",
                json={"tool_name": "x", "args": {}},
            )
        assert resp.json()["verdict"] == "BLOCK"

    def test_validation_error_hides_internals(self, client: TestClient):
        """Validation error should return clean message without pydantic details."""
        resp = client.post(
            "/api/v1/check",
            content="not json",
            headers={"content-type": "application/json"},
        )
        body = resp.json()
        assert body["error"] == "validation_error"
        assert "pydantic" not in body.get("message", "").lower()


# ── Prompt 302: Request / Correlation ID ─────────────────────────


class TestRequestId:
    def test_response_always_has_request_id(self, client: TestClient):
        resp = client.post("/api/v1/check", json={"tool_name": "test"})
        data = resp.json()
        assert "request_id" in data
        assert len(data["request_id"]) > 0

    def test_client_request_id_echoed(self, client: TestClient):
        resp = client.post(
            "/api/v1/check",
            json={"tool_name": "test", "request_id": "my-id-123"},
        )
        assert resp.json()["request_id"] == "my-id-123"

    def test_generated_id_is_uuid(self, client: TestClient):
        resp = client.post("/api/v1/check", json={"tool_name": "test"})
        rid = resp.json()["request_id"]
        uuid.UUID(rid)  # Raises ValueError if not valid UUID


# ── Prompt 303: CORS Middleware ───────────────────────────────────


class TestCORS:
    def test_cors_disabled_by_default(self, client: TestClient):
        resp = client.options(
            "/api/v1/check", headers={"Origin": "http://evil.com"}
        )
        assert "access-control-allow-origin" not in resp.headers

    def test_cors_enabled_with_env(self, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_CORS_ORIGINS", "http://localhost:3000")
        engine = _make_engine()
        app = create_app(engine)
        c = TestClient(app)
        resp = c.options(
            "/api/v1/check",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert (
            resp.headers.get("access-control-allow-origin")
            == "http://localhost:3000"
        )
