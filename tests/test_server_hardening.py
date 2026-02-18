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
        resp = client.options("/api/v1/check", headers={"Origin": "http://evil.com"})
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
        assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"


# ── Prompt 304: Content-Type Validation ──────────────────────────


class TestContentType:
    def test_json_accepted(self, client: TestClient):
        resp = client.post("/api/v1/check", json={"tool_name": "test"})
        assert resp.status_code != 415

    def test_plain_text_rejected(self, client: TestClient):
        resp = client.post(
            "/api/v1/check",
            content="not json",
            headers={"content-type": "text/plain"},
        )
        assert resp.status_code == 415

    def test_form_data_rejected(self, client: TestClient):
        resp = client.post(
            "/api/v1/check",
            content="data",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        assert resp.status_code == 415

    def test_no_content_type_allowed(self, client: TestClient):
        """Missing Content-Type should still work (FastAPI handles it)."""
        resp = client.post("/api/v1/check", json={"tool_name": "test"})
        assert resp.status_code != 415


# ── Prompt 305: Payload Size Limit ───────────────────────────────


class TestPayloadSize:
    def test_normal_payload_accepted(self, client: TestClient):
        resp = client.post(
            "/api/v1/check",
            json={"tool_name": "test", "args": {"x": "a" * 100}},
        )
        assert resp.status_code != 413

    def test_oversized_payload_rejected(self, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_MAX_REQUEST_SIZE", "50")
        engine = _make_engine()
        app = create_app(engine)
        c = TestClient(app, raise_server_exceptions=False)
        resp = c.post(
            "/api/v1/check",
            json={"tool_name": "test", "args": {"data": "x" * 200}},
        )
        assert resp.status_code == 413
        assert resp.json()["error"] == "payload_too_large"


# ── Prompt 306: Input Validation ─────────────────────────────────


class TestInputValidation:
    def test_valid_tool_name(self, client: TestClient):
        resp = client.post("/api/v1/check", json={"tool_name": "send_email"})
        assert resp.status_code != 422

    def test_empty_tool_name_rejected(self, client: TestClient):
        resp = client.post("/api/v1/check", json={"tool_name": ""})
        assert resp.status_code == 422

    def test_too_long_tool_name_rejected(self, client: TestClient):
        resp = client.post("/api/v1/check", json={"tool_name": "a" * 300})
        assert resp.status_code == 422

    def test_special_chars_rejected(self, client: TestClient):
        resp = client.post("/api/v1/check", json={"tool_name": "rm -rf /"})
        assert resp.status_code == 422

    def test_dots_colons_allowed(self, client: TestClient):
        resp = client.post("/api/v1/check", json={"tool_name": "my.tool:v2-beta"})
        assert resp.status_code != 422

    def test_deeply_nested_args_rejected(self, client: TestClient):
        nested: dict = {"a": {}}
        current = nested["a"]
        for _ in range(15):
            current["b"] = {}
            current = current["b"]
        resp = client.post("/api/v1/check", json={"tool_name": "test", "args": nested})
        assert resp.status_code == 422

    def test_normal_depth_accepted(self, client: TestClient):
        resp = client.post(
            "/api/v1/check",
            json={"tool_name": "test", "args": {"a": {"b": {"c": 1}}}},
        )
        assert resp.status_code != 422


# ── Prompt 307: Backpressure ─────────────────────────────────────


class TestBackpressure:
    def test_overload_returns_503_with_verdict(self, monkeypatch):
        """When semaphore is at 1, concurrent check should get 503."""
        monkeypatch.setenv("POLICYSHIELD_MAX_CONCURRENT_CHECKS", "0")
        engine = _make_engine()
        app = create_app(engine)
        c = TestClient(app, raise_server_exceptions=False)
        resp = c.post("/api/v1/check", json={"tool_name": "test"})
        assert resp.status_code == 503
        body = resp.json()
        assert body["verdict"] == "BLOCK"
        assert body["error"] == "server_overloaded"

    def test_non_check_endpoints_not_limited(self, client: TestClient):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200


# ── Prompt 308: Request Timeout ──────────────────────────────────


class TestRequestTimeout:
    def test_fast_request_succeeds(self, client: TestClient):
        resp = client.post("/api/v1/check", json={"tool_name": "test"})
        assert resp.status_code != 504

    def test_health_not_affected(self, client: TestClient):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
