"""Tests for kill switch REST API endpoints (Prompt 205)."""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient  # noqa: E402

from policyshield.core.models import RuleSet, Verdict  # noqa: E402
from policyshield.server.app import create_app  # noqa: E402
from policyshield.shield.async_engine import AsyncShieldEngine  # noqa: E402


def _make_engine() -> AsyncShieldEngine:
    return AsyncShieldEngine(
        rules=RuleSet(shield_name="test", version=1, rules=[], default_verdict=Verdict.ALLOW),
    )


@pytest.fixture
def client_engine():
    engine = _make_engine()
    app = create_app(engine)
    return TestClient(app), engine


class TestKillSwitchAPI:
    def test_kill_endpoint(self, client_engine):
        client, engine = client_engine
        resp = client.post("/api/v1/kill", json={"reason": "test"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "killed"
        assert engine.is_killed

    def test_resume_endpoint(self, client_engine):
        client, engine = client_engine
        engine.kill()
        resp = client.post("/api/v1/resume")
        assert resp.status_code == 200
        assert resp.json()["status"] == "resumed"
        assert not engine.is_killed

    def test_status_shows_killed(self, client_engine):
        client, engine = client_engine
        engine.kill()
        resp = client.get("/api/v1/status")
        assert resp.json()["killed"] is True

    def test_status_shows_not_killed(self, client_engine):
        client, engine = client_engine
        resp = client.get("/api/v1/status")
        assert resp.json()["killed"] is False
        assert resp.json()["status"] == "running"

    def test_status_has_version(self, client_engine):
        client, _ = client_engine
        resp = client.get("/api/v1/status")
        data = resp.json()
        assert "version" in data
        assert data["version"] != ""

    def test_kill_then_check_blocks(self, client_engine):
        client, engine = client_engine
        client.post("/api/v1/kill", json={"reason": "emergency"})
        resp = client.post(
            "/api/v1/check",
            json={"tool_name": "any_tool", "args": {}},
        )
        data = resp.json()
        assert data["verdict"] == "BLOCK"
        assert data["rule_id"] == "__kill_switch__"

    def test_kill_default_reason(self, client_engine):
        client, _ = client_engine
        resp = client.post("/api/v1/kill")
        data = resp.json()
        assert "Kill switch activated" in data["reason"]

    def test_kill_resume_kill_cycle(self, client_engine):
        client, engine = client_engine
        client.post("/api/v1/kill")
        assert engine.is_killed
        client.post("/api/v1/resume")
        assert not engine.is_killed
        # Check passes
        resp = client.post(
            "/api/v1/check",
            json={"tool_name": "tool", "args": {}},
        )
        assert resp.json()["verdict"] == "ALLOW"
        # Kill again
        client.post("/api/v1/kill")
        resp = client.post(
            "/api/v1/check",
            json={"tool_name": "tool", "args": {}},
        )
        assert resp.json()["verdict"] == "BLOCK"
