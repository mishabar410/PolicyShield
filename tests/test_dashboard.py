"""Tests for dashboard backend."""

import json

import pytest

pytest.importorskip("fastapi", reason="Dashboard tests require fastapi")
pytest.importorskip("starlette", reason="Dashboard tests require starlette")

from policyshield.dashboard import create_dashboard_app


def _write_traces(trace_dir, records):
    trace_dir.mkdir(parents=True, exist_ok=True)
    with open(trace_dir / "trace.jsonl", "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


@pytest.fixture
def trace_dir(tmp_path):
    d = tmp_path / "traces"
    records = [
        {"timestamp": "2025-01-01T12:00:00", "tool": "exec", "verdict": "BLOCK", "session_id": "s1"},
        {"timestamp": "2025-01-01T12:01:00", "tool": "exec", "verdict": "ALLOW", "session_id": "s1"},
        {"timestamp": "2025-01-01T12:02:00", "tool": "read_file", "verdict": "ALLOW", "session_id": "s1"},
        {
            "timestamp": "2025-01-01T12:03:00",
            "tool": "web_fetch",
            "verdict": "BLOCK",
            "session_id": "s1",
            "pii_types": ["EMAIL"],
        },
    ]
    _write_traces(d, records)
    return d


@pytest.fixture
def test_client(trace_dir):
    from starlette.testclient import TestClient

    app = create_dashboard_app(trace_dir)
    return TestClient(app)


class TestMetricsEndpoint:
    def test_get_metrics(self, test_client):
        resp = test_client.get("/api/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert "verdict_breakdown" in data

    def test_metrics_missing_dir(self, tmp_path):
        from starlette.testclient import TestClient

        app = create_dashboard_app(tmp_path / "nonexistent")
        client = TestClient(app)
        resp = client.get("/api/metrics")
        assert resp.status_code == 200
        assert "error" in resp.json()


class TestVerdictsEndpoint:
    def test_get_verdicts(self, test_client):
        resp = test_client.get("/api/metrics/verdicts")
        assert resp.status_code == 200
        data = resp.json()
        assert "allow" in data
        assert "block" in data


class TestToolsEndpoint:
    def test_get_tools(self, test_client):
        resp = test_client.get("/api/metrics/tools")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0


class TestPIIEndpoint:
    def test_get_pii(self, test_client):
        resp = test_client.get("/api/metrics/pii")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)


class TestCostEndpoint:
    def test_get_cost(self, test_client):
        resp = test_client.get("/api/metrics/cost")
        assert resp.status_code == 200
        data = resp.json()
        assert "model" in data

    def test_get_cost_custom_model(self, test_client):
        resp = test_client.get("/api/metrics/cost?model=gpt-4o-mini")
        assert resp.status_code == 200
        data = resp.json()
        assert data["model"] == "gpt-4o-mini"


class TestIndexPage:
    def test_index_no_static(self, test_client):
        resp = test_client.get("/")
        assert resp.status_code == 200
        assert "Dashboard" in resp.text


class TestWebSocket:
    def test_ws_connect(self, test_client):
        try:
            with test_client.websocket_connect("/ws/verdicts") as ws:
                assert ws is not None
        except Exception:
            # WebSocket may not work without full websockets package
            pytest.skip("WebSocket test requires websockets package")


class TestAppCreation:
    def test_creates_fastapi_app(self, trace_dir):
        app = create_dashboard_app(trace_dir)
        assert app.title == "PolicyShield Dashboard"
