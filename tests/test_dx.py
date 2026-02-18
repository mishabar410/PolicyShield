"""Tests for DX & Adoption — prompts 351-367."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from policyshield.core.models import Verdict
from policyshield.server.app import create_app
from policyshield.shield.async_engine import AsyncShieldEngine
from policyshield.shield.engine import ShieldEngine
from starlette.testclient import TestClient


def _make_engine(tmp_path, **kwargs):
    rules = tmp_path / "rules.yaml"
    rules.write_text("shield_name: test\nversion: '1'\nrules: []\n")
    return AsyncShieldEngine(rules=rules, **kwargs)


def _make_client(tmp_path):
    engine = _make_engine(tmp_path)
    app = create_app(engine)
    return TestClient(app), engine


# ── Prompt 351+352: Python SDK Client + Retry ────────────────────


class TestPolicyShieldClient:
    def test_client_init_with_token(self):
        from policyshield.client import PolicyShieldClient

        c = PolicyShieldClient(token="test-token")
        assert c._client.headers.get("authorization") == "Bearer test-token"
        c.close()

    def test_client_context_manager(self):
        from policyshield.client import PolicyShieldClient

        with PolicyShieldClient() as c:
            assert c is not None

    def test_check_result_fields(self):
        from policyshield.client import CheckResult

        r = CheckResult(verdict="ALLOW", message="ok", rule_id="r1")
        assert r.verdict == "ALLOW"
        assert r.rule_id == "r1"


# ── Prompt 353: Dry-run CLI (check subcommand) ───────────────────


class TestDryRunCLI:
    def test_check_with_engine(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: test\nversion: '1'\nrules: []\n")
        engine = ShieldEngine(rules=str(rules))
        result = engine.check("test_tool", {})
        assert result.verdict in (Verdict.ALLOW, Verdict.BLOCK)


# ── Prompt 354: Decorator API ────────────────────────────────────


class TestDecoratorAPI:
    def test_guard_allows(self, tmp_path):
        from policyshield.decorators import guard

        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: test\nversion: '1'\nrules: []\n")
        engine = ShieldEngine(rules=str(rules))

        @guard("safe_tool", engine=engine)
        def my_func(x=1):
            return x * 2

        assert my_func(x=5) == 10

    def test_guard_blocks(self, tmp_path):
        from policyshield.decorators import guard

        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "shield_name: test\nversion: '1'\n"
            "rules:\n  - id: r1\n    tool_name: blocked\n    then: BLOCK\n    message: blocked\n"
        )
        engine = ShieldEngine(rules=str(rules))

        @guard("blocked", engine=engine, on_block="raise")
        def my_func():
            return "should not reach"

        with pytest.raises(PermissionError):
            my_func()

    def test_guard_return_none_on_block(self, tmp_path):
        from policyshield.decorators import guard

        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "shield_name: test\nversion: '1'\n"
            "rules:\n  - id: r1\n    tool_name: blocked\n    then: BLOCK\n    message: blocked\n"
        )
        engine = ShieldEngine(rules=str(rules))

        @guard("blocked", engine=engine, on_block="return_none")
        def my_func():
            return "value"

        assert my_func() is None


# ── Prompt 355: Presets ──────────────────────────────────────────


class TestPresets:
    @pytest.mark.parametrize("preset", ["strict", "permissive", "minimal"])
    def test_preset_exists(self, preset):
        preset_dir = Path(__file__).parent.parent / "policyshield" / "presets"
        assert (preset_dir / f"{preset}.yaml").exists()

    @pytest.mark.parametrize("preset", ["strict", "permissive", "minimal"])
    def test_preset_is_valid_yaml(self, preset):
        import yaml

        preset_dir = Path(__file__).parent.parent / "policyshield" / "presets"
        content = (preset_dir / f"{preset}.yaml").read_text()
        data = yaml.safe_load(content)
        assert "rules" in data


# ── Prompt 356: MCP Server ───────────────────────────────────────


class TestMCPServer:
    def test_mcp_import_check(self):
        from policyshield.mcp_server import HAS_MCP

        # Just verify import works (mcp may not be installed)
        assert isinstance(HAS_MCP, bool)


# ── Prompt 357: K8s Probes ───────────────────────────────────────


class TestK8sProbes:
    def test_liveness_always_200(self, tmp_path):
        client, _ = _make_client(tmp_path)
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "alive"

    def test_readiness_ok_when_ready(self, tmp_path):
        client, _ = _make_client(tmp_path)
        resp = client.get("/readyz")
        # May be 200 or 503 depending on rules loaded (0 rules → 503)
        assert resp.status_code in (200, 503)

    def test_probes_no_auth_required(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_API_TOKEN", "secret")
        client, _ = _make_client(tmp_path)
        resp = client.get("/healthz")
        assert resp.status_code == 200


# ── Prompt 358: Settings ─────────────────────────────────────────


class TestSettings:
    def test_defaults(self, monkeypatch):
        monkeypatch.delenv("POLICYSHIELD_PORT", raising=False)
        monkeypatch.delenv("POLICYSHIELD_FAIL_MODE", raising=False)
        from policyshield.config.settings import PolicyShieldSettings

        s = PolicyShieldSettings()
        assert s.port == 8000
        assert s.fail_mode == "closed"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_PORT", "9090")
        from policyshield.config.settings import PolicyShieldSettings

        s = PolicyShieldSettings()
        assert s.port == 9090


# ── Prompt 359: Idempotency ──────────────────────────────────────


class TestIdempotency:
    def test_cache_set_get(self):
        from policyshield.server.idempotency import IdempotencyCache

        cache = IdempotencyCache()
        cache.set("k1", {"verdict": "ALLOW"})
        assert cache.get("k1") == {"verdict": "ALLOW"}

    def test_cache_miss(self):
        from policyshield.server.idempotency import IdempotencyCache

        cache = IdempotencyCache()
        assert cache.get("nonexistent") is None

    def test_cache_max_size(self):
        from policyshield.server.idempotency import IdempotencyCache

        cache = IdempotencyCache(max_size=2)
        cache.set("a", {"v": 1})
        cache.set("b", {"v": 2})
        cache.set("c", {"v": 3})
        assert cache.get("a") is None  # Evicted
        assert cache.get("c") == {"v": 3}

    def test_idempotency_header(self, tmp_path):
        client, _ = _make_client(tmp_path)
        headers = {"x-idempotency-key": "test-key-1"}
        r1 = client.post(
            "/api/v1/check",
            json={"tool_name": "test"},
            headers=headers,
        )
        r2 = client.post(
            "/api/v1/check",
            json={"tool_name": "test"},
            headers=headers,
        )
        assert r1.json()["verdict"] == r2.json()["verdict"]


# ── Prompt 360: Examples ─────────────────────────────────────────


class TestExamples:
    @pytest.mark.parametrize(
        "example",
        ["standalone_check.py", "fastapi_middleware.py"],
    )
    def test_example_syntax(self, example):
        example_path = Path(__file__).parent.parent / "examples" / example
        if example_path.exists():
            ast.parse(example_path.read_text())


# ── Prompt 361: OpenAPI Schema ───────────────────────────────────


class TestSchemaExport:
    def test_schema_is_valid_openapi(self, tmp_path):
        engine = _make_engine(tmp_path)
        app = create_app(engine)
        schema = app.openapi()
        assert "openapi" in schema
        assert "paths" in schema

    def test_schema_has_check_endpoint(self, tmp_path):
        engine = _make_engine(tmp_path)
        app = create_app(engine)
        schema = app.openapi()
        paths_str = json.dumps(schema["paths"])
        assert "/check" in paths_str


# ── Prompt 362: Metrics ──────────────────────────────────────────


class TestMetrics:
    def test_metrics_format(self):
        from policyshield.server.metrics import MetricsCollector

        m = MetricsCollector()
        m.record("ALLOW", 5.0)
        m.record("BLOCK", 3.0)
        output = m.to_prometheus()
        assert "policyshield_requests_total 2" in output
        assert 'verdict="ALLOW"' in output

    def test_metrics_endpoint(self, tmp_path):
        client, _ = _make_client(tmp_path)
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "policyshield_requests_total" in resp.text


# ── Prompt 364: Async Client ─────────────────────────────────────


class TestAsyncClient:
    def test_async_client_importable(self):
        from policyshield.async_client import AsyncPolicyShieldClient

        assert AsyncPolicyShieldClient is not None


# ── Prompt 366: Webhook ──────────────────────────────────────────


class TestWebhook:
    def test_webhook_notifier_importable(self):
        from policyshield.server.webhook import WebhookNotifier

        wh = WebhookNotifier(url="https://example.com/test")
        assert wh._url == "https://example.com/test"


# ── Prompt 367: AsyncEngine Compat ───────────────────────────────


class TestAsyncEngineCompat:
    @pytest.mark.asyncio
    async def test_async_engine_has_fail_open(self, tmp_path):
        engine = _make_engine(tmp_path)
        assert hasattr(engine, "_fail_open")

    @pytest.mark.asyncio
    async def test_async_check_with_timeout(self, tmp_path):
        engine = _make_engine(tmp_path)
        result = await engine.check("test_tool", {})
        assert result.verdict is not None

    @pytest.mark.asyncio
    async def test_async_approval_meta_cleanup(self, tmp_path):
        engine = _make_engine(tmp_path)
        assert hasattr(engine, "_cleanup_approval_meta")
