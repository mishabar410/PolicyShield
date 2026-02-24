"""Tests for Tier 2 features — decorator, SDK, dry-run CLI, health probes, retry."""

from __future__ import annotations

import json

import pytest

from policyshield import ShieldEngine
from policyshield.server.app import create_app
from policyshield.shield.async_engine import AsyncShieldEngine
from starlette.testclient import TestClient


# ── Helper ──────────────────────────────────────────────────────────

def _make_engine(tmp_path, rules_yaml=None):
    rules = tmp_path / "rules.yaml"
    rules.write_text(rules_yaml or """
shield_name: test
version: '1'
rules:
  - id: block-exec
    when: { tool: exec_command }
    then: BLOCK
    message: "Execution blocked"
  - id: allow-read
    when: { tool: read_file }
    then: ALLOW
""")
    return ShieldEngine(rules=rules)


def _make_async_engine(tmp_path, rules_yaml=None):
    rules = tmp_path / "rules.yaml"
    rules.write_text(rules_yaml or """
shield_name: test
version: '1'
rules:
  - id: block-exec
    when: { tool: exec_command }
    then: BLOCK
    message: "Execution blocked"
  - id: allow-read
    when: { tool: read_file }
    then: ALLOW
""")
    return AsyncShieldEngine(rules=rules)


# ── 504: Decorator API ──────────────────────────────────────────────

class TestShieldDecorator:
    def test_sync_allow(self, tmp_path):
        from policyshield.decorators import shield

        engine = _make_engine(tmp_path)

        @shield(engine, tool_name="read_file")
        def read_it(path="/tmp"):
            return f"read {path}"

        assert read_it() == "read /tmp"

    def test_sync_block_raises(self, tmp_path):
        from policyshield.decorators import shield

        engine = _make_engine(tmp_path)

        @shield(engine, tool_name="exec_command")
        def exec_it(cmd="ls"):
            return cmd

        with pytest.raises(PermissionError, match="BLOCKED"):
            exec_it()

    def test_sync_block_return_none(self, tmp_path):
        from policyshield.decorators import shield

        engine = _make_engine(tmp_path)

        @shield(engine, tool_name="exec_command", on_block="return_none")
        def exec_it(cmd="ls"):
            return cmd

        assert exec_it() is None

    def test_tool_name_defaults_to_function_name(self, tmp_path):
        from policyshield.decorators import shield

        engine = _make_engine(tmp_path)

        @shield(engine)
        def read_file(path="/tmp"):
            return f"read {path}"

        assert read_file() == "read /tmp"

    @pytest.mark.asyncio
    async def test_async_allow(self, tmp_path):
        from policyshield.decorators import shield

        engine = _make_async_engine(tmp_path)

        @shield(engine, tool_name="read_file")
        async def async_read(path="/tmp"):
            return f"async read {path}"

        assert await async_read() == "async read /tmp"

    @pytest.mark.asyncio
    async def test_async_block_raises(self, tmp_path):
        from policyshield.decorators import shield

        engine = _make_async_engine(tmp_path)

        @shield(engine, tool_name="exec_command")
        async def async_exec(cmd="ls"):
            return cmd

        with pytest.raises(PermissionError, match="BLOCKED"):
            await async_exec()


# ── 513: Dry-run CLI ────────────────────────────────────────────────

class TestDryRunCLI:
    def test_check_allow(self, tmp_path):
        from policyshield.cli.main import app

        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: t\nversion: '1'\nrules:\n  - id: r1\n    when: { tool: safe }\n    then: ALLOW\n")
        code = app(["check", "--tool", "safe", "--rules", str(rules)])
        assert code == 0

    def test_check_block_exit_2(self, tmp_path):
        from policyshield.cli.main import app

        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: t\nversion: '1'\nrules:\n  - id: r1\n    when: { tool: bad }\n    then: BLOCK\n    message: blocked\n")
        code = app(["check", "--tool", "bad", "--rules", str(rules)])
        assert code == 2

    def test_check_json_output(self, tmp_path, capsys):
        from policyshield.cli.main import app

        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: t\nversion: '1'\nrules:\n  - id: r1\n    when: { tool: safe }\n    then: ALLOW\n")
        app(["check", "--tool", "safe", "--rules", str(rules), "--json"])
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["verdict"] == "ALLOW"


# ── 523/524: Health Probes ──────────────────────────────────────────

class TestHealthProbes:
    def _client(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: t\nversion: '1'\nrules:\n  - id: r1\n    when: { tool: x }\n    then: ALLOW\n")
        engine = AsyncShieldEngine(rules=rules)
        return TestClient(create_app(engine))

    def test_livez(self, tmp_path):
        client = self._client(tmp_path)
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "alive"

    def test_readyz(self, tmp_path):
        client = self._client(tmp_path)
        resp = client.get("/readyz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ready"

    def test_api_livez(self, tmp_path):
        client = self._client(tmp_path)
        resp = client.get("/api/v1/livez")
        assert resp.status_code == 200

    def test_api_readyz(self, tmp_path):
        client = self._client(tmp_path)
        resp = client.get("/api/v1/readyz")
        assert resp.status_code == 200


# ── 522: Retry/Backoff ─────────────────────────────────────────────

class TestRetryBackoff:
    @pytest.mark.asyncio
    async def test_success_first_attempt(self):
        from policyshield.approval.retry import retry_with_backoff

        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = await retry_with_backoff(fn, max_retries=3, base_delay=0.01)
        assert result == "ok"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_success_after_retries(self):
        from policyshield.approval.retry import retry_with_backoff

        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("fail")
            return "ok"

        result = await retry_with_backoff(fn, max_retries=3, base_delay=0.01)
        assert result == "ok"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_exhausts_retries(self):
        from policyshield.approval.retry import retry_with_backoff

        async def fn():
            raise ValueError("always fails")

        with pytest.raises(ValueError, match="always fails"):
            await retry_with_backoff(fn, max_retries=2, base_delay=0.01)


# ── 501: SDK Client ────────────────────────────────────────────────

class TestSDKClient:
    def test_check_via_sdk(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: t\nversion: '1'\nrules:\n  - id: r1\n    when: { tool: safe }\n    then: ALLOW\n")
        engine = AsyncShieldEngine(rules=rules)
        app = create_app(engine)

        from policyshield.sdk.client import PolicyShieldClient

        with TestClient(app) as tc:
            # Monkey-patch SDK client to use test transport
            client = PolicyShieldClient.__new__(PolicyShieldClient)
            client._client = tc
            result = client.check("safe")
            assert result.verdict == "ALLOW"

    def test_health_via_sdk(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: t\nversion: '1'\nrules:\n  - id: r1\n    when: { tool: x }\n    then: ALLOW\n")
        engine = AsyncShieldEngine(rules=rules)
        app = create_app(engine)

        from policyshield.sdk.client import PolicyShieldClient

        with TestClient(app) as tc:
            client = PolicyShieldClient.__new__(PolicyShieldClient)
            client._client = tc
            data = client.health()
            assert "shield_name" in data
