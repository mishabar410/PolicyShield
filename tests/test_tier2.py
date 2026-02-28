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
    rules.write_text(
        rules_yaml
        or """
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
"""
    )
    return ShieldEngine(rules=rules)


def _make_async_engine(tmp_path, rules_yaml=None):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        rules_yaml
        or """
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
"""
    )
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

        with pytest.raises(PermissionError, match="PolicyShield blocked"):
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

        with pytest.raises(PermissionError, match="PolicyShield blocked"):
            await async_exec()


# ── 513: Dry-run CLI ────────────────────────────────────────────────


class TestDryRunCLI:
    def test_check_allow(self, tmp_path):
        from policyshield.cli.main import app

        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "shield_name: t\nversion: '1'\nrules:\n  - id: r1\n    when: { tool: safe }\n    then: ALLOW\n"
        )
        code = app(["check", "--tool", "safe", "--rules", str(rules)])
        assert code == 0

    def test_check_block_exit_2(self, tmp_path):
        from policyshield.cli.main import app

        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "shield_name: t\nversion: '1'\nrules:\n  - id: r1\n    when: { tool: bad }\n    then: BLOCK\n    message: blocked\n"
        )
        code = app(["check", "--tool", "bad", "--rules", str(rules)])
        assert code == 2

    def test_check_json_output(self, tmp_path, capsys):
        from policyshield.cli.main import app

        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "shield_name: t\nversion: '1'\nrules:\n  - id: r1\n    when: { tool: safe }\n    then: ALLOW\n"
        )
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
        rules.write_text(
            "shield_name: t\nversion: '1'\nrules:\n  - id: r1\n    when: { tool: safe }\n    then: ALLOW\n"
        )
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

    def test_kill_and_resume_via_sdk(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: t\nversion: '1'\nrules:\n  - id: r1\n    when: { tool: x }\n    then: ALLOW\n")
        engine = AsyncShieldEngine(rules=rules)
        app = create_app(engine)

        from policyshield.sdk.client import PolicyShieldClient

        with TestClient(app) as tc:
            client = PolicyShieldClient.__new__(PolicyShieldClient)
            client._client = tc
            data = client.kill("test reason")
            assert data.get("status") == "killed"
            data = client.resume()
            assert data.get("status") == "resumed"

    def test_reload_via_sdk(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: t\nversion: '1'\nrules:\n  - id: r1\n    when: { tool: x }\n    then: ALLOW\n")
        engine = AsyncShieldEngine(rules=rules)
        app = create_app(engine)

        from policyshield.sdk.client import PolicyShieldClient

        with TestClient(app) as tc:
            client = PolicyShieldClient.__new__(PolicyShieldClient)
            client._client = tc
            data = client.reload()
            assert "rules_count" in data or "status" in data

    def test_post_check_via_sdk(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: t\nversion: '1'\nrules:\n  - id: r1\n    when: { tool: x }\n    then: ALLOW\n")
        engine = AsyncShieldEngine(rules=rules)
        app = create_app(engine)

        from policyshield.sdk.client import PolicyShieldClient

        with TestClient(app) as tc:
            client = PolicyShieldClient.__new__(PolicyShieldClient)
            client._client = tc
            data = client.post_check("x", "some result text")
            assert isinstance(data, dict)

    def test_check_result_fields(self):
        from policyshield.sdk.client import CheckResult

        r = CheckResult(verdict="ALLOW", message="ok", rule_id="r1", shield_version="0.11.0")
        assert r.verdict == "ALLOW"
        assert r.shield_version == "0.11.0"
        assert r.pii_types == []

    def test_client_context_manager(self):
        from policyshield.sdk.client import PolicyShieldClient

        # Just verify it instantiates and closes without error
        client = PolicyShieldClient("http://localhost:19999")
        client.close()


# ── 533: Slack Backend ─────────────────────────────────────────────


class TestSlackBackend:
    def test_slack_health(self):
        from policyshield.approval.slack import SlackApprovalBackend

        backend = SlackApprovalBackend(webhook_url="https://hooks.slack.com/test")
        h = backend.health()
        assert h["healthy"] is True
        assert h["backend"] == "slack"

    def test_slack_submit_and_pending(self):
        from policyshield.approval.base import ApprovalRequest
        from policyshield.approval.slack import SlackApprovalBackend

        backend = SlackApprovalBackend(webhook_url="https://hooks.slack.com/test")
        req = ApprovalRequest.create(
            tool_name="test_tool",
            args={"key": "value"},
            rule_id="r1",
            message="test",
            session_id="s1",
        )
        # submit will fail to send to Slack (no real webhook), but stores in memory
        backend.submit(req)
        pending = backend.pending()
        assert len(pending) == 1
        assert pending[0].tool_name == "test_tool"

    def test_slack_respond(self):
        from policyshield.approval.base import ApprovalRequest
        from policyshield.approval.slack import SlackApprovalBackend

        backend = SlackApprovalBackend(webhook_url="https://hooks.slack.com/test")
        req = ApprovalRequest.create(tool_name="t", args={}, rule_id="r1", message="m", session_id="s1")
        backend.submit(req)
        backend.respond(req.request_id, approved=True, responder="admin")
        assert len(backend.pending()) == 0


# ── 502: MCP Proxy ─────────────────────────────────────────────────


class TestMCPProxy:
    @pytest.mark.asyncio
    async def test_proxy_blocks(self, tmp_path):
        from policyshield.mcp_proxy import MCPProxy

        engine = _make_async_engine(tmp_path)
        proxy = MCPProxy(engine, [])
        result = await proxy.check_and_forward("exec_command", {"cmd": "rm -rf /"})
        assert result["blocked"] is True
        assert result["verdict"] == "BLOCK"

    @pytest.mark.asyncio
    async def test_proxy_allows(self, tmp_path):
        from policyshield.mcp_proxy import MCPProxy

        engine = _make_async_engine(tmp_path)
        proxy = MCPProxy(engine, [])
        result = await proxy.check_and_forward("read_file", {"path": "/tmp"})
        assert result["blocked"] is False
        assert result["verdict"] == "ALLOW"

    def test_proxy_server_creation(self, tmp_path):
        """Test that create_mcp_proxy_server doesn't crash (MCP may not be installed)."""
        from policyshield.mcp_proxy import HAS_MCP

        if not HAS_MCP:
            pytest.skip("MCP not installed")
        from policyshield.mcp_proxy import create_mcp_proxy_server

        engine = _make_async_engine(tmp_path)
        server = create_mcp_proxy_server(engine)
        assert server is not None


# ── 512: Quickstart ────────────────────────────────────────────────


class TestQuickstart:
    def test_generate_rules_custom(self):
        from policyshield.cli.quickstart import _generate_rules

        rules_yaml = _generate_rules(["read_file", "exec_command"], "block", "custom")
        assert "shield_name: quickstart-shield" in rules_yaml
        assert "default_verdict: BLOCK" in rules_yaml
        assert "read_file" in rules_yaml
        assert "exec_command" in rules_yaml

    def test_generate_rules_preset(self):
        from policyshield.cli.quickstart import _generate_rules

        rules_yaml = _generate_rules([], "block", "coding-agent")
        assert "coding-agent" in rules_yaml

    def test_discover_openclaw_tools_no_server(self):
        from policyshield.cli.quickstart import _discover_openclaw_tools

        # No OpenClaw running → returns empty list
        tools = _discover_openclaw_tools()
        assert tools == []


# ── 531: ENV Config ────────────────────────────────────────────────


class TestENVConfig:
    def test_default_settings(self):
        from policyshield.config.settings import PolicyShieldSettings

        s = PolicyShieldSettings()
        assert s.mode == "enforce"
        assert s.rules_path == "policies/rules.yaml"
        assert s.fail_open is False
        assert s.trace_dir == "./traces"
        assert s.trace_privacy is False
        assert s.approval_timeout == 60.0
        assert s.telegram_token is None
        assert s.slack_webhook_url is None

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_MODE", "audit")
        monkeypatch.setenv("POLICYSHIELD_FAIL_OPEN", "true")
        monkeypatch.setenv("POLICYSHIELD_APPROVAL_TIMEOUT", "120")
        from policyshield.config.settings import PolicyShieldSettings

        s = PolicyShieldSettings()
        assert s.mode == "audit"
        assert s.fail_open is True
        assert s.approval_timeout == 120.0
