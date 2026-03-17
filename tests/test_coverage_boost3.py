"""Targeted coverage tests for async_engine, engine edge cases, and mcp_proxy."""

from __future__ import annotations

import textwrap
from unittest.mock import MagicMock, patch

import pytest

from policyshield.core.models import (
    RuleConfig,
    RuleSet,
    ShieldMode,
    Verdict,
)


_RULES_YAML = textwrap.dedent("""\
    shield_name: test
    version: 1
    rules:
      - id: block-exec
        when:
          tool: exec
        then: BLOCK
        message: "exec blocked"
      - id: redact-send
        when:
          tool: send_message
        then: REDACT
        message: "PII redacted"
      - id: approve-deploy
        when:
          tool: deploy
        then: APPROVE
        message: "Needs human approval"
      - id: allow-read
        when:
          tool: read_file
        then: ALLOW
""")


def _make_ruleset():
    return RuleSet(
        shield_name="test",
        version=1,
        rules=[
            RuleConfig(
                id="block-exec",
                when={"tool": "exec"},
                then=Verdict.BLOCK,
                message="exec blocked",
            ),
            RuleConfig(
                id="redact-send",
                when={"tool": "send_message"},
                then=Verdict.REDACT,
                message="PII redacted",
            ),
            RuleConfig(
                id="approve-deploy",
                when={"tool": "deploy"},
                then=Verdict.APPROVE,
                message="Needs approval",
            ),
            RuleConfig(
                id="allow-read",
                when={"tool": "read_file"},
                then=Verdict.ALLOW,
            ),
        ],
    )


# ── AsyncShieldEngine coverage ──────────────────────────────────────


class TestAsyncEngineCheck:
    """Cover async_engine.py check() and _do_check() paths."""

    @pytest.mark.asyncio
    async def test_check_block(self):
        """Cover async check → BLOCK path."""
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset())
        result = await engine.check("exec", {"cmd": "rm -rf /"})
        assert result.verdict == Verdict.BLOCK

    @pytest.mark.asyncio
    async def test_check_allow(self):
        """Cover async check → ALLOW path."""
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset())
        result = await engine.check("read_file", {"path": "/tmp/x"})
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_check_redact(self):
        """Cover async check → REDACT path with PII."""
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset())
        result = await engine.check("send_message", {"text": "Contact john@corp.com"})
        assert result.verdict == Verdict.REDACT
        assert result.modified_args is not None

    @pytest.mark.asyncio
    async def test_check_approve_no_backend(self):
        """Cover async APPROVE with no backend → falls back to BLOCK."""
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset())
        result = await engine.check("deploy", {"env": "prod"})
        assert result.verdict == Verdict.BLOCK
        assert "No approval backend" in result.message

    @pytest.mark.asyncio
    async def test_check_disabled_mode(self):
        """Cover DISABLED mode returns ALLOW immediately."""
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset(), mode=ShieldMode.DISABLED)
        result = await engine.check("exec", {"cmd": "rm -rf /"})
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_check_kill_switch(self):
        """Cover async kill switch path."""
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset())
        engine.kill("test kill")
        result = await engine.check("read_file", {"path": "/tmp"})
        assert result.verdict == Verdict.BLOCK
        assert "test kill" in result.message
        engine.resume()

    @pytest.mark.asyncio
    async def test_check_no_matching_rule(self):
        """Cover no-match → default ALLOW path."""
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset())
        result = await engine.check("unknown_tool", {})
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_check_no_match_default_block(self):
        """Cover no-match → default BLOCK when default_verdict is BLOCK."""
        from policyshield.shield.async_engine import AsyncShieldEngine

        rs = RuleSet(
            shield_name="strict",
            version=1,
            rules=[],
            default_verdict=Verdict.BLOCK,
        )
        engine = AsyncShieldEngine(rs)
        result = await engine.check("anything", {})
        assert result.verdict == Verdict.BLOCK
        assert "Default policy" in result.message

    @pytest.mark.asyncio
    async def test_post_check(self):
        """Cover async post_check."""
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset())
        result = await engine.post_check("exec", "some output")
        assert result.blocked is False

    @pytest.mark.asyncio
    async def test_check_with_otel(self):
        """Cover OTel span_ctx branch."""
        from policyshield.shield.async_engine import AsyncShieldEngine

        mock_otel = MagicMock()
        mock_otel.on_check_start.return_value = "span"
        engine = AsyncShieldEngine(_make_ruleset(), otel_exporter=mock_otel)
        result = await engine.check("read_file", {})
        assert result.verdict == Verdict.ALLOW
        mock_otel.on_check_start.assert_called_once()
        mock_otel.on_check_end.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_fail_open_on_error(self):
        """Cover exception → fail-open ALLOW."""
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset(), fail_open=True)
        with patch.object(engine, "_do_check", side_effect=RuntimeError("boom")):
            result = await engine.check("exec", {})
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_check_fail_closed_on_error(self):
        """Cover exception → fail-closed raises PolicyShieldError."""
        from policyshield.core.exceptions import PolicyShieldError
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset(), fail_open=False)
        with patch.object(engine, "_do_check", side_effect=RuntimeError("boom")):
            with pytest.raises(PolicyShieldError):
                await engine.check("exec", {})

    @pytest.mark.asyncio
    async def test_check_approve_with_backend(self):
        """Cover async APPROVE with a real InMemory backend."""
        from policyshield.approval.memory import InMemoryBackend
        from policyshield.shield.async_engine import AsyncShieldEngine

        backend = InMemoryBackend()
        engine = AsyncShieldEngine(_make_ruleset(), approval_backend=backend)
        result = await engine.check("deploy", {"env": "prod"})
        assert result.verdict == Verdict.APPROVE
        assert result.approval_id is not None


# ── Sync ShieldEngine edge cases ────────────────────────────────────


class TestSyncEngineEdgeCases:
    """Cover uncovered lines in engine.py."""

    def test_no_timeout(self):
        """Cover the no-timeout branch (line 75)."""
        from policyshield.shield.engine import ShieldEngine

        engine = ShieldEngine(_make_ruleset())
        engine._engine_timeout = 0  # Disable timeout
        result = engine.check("read_file", {"path": "/tmp"})
        assert result.verdict == Verdict.ALLOW

    def test_fail_closed_raises_on_timeout(self):
        """Cover fail-closed timeout raises PolicyShieldError (lines 83-84)."""
        from policyshield.core.exceptions import PolicyShieldError
        from policyshield.shield.engine import ShieldEngine
        import concurrent.futures

        engine = ShieldEngine(_make_ruleset(), fail_open=False)
        with patch.object(engine._pool, "submit") as mock_submit:
            mock_future = MagicMock()
            mock_future.result.side_effect = concurrent.futures.TimeoutError()
            mock_submit.return_value = mock_future
            with pytest.raises(PolicyShieldError, match="timed out"):
                engine.check("exec", {})

    def test_fail_closed_raises_on_exception(self):
        """Cover fail-closed exception raises PolicyShieldError (lines 89-90)."""
        from policyshield.core.exceptions import PolicyShieldError
        from policyshield.shield.engine import ShieldEngine

        engine = ShieldEngine(_make_ruleset(), fail_open=False)
        with patch.object(engine, "_do_check_sync", side_effect=RuntimeError("boom")):
            with pytest.raises(PolicyShieldError, match="Shield check failed"):
                engine.check("exec", {})

    def test_otel_integration(self):
        """Cover OTel span start/end (line 96)."""
        from policyshield.shield.engine import ShieldEngine

        mock_otel = MagicMock()
        mock_otel.on_check_start.return_value = "span"
        engine = ShieldEngine(_make_ruleset(), otel_exporter=mock_otel)
        result = engine.check("read_file", {})
        assert result.verdict == Verdict.ALLOW
        mock_otel.on_check_start.assert_called_once()
        mock_otel.on_check_end.assert_called_once()

    def test_post_check(self):
        """Cover post_check method (line 127)."""
        from policyshield.shield.engine import ShieldEngine

        engine = ShieldEngine(_make_ruleset())
        result = engine.post_check("exec", "output text with john@example.com")
        # Should detect PII
        assert len(result.pii_matches) > 0 or result.redacted_output is not None

    def test_shutdown(self):
        """Cover shutdown method (line 29)."""
        from policyshield.shield.engine import ShieldEngine

        engine = ShieldEngine(_make_ruleset())
        engine.shutdown()  # Should not raise


# ── MCPProxy coverage ───────────────────────────────────────────────


class TestMCPProxy:
    """Cover mcp_proxy.py MCPProxy class."""

    @pytest.mark.asyncio
    async def test_check_and_forward_block(self):
        """Cover BLOCK path."""
        from policyshield.mcp_proxy import MCPProxy
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset())
        proxy = MCPProxy(engine, [])
        result = await proxy.check_and_forward("exec", {"cmd": "rm"})
        assert result["blocked"] is True
        assert result["verdict"] == "BLOCK"

    @pytest.mark.asyncio
    async def test_check_and_forward_allow(self):
        """Cover ALLOW path."""
        from policyshield.mcp_proxy import MCPProxy
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset())
        proxy = MCPProxy(engine, [])
        result = await proxy.check_and_forward("read_file", {"path": "/tmp"})
        assert result["blocked"] is False
        assert result["verdict"] == "ALLOW"

    @pytest.mark.asyncio
    async def test_check_and_forward_approve(self):
        """Cover APPROVE path (no backend → engine returns BLOCK)."""
        from policyshield.mcp_proxy import MCPProxy
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset())
        proxy = MCPProxy(engine, [])
        # deploy rule has APPROVE but no backend → engine returns BLOCK
        result = await proxy.check_and_forward("deploy", {"env": "prod"})
        assert result["blocked"] is True

    @pytest.mark.asyncio
    async def test_check_and_forward_redact(self):
        """Cover REDACT path with modified_args."""
        from policyshield.mcp_proxy import MCPProxy
        from policyshield.shield.async_engine import AsyncShieldEngine

        engine = AsyncShieldEngine(_make_ruleset())
        proxy = MCPProxy(engine, [])
        result = await proxy.check_and_forward("send_message", {"text": "SSN: 123-45-6789"})
        assert result["blocked"] is False
        assert result["verdict"] == "REDACT"

    @pytest.mark.asyncio
    async def test_check_and_forward_approve_with_backend(self):
        """Cover APPROVE verdict path through proxy."""
        from policyshield.approval.memory import InMemoryBackend
        from policyshield.mcp_proxy import MCPProxy
        from policyshield.shield.async_engine import AsyncShieldEngine

        backend = InMemoryBackend()
        engine = AsyncShieldEngine(_make_ruleset(), approval_backend=backend)
        proxy = MCPProxy(engine, [])
        result = await proxy.check_and_forward("deploy", {"env": "prod"})
        assert result["blocked"] is False
        assert result["verdict"] == "APPROVE"
        assert result["status"] == "pending_approval"
