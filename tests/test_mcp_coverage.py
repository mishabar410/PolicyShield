"""Tests for MCP Server and Proxy — coverage boost."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _has_mcp():
    try:
        import mcp  # noqa: F401

        return True
    except ImportError:
        return False


@pytest.fixture
def mock_engine():
    """Create a mock AsyncShieldEngine."""
    engine = MagicMock()
    engine.rule_count = 5
    engine.mode = MagicMock(value="ENFORCE")
    engine.is_killed = False

    mock_result = MagicMock()
    mock_result.verdict = MagicMock(value="ALLOW")
    mock_result.message = "Allowed"
    mock_result.rule_id = None
    mock_result.pii_matches = []
    mock_result.modified_args = None
    mock_result.approval_id = None
    engine.check = AsyncMock(return_value=mock_result)

    mock_post = MagicMock()
    mock_post.pii_matches = []
    mock_post.redacted_output = None
    engine.post_check = AsyncMock(return_value=mock_post)
    engine.get_policy_summary = MagicMock(return_value="summary")
    return engine


class TestMCPServerCreation:
    def test_create_without_mcp_raises(self, mock_engine):
        with patch("policyshield.mcp_server.HAS_MCP", False):
            with pytest.raises(ImportError, match="mcp"):
                from policyshield.mcp_server import create_mcp_server

                create_mcp_server(mock_engine)

    def test_create_with_wrong_engine_type(self, mock_engine):
        with patch("policyshield.mcp_server.HAS_MCP", True):
            with pytest.raises(TypeError, match="AsyncShieldEngine"):
                from policyshield.mcp_server import create_mcp_server

                create_mcp_server(mock_engine)


class TestMCPProxyCreation:
    def test_create_without_mcp_raises(self, mock_engine):
        with patch("policyshield.mcp_proxy.HAS_MCP", False):
            with pytest.raises(ImportError, match="mcp"):
                from policyshield.mcp_proxy import create_mcp_proxy_server

                create_mcp_proxy_server(mock_engine)

    def test_mcpproxy_class_init(self, mock_engine):
        from policyshield.mcp_proxy import MCPProxy

        proxy = MCPProxy(engine=mock_engine, upstream_command=["node", "server.js"])
        assert proxy.engine is mock_engine
        assert proxy.upstream_command == ["node", "server.js"]

    @pytest.mark.asyncio
    async def test_mcpproxy_check_block(self, mock_engine):
        from policyshield.mcp_proxy import MCPProxy

        block_result = MagicMock()
        block_result.verdict = MagicMock(value="BLOCK")
        block_result.message = "Blocked by rule"
        block_result.rule_id = "test_rule"
        mock_engine.check = AsyncMock(return_value=block_result)

        proxy = MCPProxy(engine=mock_engine, upstream_command=[])
        result = await proxy.check_and_forward("dangerous_tool", {"cmd": "rm -rf"})
        assert result["blocked"] is True
        assert result["verdict"] == "BLOCK"

    @pytest.mark.asyncio
    async def test_mcpproxy_check_allow(self, mock_engine):
        from policyshield.mcp_proxy import MCPProxy

        allow_result = MagicMock()
        allow_result.verdict = MagicMock(value="ALLOW")
        allow_result.message = ""
        allow_result.modified_args = None
        mock_engine.check = AsyncMock(return_value=allow_result)

        proxy = MCPProxy(engine=mock_engine, upstream_command=[])
        result = await proxy.check_and_forward("safe_tool", {"cmd": "ls"})
        assert result["blocked"] is False
        assert result["verdict"] == "ALLOW"

    @pytest.mark.asyncio
    async def test_mcpproxy_check_approve(self, mock_engine):
        from policyshield.mcp_proxy import MCPProxy

        approve_result = MagicMock()
        approve_result.verdict = MagicMock(value="APPROVE")
        approve_result.message = "Needs approval"
        approve_result.rule_id = "approval_rule"
        mock_engine.check = AsyncMock(return_value=approve_result)

        proxy = MCPProxy(engine=mock_engine, upstream_command=[])
        result = await proxy.check_and_forward("sensitive_tool", {"data": "pii"})
        assert result["blocked"] is False
        assert result["verdict"] == "APPROVE"
        assert result["status"] == "pending_approval"


class TestRemoteRuleLoader:
    def test_init(self):
        from policyshield.shield.remote_loader import RemoteRuleLoader

        loader = RemoteRuleLoader(url="http://example.com/rules.yaml", refresh_interval=60.0)
        assert loader._url == "http://example.com/rules.yaml"
        assert loader._refresh_interval == 60.0

    def test_start_stop(self):
        from policyshield.shield.remote_loader import RemoteRuleLoader

        loader = RemoteRuleLoader(url="http://nonexistent.invalid/rules.yaml", refresh_interval=0.1)
        loader.start()
        assert loader._thread is not None
        loader.stop()
        assert loader._stop_event.is_set()

    def test_fetch_once_error(self):
        from policyshield.shield.remote_loader import RemoteRuleLoader

        loader = RemoteRuleLoader(url="http://nonexistent.invalid/rules.yaml")
        result = loader.fetch_once()
        assert result is None
