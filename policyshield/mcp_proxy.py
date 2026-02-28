"""MCP Proxy — intercepts tool calls from upstream MCP servers.

Sits between an MCP client (e.g. Claude Code) and an upstream MCP server,
enforcing PolicyShield rules on every tool call.

.. note::
    This is currently a **check-only** proxy — it evaluates PolicyShield rules
    but does not forward calls to an actual upstream MCP process.  The upstream
    command infrastructure is reserved for a future release.

Usage:
    policyshield mcp-proxy --upstream "node server.js" --rules rules.yaml
"""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

try:
    from mcp.server import Server
    from mcp.types import TextContent, Tool

    HAS_MCP = True
except ImportError:
    HAS_MCP = False


class MCPProxy:
    """Transparent MCP proxy that enforces PolicyShield rules.

    Forwards tool calls to an upstream MCP server after checking
    with PolicyShield. Blocks/modifies calls as needed.

    Args:
        engine: AsyncShieldEngine instance.
        upstream_command: Command to start the upstream MCP server.
    """

    def __init__(self, engine: Any, upstream_command: list[str]) -> None:
        self.engine = engine
        self.upstream_command = upstream_command
        self._upstream_proc: subprocess.Popen | None = None

    async def check_and_forward(
        self,
        tool_name: str,
        arguments: dict,
        session_id: str = "mcp-proxy",
    ) -> dict:
        """Check tool call, then forward if allowed."""
        result = await self.engine.check(tool_name, arguments, session_id=session_id)

        if result.verdict.value == "BLOCK":
            return {
                "blocked": True,
                "verdict": "BLOCK",
                "message": result.message,
                "rule_id": result.rule_id,
            }

        # Use modified args if REDACT
        final_args = result.modified_args if result.modified_args else arguments

        return {
            "blocked": False,
            "verdict": result.verdict.value,
            "tool_name": tool_name,
            "args": final_args,
            "message": result.message,
        }


def create_mcp_proxy_server(engine: Any) -> Any:
    """Create an MCP server that proxies tool calls through PolicyShield.

    This creates a transparent proxy: it lists all tools from the upstream
    server, but intercepts ``call_tool`` to enforce PolicyShield rules.

    Args:
        engine: AsyncShieldEngine with loaded rules.

    Returns:
        An MCP Server instance.
    """
    if not HAS_MCP:
        raise ImportError("MCP proxy requires the 'mcp' package: pip install mcp")

    server = Server("policyshield-proxy")
    proxy = MCPProxy(engine, [])

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict | None) -> list:
        args = arguments or {}
        result = await proxy.check_and_forward(name, args)

        if result.get("blocked"):
            return [TextContent(type="text", text=f"🛡️ BLOCKED: {result['message']}")]

        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {"status": "forwarded", "tool": name, "verdict": result["verdict"]},
                    indent=2,
                ),
            )
        ]

    @server.list_tools()
    async def handle_list_tools() -> list[Tool]:
        """List tools from the engine's ruleset."""
        tools = []
        for rule in engine.rules.rules:
            tool_pattern = rule.when.get("tool") if isinstance(rule.when, dict) else None
            if tool_pattern and tool_pattern != "*":
                tools.append(
                    Tool(
                        name=tool_pattern,
                        description=f"[PolicyShield: {rule.then.value}] {rule.message or rule.id}",
                        inputSchema={"type": "object"},
                    )
                )
        return tools

    return server
