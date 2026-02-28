"""MCP Server transport for PolicyShield.

Provides a full MCP-compatible server with tools for checking,
post-checking, kill switch, reload, and constraints queries.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

try:
    from mcp.server import Server  # type: ignore[import-untyped]
    from mcp.types import TextContent, Tool  # type: ignore[import-untyped]

    HAS_MCP = True
except ImportError:
    HAS_MCP = False


def create_mcp_server(engine: Any) -> Any:
    """Create MCP server with PolicyShield tools.

    Requires the ``mcp`` package and an :class:`AsyncShieldEngine`.
    """
    if not HAS_MCP:
        raise ImportError("MCP support requires the 'mcp' package: pip install mcp")

    # Validate engine — MCP handlers are async and require awaitable engine
    from policyshield.shield.async_engine import AsyncShieldEngine

    if not isinstance(engine, AsyncShieldEngine):
        raise TypeError(
            f"MCP server requires AsyncShieldEngine, got {type(engine).__name__}. "
            "Use AsyncShieldEngine or build_async_engine_from_config()."
        )

    server = Server("policyshield")

    @server.list_tools()  # type: ignore[misc]
    async def list_tools() -> list:
        return [
            Tool(
                name="check",
                description="Check a tool call against security rules",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "tool_name": {"type": "string", "description": "Name of the tool to check"},
                        "args": {"type": "object", "description": "Tool arguments"},
                        "session_id": {"type": "string", "description": "Session identifier"},
                        "sender": {"type": "string", "description": "Caller identity"},
                    },
                    "required": ["tool_name"],
                },
            ),
            Tool(
                name="post_check",
                description="Post-call check on tool output for PII/secret detection",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "tool_name": {"type": "string", "description": "Name of the tool"},
                        "result": {"type": "string", "description": "Tool output to scan"},
                        "session_id": {"type": "string", "description": "Session identifier"},
                    },
                    "required": ["tool_name", "result"],
                },
            ),
            Tool(
                name="health",
                description="Check PolicyShield health and get server info",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="kill_switch",
                description="Activate kill switch — block ALL tool calls",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "reason": {"type": "string", "description": "Reason for kill switch activation"},
                    },
                },
            ),
            Tool(
                name="resume",
                description="Deactivate kill switch — resume normal operation",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="reload",
                description="Reload rules from disk",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="constraints",
                description="Get current policy summary / active rule constraints",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()  # type: ignore[misc]
    async def call_tool(name: str, arguments: dict) -> list:
        try:
            if name == "check":
                result = await engine.check(
                    arguments["tool_name"],
                    arguments.get("args", {}),
                    session_id=arguments.get("session_id", "default"),
                    sender=arguments.get("sender"),
                )
                payload: dict[str, Any] = {
                    "verdict": result.verdict.value,
                    "message": result.message,
                    "rule_id": result.rule_id,
                    "pii_types": [m.pii_type.value for m in result.pii_matches],
                }
                if result.modified_args:
                    payload["modified_args"] = result.modified_args
                if result.approval_id:
                    payload["approval_id"] = result.approval_id
                return [TextContent(type="text", text=json.dumps(payload))]

            elif name == "post_check":
                post_result = await engine.post_check(
                    arguments["tool_name"],
                    arguments.get("result", ""),
                    session_id=arguments.get("session_id", "default"),
                )
                post_payload: dict[str, Any] = {
                    "pii_found": len(post_result.pii_matches) > 0,
                    "pii_types": [m.pii_type.value for m in post_result.pii_matches],
                    "redacted_output": post_result.redacted_output,
                }
                return [TextContent(type="text", text=json.dumps(post_payload))]

            elif name == "health":
                info = {
                    "status": "ok",
                    "rules_count": engine.rule_count,
                    "mode": engine.mode.value,
                    "killed": engine.is_killed,
                }
                return [TextContent(type="text", text=json.dumps(info))]

            elif name == "kill_switch":
                reason = arguments.get("reason", "MCP kill switch")
                await asyncio.to_thread(engine.kill, reason)
                return [TextContent(type="text", text=json.dumps({"status": "killed", "reason": reason}))]

            elif name == "resume":
                await asyncio.to_thread(engine.resume)
                return [TextContent(type="text", text=json.dumps({"status": "resumed"}))]

            elif name == "reload":
                await asyncio.to_thread(engine.reload_rules)
                return [
                    TextContent(
                        type="text",
                        text=json.dumps({"status": "ok", "rules_count": engine.rule_count}),
                    )
                ]

            elif name == "constraints":
                summary = engine.get_policy_summary()
                return [TextContent(type="text", text=summary)]

            return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)}))]

    return server
