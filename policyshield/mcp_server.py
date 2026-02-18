"""MCP Server transport for PolicyShield."""

from __future__ import annotations

from typing import Any

try:
    from mcp.server import Server  # type: ignore[import-untyped]
    from mcp.types import TextContent, Tool  # type: ignore[import-untyped]

    HAS_MCP = True
except ImportError:
    HAS_MCP = False


def create_mcp_server(engine: Any) -> Any:
    """Create MCP server with PolicyShield tools.

    Requires the ``mcp`` package: ``pip install mcp``.
    """
    if not HAS_MCP:
        raise ImportError("MCP support requires the 'mcp' package: pip install mcp")

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
                        "tool_name": {"type": "string"},
                        "args": {"type": "object"},
                    },
                    "required": ["tool_name"],
                },
            ),
            Tool(
                name="health",
                description="Check PolicyShield health",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()  # type: ignore[misc]
    async def call_tool(name: str, arguments: dict) -> list:
        if name == "check":
            result = await engine.check(arguments["tool_name"], arguments.get("args", {}))
            return [
                TextContent(
                    type="text",
                    text=f"verdict: {result.verdict.value}",
                )
            ]
        elif name == "health":
            return [TextContent(type="text", text="ok")]
        return [TextContent(type="text", text="unknown tool")]

    return server
