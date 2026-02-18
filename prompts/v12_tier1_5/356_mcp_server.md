# Prompt 356 — MCP Server Integration

## Цель

Добавить MCP (Model Context Protocol) server transport: PolicyShield как MCP tool server для AI Agent frameworks.

## Контекст

- MCP — стандарт для AI agents → tools → servers (Anthropic spec)
- Нужно: `policyshield serve --transport mcp` → MCP-совместимый stdio server
- Expose `check`, `health`, `reload` как MCP tools

## Что сделать

```python
# policyshield/mcp_server.py
"""MCP Server transport for PolicyShield."""

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    HAS_MCP = True
except ImportError:
    HAS_MCP = False

def create_mcp_server(engine) -> "Server":
    """Create MCP server with PolicyShield tools."""
    if not HAS_MCP:
        raise ImportError("Install mcp package: pip install mcp")

    server = Server("policyshield")

    @server.list_tools()
    async def list_tools():
        return [
            Tool(name="check", description="Check a tool call against security rules",
                 inputSchema={"type": "object", "properties": {
                     "tool_name": {"type": "string"},
                     "args": {"type": "object"},
                 }, "required": ["tool_name"]}),
            Tool(name="health", description="Check PolicyShield health",
                 inputSchema={"type": "object", "properties": {}}),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        if name == "check":
            result = await engine.check(arguments["tool_name"], arguments.get("args", {}))
            return [TextContent(type="text", text=f"verdict: {result.verdict.value}")]
        elif name == "health":
            return [TextContent(type="text", text="ok")]

    return server
```

## Тесты

```python
class TestMCPServer:
    @pytest.mark.skipif(not HAS_MCP, reason="mcp not installed")
    def test_mcp_server_creates(self, engine):
        from policyshield.mcp_server import create_mcp_server
        server = create_mcp_server(engine)
        assert server is not None
```

## Самопроверка

```bash
pytest tests/test_dx.py::TestMCPServer -v
pytest tests/ -q
```

## Коммит

```
feat: add MCP server transport (policyshield serve --transport mcp)
```
