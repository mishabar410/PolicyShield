# 502 — MCP Proxy Mode

## Goal

Add `policyshield mcp-proxy` CLI command that wraps an upstream MCP server, intercepting `call_tool` to enforce PolicyShield rules.

## Context

- Current `mcp_server.py` exposes PolicyShield as tools — not as a transparent proxy
- MCP proxy = transparent middleware: client → PolicyShield → upstream MCP server
- Blocks/modifies tool calls before they reach the upstream
- **Value**: 🔥🔥🔥 — enables Claude Code, Cursor, and the entire MCP ecosystem

## Code

### New file: `policyshield/mcp_proxy.py`

```python
"""MCP Proxy — intercepts tool calls and enforces PolicyShield rules."""

class MCPProxy:
    def __init__(self, engine, upstream_command: list[str]):
        self.engine = engine
        self.upstream = upstream_command

    async def handle_call_tool(self, name: str, arguments: dict) -> Any:
        result = await self.engine.check(name, arguments)
        if result.verdict.value == "BLOCK":
            return [TextContent(type="text", text=f"BLOCKED: {result.message}")]
        args = result.modified_args or arguments
        return await self._forward_to_upstream(name, args)
```

### CLI entry: `policyshield mcp-proxy --upstream "stdio://node server.js" --rules rules.yaml`

Add parser in `cli/main.py`, handler launches proxy server.

## Tests

- Test that blocked tools return BLOCKED without forwarding
- Test that allowed tools forward to upstream
- Test that REDACT modifies args before forwarding

## Self-check

```bash
ruff check policyshield/mcp_proxy.py tests/test_mcp_proxy.py
pytest tests/test_mcp_proxy.py -v
```

## Commit

```
feat(mcp): add MCP proxy mode for transparent tool call interception
```
