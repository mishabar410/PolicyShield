# MCP Integration

PolicyShield supports the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) — both as a standalone MCP server and as a transparent proxy that wraps an existing MCP server with policy enforcement.

## MCP Server

Expose PolicyShield as an MCP server so that MCP-compatible clients (Claude Desktop, Cursor, etc.) can use policy checking as a tool.

```python
from policyshield.shield.async_engine import AsyncShieldEngine
from policyshield.mcp_server import create_mcp_server

engine = AsyncShieldEngine(rules="rules.yaml")
server = create_mcp_server(engine, admin_token="secret-token")
```

### Admin authentication

Admin commands (`kill_switch`, `resume`, `reload`) require a valid `admin_token`. This prevents unauthorized clients from disabling policy enforcement.

## MCP Proxy

Wrap an existing MCP server with policy enforcement. Every tool call is checked against your rules before being forwarded upstream.

```python
from policyshield.shield.async_engine import AsyncShieldEngine
from policyshield.mcp_proxy import MCPProxy

engine = AsyncShieldEngine(rules="rules.yaml")

proxy = MCPProxy(engine=engine, upstream_command=["node", "my-mcp-server.js"])
result = await proxy.check_and_forward("exec", {"command": "rm -rf /"})
# → {"blocked": True, "verdict": "BLOCK"}
```

### Verdicts

| Upstream verdict | PolicyShield verdict | Result |
|------------------|---------------------|--------|
| — | **BLOCK** | Tool call blocked, upstream never called |
| — | **ALLOW** | Tool call forwarded to upstream |
| — | **REDACT** | Args redacted, then forwarded |
| — | **APPROVE** | Held for human approval |

## Standalone MCP proxy server

```python
from policyshield.mcp_proxy import create_mcp_proxy_server

server = create_mcp_proxy_server(engine, upstream_command=["node", "server.js"])
```

> **Note:** The proxy's `list_tools` currently returns tools derived from PolicyShield rules, not the upstream server's tool list. This is a known limitation.
