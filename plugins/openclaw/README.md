# PolicyShield Plugin for OpenClaw

Runtime policy enforcement for AI agent tool calls — block, redact, approve, allow.

## Quick Start

### 1. Install

```bash
npm install @policyshield/openclaw-plugin
```

### 2. Configure

Add to your `openclaw.yaml`:

```yaml
plugins:
  policyshield:
    url: "http://localhost:8100"
    mode: "enforce"
    fail_open: true
```

### 3. Run

Start the PolicyShield server, then launch OpenClaw as usual. The plugin auto-registers.

---

## How It Works

| Hook | Action |
|------|--------|
| `before_tool_call` | Checks tool call against policy rules → **BLOCK**, **REDACT**, **APPROVE**, or **ALLOW** |
| `after_tool_call` | Scans tool output for PII via post-check |
| `before_agent_start` | Injects active policy constraints into agent context |

## Configuration Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `url` | string | `http://localhost:8100` | PolicyShield server URL |
| `mode` | string | `enforce` | `enforce` or `disabled` (audit is server-side) |
| `fail_open` | boolean | `true` | Allow tool calls when server is unreachable |
| `timeout_ms` | number | `5000` | HTTP request timeout (ms) |
| `approve_timeout_ms` | number | `60000` | Max wait for human approval (ms) |
| `approve_poll_interval_ms` | number | `2000` | Polling interval for approval status (ms) |
| `max_result_bytes` | number | `10000` | Max bytes of tool output sent for PII scan |

## Graceful Degradation

- **`fail_open: true`** (default) — Tool calls proceed with a warning if server is unreachable.
- **`fail_open: false`** — All tool calls are blocked until the server recovers.

## Development

```bash
npm test             # Run tests
npm run typecheck    # Type check
npm run build        # Build to dist/
```

## Requirements

- OpenClaw (any recent version)
- PolicyShield server running at configured URL
- Node.js 18+
