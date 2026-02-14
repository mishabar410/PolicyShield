# PolicyShield Plugin for OpenClaw

Runtime policy enforcement for AI agent tool calls — block, redact, audit, approve.

## Installation

Place this extension in your OpenClaw workspace's `extensions/` directory, or install via the plugin registry once published.

```
extensions/
  policyshield/
    index.ts
    src/
    openclaw.plugin.json
    package.json
```

## Configuration

Add to your OpenClaw config (`openclaw.yaml` or UI):

```yaml
plugins:
  policyshield:
    url: "http://localhost:8100"      # PolicyShield server URL
    mode: "enforce"                    # enforce | audit | disabled
    fail_open: true                    # allow tool calls when server is unreachable
    timeout_ms: 5000                   # HTTP request timeout
```

## How It Works

The plugin hooks into three OpenClaw lifecycle events:

| Hook | What it does |
|------|-------------|
| `before_tool_call` | Checks the tool call against PolicyShield rules. Can **BLOCK**, **REDACT** parameters, require **APPROVE** (human-in-the-loop), or **ALLOW**. |
| `after_tool_call` | Scans tool output for PII via the PolicyShield post-check API. |
| `before_agent_start` | Injects active policy constraints into the agent's context. |

## Modes

- **`enforce`** — Full enforcement. BLOCK/REDACT/APPROVE verdicts are applied.
- **`audit`** — Logs verdicts but always allows tool calls (shadow mode).
- **`disabled`** — Plugin does nothing (ALLOW everything).

## Graceful Degradation

If the PolicyShield server is unreachable:
- **`fail_open: true`** (default) — Tool calls proceed with a warning logged.
- **`fail_open: false`** — All tool calls are blocked until the server recovers.

## Development

```bash
# Run tests
npm test

# Type check
npx tsc --noEmit

# Build
npm run build
```

## Requirements

- OpenClaw (any recent version)
- PolicyShield server running at the configured URL
- Node.js 18+ (for `fetch` and `AbortSignal.timeout`)
