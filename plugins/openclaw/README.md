# PolicyShield Plugin for OpenClaw

Runtime policy enforcement for AI agent tool calls.

## Installation

```bash
openclaw plugin install openclaw-plugin-policyshield
```

## Prerequisites

PolicyShield server must be running:

```bash
pip install policyshield[server]
policyshield server --rules ./rules.yaml --port 8100
```

## Configuration

In `openclaw.yaml`:

```yaml
plugins:
  policyshield:
    url: http://localhost:8100
    mode: enforce        # enforce | audit | disabled
    fail_open: true      # allow calls when server is down
    timeout_ms: 5000     # HTTP timeout
```

## How It Works

1. **before_tool_call**: Every tool call is checked against your policy rules
2. **BLOCK**: Dangerous operations are stopped before execution
3. **REDACT**: PII is automatically masked in arguments
4. **after_tool_call**: Tool outputs are scanned for PII (audit trail)
5. **before_agent_start**: Active rules are injected into the agent's context

## Modes

| Mode       | Behavior                                                  |
|------------|-----------------------------------------------------------|
| `enforce`  | Block/redact based on rules (default)                     |
| `audit`    | Log verdicts but always allow (for testing)               |
| `disabled` | Skip all checks (pass-through)                            |

## Graceful Degradation

- If the server is unreachable at startup, the plugin logs a warning and continues
- If `fail_open: true` (default), tool calls are allowed when the server is down
- If `fail_open: false`, tool calls are blocked when the server is unreachable

## Development

```bash
cd plugins/openclaw
npm install
npm run build   # compile TypeScript
npm test        # run tests
```
