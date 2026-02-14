# OpenClaw Integration

PolicyShield integrates natively with [OpenClaw](https://github.com/AgenturAI/OpenClaw) through a TypeScript plugin and an HTTP server.

## Architecture

```
┌─────────────────────────────────────┐
│           OpenClaw Agent            │
│                                     │
│   LLM → tool_call(name, args)       │
│              │                      │
│              ▼                      │
│   ┌──────────────────────────┐      │
│   │  PolicyShield Plugin     │      │
│   │  (before/after hooks)    │      │
│   └──────────┬───────────────┘      │
│              │ HTTP                  │
│              ▼                      │
│   ┌──────────────────────────┐      │
│   │  PolicyShield Server     │      │
│   │  (Python + FastAPI)      │      │
│   └──────────────────────────┘      │
└─────────────────────────────────────┘
```

## Setup

### 1. Start the PolicyShield server

```bash
pip install "policyshield[server]"
policyshield server --rules ./rules.yaml --port 8100
```

### 2. Install the OpenClaw plugin

```bash
openclaw plugin install openclaw-plugin-policyshield
```

### 3. Configure in `openclaw.yaml`

```yaml
plugins:
  policyshield:
    url: http://localhost:8100
    mode: enforce        # enforce | audit | disabled
    fail_open: true      # allow calls when server is unreachable
    timeout_ms: 5000
```

## Plugin Hooks

| Hook | When | What it does |
|------|------|-------------|
| `before_tool_call` | Before tool execution | Checks policy → ALLOW, BLOCK, REDACT, or APPROVE |
| `after_tool_call` | After tool execution | Scans output for PII, creates audit record |
| `before_agent_start` | At agent startup | Injects policy constraints into system prompt |

## OpenClaw Preset

Generate rules specifically for OpenClaw:

```bash
policyshield init --preset openclaw
```

This generates 11 rules covering:

- **Block** destructive shell commands (`rm -rf`, `mkfs`, `dd if=`)
- **Block** access to sensitive paths (`/etc/shadow`, SSH keys, `.env`)
- **Redact** PII in web requests, messages, and search
- **Approve** file deletion operations
- **Rate-limit** exec tool (60 calls per session)
- **Rate-limit** web fetch (10 calls per minute)
- **Block** subdomain enumeration

## Modes

| Mode | Behavior |
|------|----------|
| `enforce` | Verdicts are applied: blocked calls fail, PII is redacted |
| `audit` | Verdicts are logged but not applied (shadow mode) |
| `disabled` | Plugin is off, all calls pass through |

## Graceful Degradation

When `fail_open: true` is set:
- If the PolicyShield server is unreachable, tool calls are **allowed** (with a warning logged)
- If there's a timeout, calls are allowed
- All failures are recorded in the audit trail
