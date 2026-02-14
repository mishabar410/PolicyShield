# @policyshield/openclaw-plugin

> 🛡️ PolicyShield plugin for [OpenClaw](https://github.com/AgenturAI/OpenClaw) — runtime tool call policy enforcement for AI agents.

> Verified with **OpenClaw 2026.2.13** and **PolicyShield 0.8.1**.

## What it does

Intercepts every tool call in OpenClaw and enforces declarative YAML-based security policies:

- **BLOCK** — prevent dangerous tool calls (e.g., `rm -rf /`, `curl | sh`)
- **REDACT** — mask PII before it reaches tools (emails, phones, credit cards)
- **APPROVE** — require human confirmation for sensitive operations
- **ALLOW** — let safe calls through with audit trail

## Quick Start

### 1. Start the PolicyShield server

```bash
pip install "policyshield[server]"
policyshield init --preset openclaw --no-interactive  # → rules.yaml
policyshield server --rules rules.yaml --port 8100
```

Verify: `curl http://localhost:8100/api/v1/health`

### 2. Install the plugin into OpenClaw

```bash
openclaw plugins install @policyshield/openclaw-plugin
```

### 3. Configure the server URL

```bash
openclaw config set plugins.entries.policyshield.config.url http://localhost:8100
```

### 4. Verify the plugin is loaded

```bash
openclaw plugins info policyshield
# → Status: loaded
# → ✓ Connected to PolicyShield server
```

### 5. Test it

```bash
openclaw agent --local --session-id test -m "Run: rm -rf /"
# → "I'm unable to execute that command as it is considered destructive
#    and is blocked by policy."
```

## Plugin Hooks

| Hook | When | What it does |
|------|------|-------------|
| `before_agent_start` | Agent session starts | Injects all active policy rules into the LLM system prompt |
| `before_tool_call` | Before every tool call | Checks policy → ALLOW, BLOCK, REDACT, or APPROVE |
| `after_tool_call` | After every tool call | Scans tool output for PII leaks |

## Features

- 🔒 **Pre-check**: blocks/redacts tool calls before execution
- 📝 **Post-check**: scans tool output for PII leaks
- 🧠 **Prompt enrichment**: injects active rules into agent context
- ⏱️ **Human-in-the-loop**: APPROVE verdict with configurable timeout and polling
- 🛡️ **Fail-open**: graceful degradation when server is down

## Configuration

Set options via the OpenClaw CLI:

```bash
openclaw config set plugins.entries.policyshield.config.<key> <value>
```

| Key | Default | Description |
|-----|---------|-------------|
| `url` | `http://localhost:8100` | PolicyShield server URL |
| `mode` | `enforce` | `enforce` or `disabled` |
| `fail_open` | `true` | Allow calls if server unreachable |
| `timeout_ms` | `5000` | Per-check timeout (ms) |
| `approve_timeout_ms` | `60000` | Max wait for human approval (ms) |
| `approve_poll_interval_ms` | `2000` | Approval polling interval (ms) |
| `max_result_bytes` | `10000` | Max tool output bytes for post-check |

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `⚠ PolicyShield server unreachable` | Check server is running: `curl http://localhost:8100/api/v1/health` |
| `plugin id mismatch` warning | Cosmetic — rename `~/.openclaw/extensions/openclaw-plugin` to `policyshield` |
| `No API key found` | Set model + auth profile (see [full guide](../../docs/integrations/openclaw.md)) |

## Documentation

Full integration guide: [docs/integrations/openclaw.md](../../docs/integrations/openclaw.md)

## License

MIT
