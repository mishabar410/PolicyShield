# @policyshield/openclaw-plugin

> 🛡️ PolicyShield plugin for [OpenClaw](https://github.com/openclaw/openclaw) — runtime tool call policy enforcement for AI agents.

## What it does

Intercepts every tool call in OpenClaw and enforces declarative YAML-based security policies:

- **BLOCK** — prevent dangerous tool calls (e.g., `rm -rf /`)
- **REDACT** — mask PII before it reaches tools (emails, phones, credit cards)
- **APPROVE** — require human confirmation for sensitive operations
- **ALLOW** — let safe calls through with audit trail

## Quick Start

### 1. Install and start the PolicyShield server

```bash
pip install policyshield[server]
policyshield init --preset openclaw   # creates rules.yaml
policyshield server --rules rules.yaml
```

### 2. Install the OpenClaw plugin

```bash
npm install @policyshield/openclaw-plugin
```

### 3. Configure in `openclaw.yaml`

```yaml
plugins:
  - name: policyshield
    module: "@policyshield/openclaw-plugin"
    config:
      url: "http://localhost:8000"
      mode: "enforce"        # "enforce" | "disabled"
      fail_open: true        # allow calls if server unreachable
      timeout_ms: 5000       # per-check timeout
```

## Features

- 🔒 **Pre-check**: blocks/redacts tool calls before execution
- 📝 **Post-check**: scans tool output for PII leaks
- 🧠 **Prompt enrichment**: injects active rules into agent context
- ⏱️ **Human-in-the-loop**: APPROVE verdict with configurable timeout
- 🛡️ **Fail-open**: graceful degradation when server is down

## Configuration Options

| Option | Default | Description |
|---|---|---|
| `url` | `http://localhost:8000` | PolicyShield server URL |
| `mode` | `enforce` | `enforce` or `disabled` |
| `fail_open` | `true` | Allow calls if server unreachable |
| `timeout_ms` | `5000` | Per-check timeout (ms) |
| `approve_timeout_ms` | `60000` | Max wait for human approval (ms) |
| `approve_poll_interval_ms` | `2000` | Approval polling interval (ms) |
| `max_result_bytes` | `10000` | Max tool output bytes for post-check |

## Documentation

Full documentation: [github.com/policyshield/policyshield](https://github.com/policyshield/policyshield)

## License

MIT
