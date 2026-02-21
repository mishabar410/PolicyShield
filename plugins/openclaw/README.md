# @policyshield/openclaw-plugin

> 🛡️ PolicyShield plugin for [OpenClaw](https://github.com/AgenturAI/OpenClaw) — blocks dangerous tool calls, redacts PII, and adds human approval to your AI agent.

## Quick Start (2 minutes)

> **Requires:** Python ≥ 3.10, OpenClaw ≥ 2026.2

### 1. Install & start

```bash
pip install "policyshield[server]"
policyshield openclaw setup
```

This single command starts the server, installs the plugin, and configures OpenClaw.

### 2. Verify the integration works

To prove PolicyShield is actually blocking (and not the LLM self-censoring), use the included demo rules that block **harmless** commands like `cat`, `ls`, and `echo`:

```bash
# Stop the server that setup started (it’s running production rules)
policyshield openclaw teardown

# Restart with demo rules that block harmless commands
policyshield server --rules policies/demo-verify.yaml --port 8100
```

<details>
<summary>📄 What’s in demo-verify.yaml</summary>

```yaml
shield_name: demo-verify
version: 1
rules:
  - id: block-cat
    when:
      tool: exec
      args_match:
        command:
          contains: cat
    then: block
    message: "🛡️ PolicyShield blocked 'cat' (demo rule: block-cat)"

  - id: block-ls
    when:
      tool: exec
      args_match:
        command:
          regex: \bls\b
    then: block
    message: "🛡️ PolicyShield blocked 'ls' (demo rule: block-ls)"

default_verdict: allow
```

These rules block `cat` and `ls` — things any LLM would normally run without hesitation.
</details>

Now ask your agent to do something totally harmless:

```bash
# Requires OPENAI_API_KEY (or any provider key configured in OpenClaw)
openclaw agent --local --session-id test \
  -m "Show me the contents of /etc/hosts using cat"
```

**Expected response:**

> "I can't run the `cat` command due to **policy restrictions**."

🎉 **Proof it works!** No LLM would refuse `cat /etc/hosts` on its own — that's PolicyShield blocking it.

### 3. Switch to real security rules

Once verified, stop the demo server (`Ctrl+C`) and switch to the production rules:

```bash
policyshield server --rules policies/rules.yaml --port 8100
```

These rules block things that actually matter:

| Rule | Verdict | Catches |
|------|---------|---------|
| Destructive commands | 🛑 BLOCK | `rm -rf`, `mkfs`, `dd if=`, `chmod 777` |
| Remote code execution | 🛑 BLOCK | `curl \| sh`, `wget \| bash` |
| Secrets exfiltration | 🛑 BLOCK | `curl ... $API_KEY`, `wget ... $SECRET` |
| Environment dumps | 🛑 BLOCK | `env`, `printenv` |
| PII in messages | ✂️ REDACT | Emails, phones, SSNs in outgoing messages |
| PII in file writes | ✂️ REDACT | PII in `write` / `edit` tool calls |
| Sensitive file writes | 🔒 APPROVE | `.env`, `.pem`, `.key`, SSH keys |
| Rate limits | 🛑 BLOCK | >60 exec or >30 web_fetch per session |

---

## How it works

```
  OpenClaw Agent
       │
       │ LLM wants to call tool("exec", {command: "cat /etc/hosts"})
       ▼
  ┌─────────────────────────────┐
  │  PolicyShield Plugin (TS)   │── before_tool_call ──▶ POST /api/v1/check
  │                             │◀── verdict: BLOCK ───  PolicyShield Server
  └─────────────────────────────┘
       │
       ▼
  Tool call BLOCKED — agent tells user it can't do that.
```

| Hook | When | What happens |
|------|------|-------------|
| `before_agent_start` | Session starts | Injects security rules into the LLM system prompt |
| `before_tool_call` | Before every tool call | Checks policy → ALLOW / BLOCK / REDACT / APPROVE |
| `after_tool_call` | After every tool call | Scans tool output for PII leaks |

---

## Verifying without an LLM (curl)

If you don't have an API key, verify the server directly:

```bash
# Should return "verdict": "BLOCK" (with demo rules loaded)
curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "exec", "args": {"command": "cat /etc/hosts"}}' \
  | python3 -m json.tool

# Should return "verdict": "ALLOW" (pwd is not blocked)
curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "exec", "args": {"command": "pwd"}}' \
  | python3 -m json.tool
```

Check plugin status:

```bash
openclaw plugins info policyshield
# → Status: loaded
# → ✓ Connected to PolicyShield server
```

---

## Configuration

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
| `No API key found` | Set `OPENAI_API_KEY` env var, or see [full guide](../../docs/integrations/openclaw.md) |
| `externally-managed-environment` | Use a venv: `python3 -m venv venv && source venv/bin/activate` |
| `Requires-Python >=3.10` | Install Python 3.10+: `brew install python@3.12` |

## Teardown

```bash
policyshield openclaw teardown
```

## Documentation

Full integration guide with Docker, Telegram approvals, and architecture: [docs/integrations/openclaw.md](../../docs/integrations/openclaw.md)

## License

MIT
