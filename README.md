# 🛡️ PolicyShield

<p align="center">
  <img src="demo.gif" alt="PolicyShield Demo" width="700">
</p>

**AI agents can `rm -rf /`, leak your database, and run up a $10k API bill — all in one session.**

PolicyShield is a runtime firewall that sits between the LLM and the tools it calls. Write rules in YAML — PolicyShield enforces them before any tool executes.

```
   LLM → exec("rm -rf /")          → BLOCKED ✅  tool never runs
   LLM → send("SSN: 123-45-6789")  → REDACTED ✅ send("SSN: [SSN]")
   LLM → deploy("prod")            → APPROVE ✅  human reviews first
```

[![PyPI](https://img.shields.io/pypi/v/policyshield?color=blue)](https://pypi.org/project/policyshield/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/mishabar410/PolicyShield/actions/workflows/ci.yml/badge.svg)](https://github.com/mishabar410/PolicyShield/actions/workflows/ci.yml)
[![1500+ tests](https://img.shields.io/badge/tests-1500%2B-brightgreen.svg)](#development)

---

## ⚡ Quick Start (30 seconds)

```bash
pip install policyshield
```

Create `rules.yaml`:

```yaml
rules:
  - id: no-delete
    when: { tool: delete_file }
    then: block
    message: "File deletion is not allowed."

  - id: redact-pii
    when: { tool: send_message }
    then: redact
    message: "PII redacted before sending."
```

Use it:

```python
from policyshield.shield.engine import ShieldEngine

engine = ShieldEngine(rules="rules.yaml")

result = engine.check("delete_file", {"path": "/data"})
# → Verdict.BLOCK — "File deletion is not allowed."

result = engine.check("send_message", {"text": "Email john@corp.com"})
# → Verdict.REDACT — modified_args: {"text": "Email [EMAIL]"}
```

That's it. No agent rewrites. Works with any framework.

---

## 🔌 OpenClaw Integration (Step-by-Step)

PolicyShield plugs into [OpenClaw](https://github.com/openclaw/openclaw) as a native plugin. Every tool call the AI agent makes goes through PolicyShield first — BLOCK, REDACT, APPROVE, or ALLOW. You also get `/policyshield` commands in Telegram/Discord/Slack.

### 1. Start the PolicyShield server

```bash
pip install policyshield
policyshield server --rules rules.yaml --port 8100
```

The server runs on `http://localhost:8100` and exposes the REST API that the OpenClaw plugin calls.

### 2. Install the plugin into OpenClaw

From the PolicyShield repo:

```bash
cd plugins/openclaw
npm install && npm run build
```

Or install from npm:

```bash
openclaw plugins install @policyshield/openclaw-plugin
```

### 3. Configure `openclaw.json`

Add the plugin path and config to your OpenClaw config file:

```json5
{
  // your existing config...
  "plugins": {
    "enabled": true,
    "load": {
      // point to the built plugin directory
      "paths": ["/path/to/PolicyShield/plugins/openclaw"]
    },
    "entries": {
      "policyshield": {
        "enabled": true,
        "config": {
          "url": "http://localhost:8100",  // PolicyShield server
          "mode": "enforce",               // "enforce" or "disabled"
          "fail_open": true,               // allow calls if server is down
          "timeout_ms": 5000               // per-check timeout
        }
      }
    }
  }
}
```

### 4. Start the OpenClaw gateway

```bash
OPENAI_API_KEY="sk-..." openclaw gateway
```

Look for these lines in the output:

```
[gateway] ✓ Connected to PolicyShield server
[gateway] agent model: openai/gpt-4o
[telegram] starting provider (@yourbot)
```

### How it works

```
  User → OpenClaw Agent → LLM wants to call tool("exec", {command: "rm -rf /"})
                              │
                              ▼
                    ┌─────────────────────────┐
                    │ PolicyShield Plugin (TS)│─ before_tool_call → POST /api/v1/check
                    │                         │← verdict: BLOCK ──  PolicyShield Server
                    └─────────────────────────┘
                              │
                              ▼
                    Tool call BLOCKED — agent tells user it can't do that.
```

| Hook | When | What happens |
|------|------|-------------|
| `before_agent_start` | Session starts | Injects active rules into LLM context |
| `before_tool_call` | Before every tool call | Checks policy → ALLOW / BLOCK / REDACT / APPROVE |
| `after_tool_call` | After every tool call | Scans tool output for PII leaks |

### `/policyshield` commands (Telegram / Discord / Slack)

These work directly in chat — no CLI needed:

```
/policyshield status                → server health + rules count
/policyshield rules                 → view active rules
/policyshield kill                  → 🔴 emergency stop — blocks ALL tool calls
/policyshield resume                → 🟢 resume normal operation
/policyshield reload                → hot-reload rules from disk
/policyshield compile <description> → preview YAML from natural language
/policyshield apply <description>   → compile + save + reload in one step
```

### Live demo

```
You:    /policyshield kill
Bot:    🛡️ PolicyShield: 🔴 KILLED — all tool calls blocked

You:    Create a file test.txt
Bot:    I can't do that — all operations are blocked by PolicyShield.

You:    /policyshield resume
Bot:    🛡️ PolicyShield: 🟢 Resumed — normal operation
```

### Plugin config reference

| Key | Default | Description |
|-----|---------|-------------|
| `url` | `http://localhost:8100` | PolicyShield server URL |
| `mode` | `enforce` | `enforce` or `disabled` |
| `fail_open` | `true` | Allow calls if server unreachable |
| `timeout_ms` | `5000` | Per-check timeout (ms) |
| `approve_timeout_ms` | `60000` | Max wait for human approval (ms) |
| `approve_poll_interval_ms` | `2000` | Approval polling interval (ms) |
| `max_result_bytes` | `10000` | Max tool output bytes for PII scan |
| `api_token` | `""` | Bearer token for server auth |

[Full plugin README](plugins/openclaw/README.md) · [Integration docs](docs/integrations/openclaw.md)

---

## 🤖 Telegram Bot

Manage PolicyShield directly from Telegram — compile rules from natural language, deploy with one tap, and control the kill switch from your phone.

### Setup

```bash
pip install "policyshield[server]"
export TELEGRAM_BOT_TOKEN="your-bot-token"
export OPENAI_API_KEY="your-api-key"

policyshield bot --rules rules.yaml --server-url http://localhost:8100
```

### Natural Language → Live Rules

Send a plain-text policy description and the bot compiles it to validated YAML, shows a preview, and deploys on confirmation:

```
You:  Block all exec calls containing 'rm' and redact PII in send_message

Bot:  📜 Generated YAML:
      - id: block-rm-commands
        when:
          tool: exec
          args_match:
            command: { contains: rm }
        then: block
        ...
      [✅ Deploy] [❌ Cancel]
```

Tap **Deploy** — the bot atomically writes rules, merges by ID (no duplicates), backs up the old file, and hot-reloads the engine.

### Management Commands

```
/status          # Server health, rules count, mode
/rules           # View active rules summary
/kill [reason]   # Emergency kill switch — blocks ALL tool calls
/resume          # Resume normal operation
/reload          # Hot-reload rules from disk
/compile <desc>  # Preview YAML from natural language
/apply <desc>    # Compile + save + reload in one step
```

`/apply` is the most powerful command — it generates rules via LLM, replaces conflicting rules for the same tool, and reloads the engine in one step.

### OpenClaw + Telegram

With the OpenClaw plugin installed, use `/policyshield` commands directly in your OpenClaw Telegram chat:

```
/policyshield status
/policyshield apply "Block file deletions and limit web_fetch to 30 per session"
```

---

## 🔥 Core Features

### 🧱 YAML Rules — No Code Changes

Regex, glob, exact match, session conditions, chains — all in declarative YAML. The LLM never touches your rules.

```yaml
- id: block-shell-injection
  when:
    tool: exec
    args_match:
      command: { regex: "rm\\s+-rf|curl.*\\|\\s*bash" }
  then: block
  severity: critical
```

### 🔍 Built-in PII Detection + Redaction

EMAIL, PHONE, CREDIT_CARD, SSN, IBAN, IP, PASSPORT, DOB — detected and redacted automatically. Add custom patterns in 2 lines.

### 🚨 Kill Switch

One command blocks **every** tool call instantly. Resume when you're ready.

```bash
policyshield kill --reason "Incident response"
policyshield resume
```

### 🔗 Chain Rules — Catch Multi-Step Attacks

Detect temporal patterns like data exfiltration: `read_database` → `send_email` within 2 minutes.

```yaml
- id: anti-exfiltration
  when:
    tool: send_email
    chain:
      - tool: read_database
        within_seconds: 120
  then: block
  severity: critical
```

### 🕐 Conditional Rules

Block based on time, day, user role, or any custom context:

```yaml
- id: no-deploy-weekends
  when:
    tool: deploy
    context:
      day_of_week: "!Mon-Fri"
  then: block
  message: "No deploys on weekends"
```

### 🧠 LLM Guard + NL Policy Compiler

**LLM Guard** — optional async threat detection middleware. Catches what regex can't.

**NL Compiler** — write policies in English, get validated YAML:

```bash
policyshield compile "Block file deletions and redact PII" -o rules.yaml
```

---

## 🔌 Works With Everything

| Integration | How |
|-------------|-----|
| **OpenClaw** | `policyshield openclaw setup` — one command |
| **Telegram** | `policyshield bot` — NL rules + management |
| **LangChain** | `shield_all_tools([tool1, tool2], engine)` |
| **CrewAI** | `shield_crewai_tools([tool1, tool2], engine)` |
| **MCP** | `create_mcp_server(engine)` — transparent proxy |
| **Any HTTP client** | `POST /api/v1/check` — framework-agnostic REST API |
| **Python decorator** | `@shield(engine)` on any function (sync + async) |
| **Docker** | `docker build -f Dockerfile.server -t policyshield .` |

---

<details>
<summary><strong>🖥️ HTTP Server & Endpoints</strong></summary>

```bash
pip install "policyshield[server]"
policyshield server --rules ./rules.yaml --port 8100
```

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/check` | POST | Pre-call policy check |
| `/api/v1/post-check` | POST | Post-call PII scanning |
| `/api/v1/check-approval` | POST | Poll approval status |
| `/api/v1/respond-approval` | POST | Approve/deny request |
| `/api/v1/pending-approvals` | GET | List pending approvals |
| `/api/v1/health` | GET | Health check |
| `/api/v1/status` | GET | Server status |
| `/api/v1/constraints` | GET | Policy summary for LLM context |
| `/api/v1/reload` | POST | Hot-reload rules |
| `/api/v1/kill` | POST | Emergency kill switch |
| `/api/v1/resume` | POST | Deactivate kill switch |
| `/api/v1/compile` | POST | Compile NL description → YAML rules |
| `/api/v1/compile-and-apply` | POST | Compile + save + reload in one step |
| `/healthz` · `/readyz` | GET | K8s probes |
| `/metrics` | GET | Prometheus metrics |

</details>

<details>
<summary><strong>🐍 Python SDK</strong></summary>

```python
from policyshield.sdk.client import PolicyShieldClient

with PolicyShieldClient("http://localhost:8100") as client:
    result = client.check("exec_command", {"cmd": "rm -rf /"})
    print(result.verdict)  # BLOCK

    client.kill("Incident response")
    client.resume()
    client.reload()
```

**Async:**

```python
from policyshield.sdk.client import AsyncPolicyShieldClient

async with AsyncPolicyShieldClient("http://localhost:8100") as client:
    result = await client.check("send_email", {"to": "admin@corp.com"})
```

**Decorator:**

```python
from policyshield.decorators import shield

@shield(engine, tool_name="delete_file")
def delete_file(path: str):
    os.remove(path)  # only runs if PolicyShield allows
```

</details>

<details>
<summary><strong>⌨️ Full CLI Reference</strong></summary>

```bash
# Setup & Init
policyshield quickstart                    # Interactive setup wizard
policyshield init --preset secure          # Initialize with preset rules
policyshield doctor                        # 10-check health scan (A-F grading)

# Rules
policyshield validate ./policies/          # Validate rules
policyshield lint ./policies/rules.yaml    # Static analysis (7 checks)
policyshield test ./policies/              # Run YAML test cases

# Dry-run check
policyshield check --tool exec --rules rules.yaml

# Server
policyshield server --rules ./rules.yaml --port 8100 --mode enforce

# Telegram Bot
policyshield bot --rules rules.yaml --server-url http://localhost:8100

# Traces
policyshield trace show ./traces/trace.jsonl
policyshield trace violations ./traces/trace.jsonl
policyshield trace stats --dir ./traces/ --format json
policyshield trace dashboard --port 8000

# Replay & Simulation
policyshield replay ./trace.jsonl --rules new-rules.yaml --changed-only
policyshield simulate --rule rule.yaml --tool exec --args '{"cmd":"ls"}'

# Rule Generation
policyshield generate "Block all file deletions"       # AI-powered
policyshield generate-rules --from-openclaw             # Auto from OpenClaw
policyshield compile "Block deletions, redact PII"      # NL → YAML

# Reports & Ops
policyshield report --traces ./traces/ --format html
policyshield kill --reason "Incident response"
policyshield resume

# OpenClaw
policyshield openclaw setup                # Install + configure plugin
policyshield openclaw teardown             # Remove plugin
```

</details>

<details>
<summary><strong>📋 All Features</strong></summary>

**Core:** YAML DSL, 4 verdicts (ALLOW/BLOCK/REDACT/APPROVE), PII detection (8 types + custom), built-in detectors (path traversal, shell/SQL injection, SSRF), kill switch, chain rules, conditional rules, rate limiting (per-tool/session/global/adaptive), approval flows (InMemory/Telegram/Slack), hot reload, JSONL audit trail, idempotency.

**SDK & Integrations:** Python sync + async SDK, TypeScript SDK, `@shield()` decorator, MCP server + proxy, HTTP server (14 endpoints), OpenClaw plugin, LangChain/CrewAI adapters, Telegram bot, Docker.

**DX:** Quickstart wizard, doctor (A-F grading), dry-run CLI, auto-rules from OpenClaw, role presets (`coding-agent`, `data-analyst`, `customer-support`), YAML test runner, rule linter (7 checks), replay/simulation, 31 env vars (12-factor).

**Advanced:** Rule composition (`include:` / `extends:`), plugin system (pre/post check hooks), budget caps, shadow mode, canary deployments, dynamic rules (HTTP fetch), OpenTelemetry, LLM Guard, NL Policy Compiler, bounded sessions (LRU+TTL), cost estimator, alert engine (5 conditions × 4 backends), dashboard (REST + WebSocket + SPA), Prometheus metrics, compliance reports, incident timeline, config migration.

</details>

<details>
<summary><strong>📦 Examples & Presets</strong></summary>

| Example | Description |
|---------|-------------|
| [`standalone_check.py`](examples/standalone_check.py) | No server needed |
| [`langchain_demo.py`](examples/langchain_demo.py) | LangChain wrapping |
| [`async_demo.py`](examples/async_demo.py) | Async engine |
| [`fastapi_middleware.py`](examples/fastapi_middleware.py) | FastAPI integration |
| [`chain_rules.yaml`](examples/chain_rules.yaml) | Anti-exfiltration, retry storm |
| [`docker_compose/`](examples/docker_compose/) | Docker deployment |

**Role presets:** `strict` (BLOCK all), `permissive` (ALLOW all), `coding-agent`, `data-analyst`, `customer-support`

**Community rule packs:** [GDPR](community-rules/gdpr.yaml) (8 rules), [HIPAA](community-rules/hipaa.yaml) (9 rules), [PCI-DSS](community-rules/pci-dss.yaml) (9 rules)

</details>

---

📖 [Documentation](https://mishabar410.github.io/PolicyShield/) · 📝 [Changelog](CHANGELOG.md) · 🗺 [Roadmap](ROADMAP.md) · [MIT License](LICENSE)