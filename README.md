# 🛡️ PolicyShield

[![PyPI Version](https://img.shields.io/pypi/v/policyshield?color=blue)](https://pypi.org/project/policyshield/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/policyshield?color=green)](https://pypi.org/project/policyshield/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/mishabar410/PolicyShield/actions/workflows/ci.yml/badge.svg)](https://github.com/mishabar410/PolicyShield/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://mishabar410.github.io/PolicyShield/)
[![Coverage: 85%](https://img.shields.io/badge/coverage-85%25-brightgreen.svg)](#development)

**Declarative firewall for AI agent tool calls.**

Write rules in YAML → PolicyShield enforces them at runtime → get a full audit trail.

```
LLM calls web_fetch(url="...?email=john@corp.com")
      │
      ▼
  PolicyShield intercepts
      │
      ├─ PII detected → REDACT → tool runs with masked args
      ├─ Destructive cmd → BLOCK → tool never executes
      └─ Sensitive action → APPROVE → human reviews first
```

---

## Installation

```bash
pip install policyshield

# With HTTP server (for OpenClaw and other integrations)
pip install "policyshield[server]"
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
policyshield init --preset security --no-interactive
```

---

## ⚡ OpenClaw Integration (60 seconds)

PolicyShield integrates natively with [OpenClaw](https://github.com/AgenturAI/OpenClaw) as a plugin.
Verified with OpenClaw 2026.2.13.

### Option A: One Command (recommended)

```bash
pip install "policyshield[server]"
policyshield openclaw setup
```

That's it. This will:
1. Generate security rules (`policies/rules.yaml`)
2. Start PolicyShield server (port 8100)
3. Install the OpenClaw plugin
4. Configure the connection
5. Verify everything works

### Option B: Docker

```bash
curl -O https://raw.githubusercontent.com/mishabar410/PolicyShield/main/docker/docker-compose.openclaw.yml
docker compose -f docker-compose.openclaw.yml up
```

### Option C: Step by Step

```bash
# 1. Install and generate rules
pip install "policyshield[server]"
policyshield init --preset openclaw

# 2. Start server (new terminal)
policyshield server --rules policies/rules.yaml --port 8100

# 3. Install plugin into OpenClaw extensions
npm install --prefix ~/.openclaw/extensions/policyshield @policyshield/openclaw-plugin
cp -r ~/.openclaw/extensions/policyshield/node_modules/@policyshield/openclaw-plugin/* \
     ~/.openclaw/extensions/policyshield/

# 4. Add to ~/.openclaw/openclaw.json under "plugins.entries":
# { "policyshield": { "enabled": true, "config": { "url": "http://localhost:8100" } } }

# 5. Verify
curl http://localhost:8100/api/v1/health
```

See the **[full integration guide](docs/integrations/openclaw.md)** and
[`plugins/openclaw/README.md`](plugins/openclaw/README.md) for configuration, troubleshooting,
and the [Migration Guide](docs/integrations/openclaw-migration.md) for version upgrades.

---

## HTTP Server

PolicyShield ships with a built-in HTTP API for framework-agnostic integration:

```bash
policyshield server --rules ./rules.yaml --port 8100 --mode enforce
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/check` | POST | Pre-call policy check (ALLOW/BLOCK/REDACT/APPROVE) |
| `/api/v1/post-check` | POST | Post-call PII scanning on tool output |
| `/api/v1/health` | GET | Health check with rules count and mode |
| `/api/v1/constraints` | GET | Human-readable policy summary for LLM context |

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

| Category | What you get |
|----------|-------------|
| **YAML DSL** | Declarative rules with regex, glob, exact match, session conditions |
| **Verdicts** | `ALLOW` · `BLOCK` · `REDACT` · `APPROVE` (human-in-the-loop) |
| **HTTP Server** | FastAPI server with check, post-check, health, and constraints endpoints |
| **OpenClaw Plugin** | Native plugin with before/after hooks and policy injection |
| **PII Detection** | EMAIL, PHONE, CREDIT_CARD, SSN, IBAN, IP, PASSPORT, DOB + custom patterns |
| **Async Engine** | Full `async`/`await` support for FastAPI, aiohttp, async agents |
| **Approval Flow** | InMemory, CLI, Telegram, and Webhook backends with caching strategies |
| **Rate Limiting** | Sliding-window per tool/session, configurable in YAML |
| **Hot Reload** | File-watcher auto-reloads rules on change |
| **Input Sanitizer** | Normalize args, block prompt injection patterns |
| **OpenTelemetry** | OTLP export to Jaeger/Grafana (spans + metrics) |
| **Trace & Audit** | JSONL log, search, stats, violations, CSV/HTML export |
| **Cost Estimator** | Token/dollar cost estimation per tool call and model |
| **Alert Engine** | 5 condition types with Console, Webhook, Slack, Telegram backends |
| **Dashboard** | FastAPI REST API + WebSocket live stream + dark-themed SPA |
| **Prometheus** | `/metrics` endpoint with per-tool and PII labels + Grafana preset |
| **Rule Testing** | YAML test cases for policies (`policyshield test`) |
| **Rule Linter** | Static analysis: duplicates, broad patterns, missing messages, conflicts |
| **Docker** | Container-ready with Dockerfile.server and docker-compose |

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
policyshield lint ./policies/rules.yaml    # Static analysis (6 checks)
policyshield test ./policies/              # Run YAML test cases

policyshield server --rules ./rules.yaml   # Start HTTP server
policyshield server --rules ./rules.yaml --port 8100 --mode audit

policyshield trace show ./traces/trace.jsonl
policyshield trace violations ./traces/trace.jsonl
policyshield trace stats --dir ./traces/ --format json
policyshield trace search --tool exec --verdict BLOCK
policyshield trace cost --dir ./traces/ --model gpt-4o
policyshield trace export ./traces/trace.jsonl -f html

# Launch the live web dashboard
policyshield trace dashboard --port 8000 --prometheus

# Initialize a new project
policyshield init --preset openclaw --no-interactive
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
| [`policies/`](examples/policies/) | Production-ready rule sets (security, compliance, full) |

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

pytest tests/ -v                 # 715+ tests
ruff check policyshield/ tests/  # Lint
ruff format --check policyshield/ tests/  # Format check
```

📖 **Documentation**: [mishabar410.github.io/PolicyShield](https://mishabar410.github.io/PolicyShield/)

---

## License

[MIT](LICENSE)