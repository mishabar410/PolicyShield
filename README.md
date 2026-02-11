# 🛡️ PolicyShield

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-437_passing-brightgreen.svg)](#development)

**Declarative firewall for AI agent tool calls.**

Write rules in YAML → PolicyShield enforces them on every tool call → get an audit log.

```yaml
rules:
  - id: no-pii-external
    description: "Block PII from being sent to external services"
    when:
      tool: [web_fetch, web_search]
    then: block
    message: "PII detected. Redact before sending externally."
```

---

## Why

AI agents interact with the world through **tool calls**: shell commands, files, HTTP, messages. Today's controls are either prompts ("please don't delete") or ad-hoc regex checks. Both are unreliable, don't cover all tools, and leave no audit trail.

PolicyShield fixes this:
- **Declarative rules** (YAML) instead of hardcoded checks
- **Runtime enforcement** on every tool call
- **Repair loop** — when blocked, the agent gets an explanation and can self-correct
- **Audit trail** (JSONL) — proof of compliance

## Quick Start

```bash
pip install policyshield
```

Create rules in `policies/rules.yaml`:

```yaml
shield_name: my-agent
version: 1
rules:
  - id: no-delete
    when:
      tool: delete_file
    then: block
    message: "File deletion is not allowed."
```

Validate and use:

```bash
policyshield validate ./policies/
```

```python
from policyshield.shield import ShieldEngine

engine = ShieldEngine("./policies/rules.yaml")
result = engine.check("delete_file", {"path": "/data"})
# result.verdict == Verdict.BLOCK
```

See the full [Quick Start Guide](docs/QUICKSTART.md) for more.

## Features

### Core (v0.1)

| Feature | Description |
|---------|-------------|
| YAML DSL | Human-readable rules with regex, glob, and exact match |
| Verdicts | `ALLOW`, `BLOCK`, `APPROVE`, `REDACT` |
| PII Detection | EMAIL, PHONE, CREDIT_CARD, SSN, IBAN, IP, PASSPORT, DOB |
| Repair Loop | Agent gets structured counterexamples on block |
| Trace Log | JSONL audit trail for every decision |
| CLI | `validate`, `trace show`, `trace violations` |

### v0.3 (current)

| Feature | Description |
|---------|-------------|
| Async Engine | Full async/await ShieldEngine for FastAPI, aiohttp, async agents |
| CrewAI Adapter | Wrap CrewAI tools with shield enforcement |
| Nanobot Integration | `ShieldedToolRegistry` extends nanobot's `ToolRegistry` with shield enforcement |
| OpenTelemetry | OTLP export to Jaeger/Grafana (spans + metrics) |
| Webhook Approval | HTTP webhook with HMAC signing for external approval |
| Rule Testing | YAML test cases for policies (`policyshield test`) |
| Policy Diff | Compare rule sets, detect additions/removals/changes |
| Trace Export | Export JSONL to CSV or standalone HTML report |
| Input Sanitizer | Normalize args, block prompt injection patterns |
| Config File | Unified `policyshield.yaml` with env vars and JSON Schema |

### v0.2

| Feature | Description |
|---------|-------------|
| Rule Linter | 6 static checks: duplicates, invalid regex, broad patterns, missing messages, conflicts, disabled rules |
| Hot Reload | File-watcher auto-reloads YAML rules on change |
| Advanced PII | RU patterns: INN (with checksum), SNILS, passport, phone; custom PII via YAML |
| Rate Limiter | Sliding-window rate limits per tool, configurable in YAML |
| Approval Flow | Human-in-the-loop `APPROVE` verdict with InMemory, CLI, and Telegram backends |
| Batch Approve | Caching strategies: `once`, `per_session`, `per_rule`, `per_tool` |
| Trace Stats | Aggregated statistics: verdict/tool/rule distribution, latency percentiles, block rate |
| LangChain Adapter | `PolicyShieldTool` wraps any LangChain `BaseTool`; `shield_all_tools()` for bulk wrapping |

## How It Works

```
LLM wants to call web_fetch(url="...?email=john@corp.com")
      │
      ▼
  PolicyShield pre-call check
      │
      ├── PII detected (email) → rule no-pii-external → BLOCK
      │
      ▼
  Agent receives counterexample:
  "🛡️ BLOCKED: PII detected. Redact email before external request."
      │
      ▼
  LLM replans: web_fetch(url="...?email=[REDACTED]")
      │
      ▼
  PolicyShield: OK → ALLOW → tool executes
```

## Rules — YAML DSL

```yaml
rules:
  - id: no-destructive-shell
    when:
      tool: exec
      args_match:
        command: { regex: "rm\\s+-rf|mkfs|dd\\s+if=" }
    then: block
    severity: critical

  - id: approve-file-delete
    when:
      tool: delete_file
    then: approve
    approval_strategy: per_rule

  - id: rate-limit-web
    when:
      tool: web_fetch
    then: allow

rate_limits:
  - tool: web_fetch
    max_calls: 10
    window_seconds: 60
    per_session: true

pii_patterns:
  - name: EMPLOYEE_ID
    pattern: "EMP-\\d{6}"
```

## CLI

```bash
# Validate rules
policyshield validate ./policies/

# Lint rules (static analysis)
policyshield lint ./policies/rules.yaml

# View trace log
policyshield trace show ./traces/trace.jsonl
policyshield trace violations ./traces/trace.jsonl

# Aggregated statistics
policyshield trace stats ./traces/trace.jsonl
policyshield trace stats ./traces/trace.jsonl --format json
```

## LangChain Integration

```bash
pip install policyshield[langchain]
```

```python
from langchain_core.tools import BaseTool
from policyshield.integrations.langchain import PolicyShieldTool, shield_all_tools

# Wrap a single tool
safe_tool = PolicyShieldTool(wrapped_tool=my_tool, engine=engine)

# Wrap all tools at once
safe_tools = shield_all_tools([tool1, tool2], engine)
```

See [`examples/langchain_demo.py`](examples/langchain_demo.py) for a full example.

## Nanobot Integration

```python
from nanobot.agent.loop import AgentLoop

# Enable PolicyShield in nanobot's agent loop
loop = AgentLoop(
    model="gpt-4",
    shield_config={"rules": "policies/rules.yaml"},
)
# All tool calls now go through PolicyShield pre-check
```

See [`examples/nanobot_shield_example.py`](examples/nanobot_shield_example.py) for details.

## Examples

See [`examples/policies/`](examples/policies/) for production-ready rule sets:

| File | Description |
|------|-------------|
| [`full.yaml`](examples/policies/full.yaml) | All v0.2 features: rate limits, custom PII, approval strategy |
| [`security.yaml`](examples/policies/security.yaml) | Destructive commands, PII, downloads, workspace boundaries |
| [`compliance.yaml`](examples/policies/compliance.yaml) | PII redaction, rate limiting, shell audit logging |
| [`minimal.yaml`](examples/policies/minimal.yaml) | Minimal example with detailed comments |

## Development

```bash
git clone https://github.com/policyshield/policyshield.git
cd policyshield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,langchain]"

# Run tests
pytest tests/ -v

# Lint
ruff check policyshield/ tests/

# Coverage
pytest tests/ --cov=policyshield --cov-report=term-missing
```

## Roadmap

| Version | Features |
|---------|----------|
| **v0.1** ✅ | YAML DSL, BLOCK/ALLOW/REDACT/APPROVE verdicts, PII detection, repair loop, JSONL trace, CLI |
| **v0.2** ✅ | Rule linter, hot reload, advanced PII, rate limiter, approval flow, batch approve, trace stats, LangChain adapter |
| **v0.3** ✅ | Async engine, CrewAI / nanobot adapters, OTel, webhook approval, rule testing, policy diff, trace export, input sanitizer, config file |
| **v1.0** | Stable API, PyPI publish, dashboard UI |

---

## License

[MIT](LICENSE)