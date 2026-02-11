# 🛡️ PolicyShield

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-437_passing-brightgreen.svg)](#development)

**Declarative firewall for AI agent tool calls.**

Write rules in YAML → PolicyShield enforces them at runtime → get a full audit trail.

---

## Quick Start

```bash
pip install policyshield
```

**1. Define rules** in `policies/rules.yaml`:

```yaml
shield_name: my-agent
version: 1
rules:
  - id: no-delete
    when:
      tool: delete_file
    then: block
    message: "File deletion is not allowed."

  - id: no-pii-external
    when:
      tool: [web_fetch, web_search]
    then: redact
    message: "PII detected — redacting before external request."
```

**2. Enforce:**

```python
from policyshield.shield import ShieldEngine

engine = ShieldEngine("./policies/rules.yaml")
result = engine.check("delete_file", {"path": "/data"})
# result.verdict == Verdict.BLOCK
# result.message == "File deletion is not allowed."
```

**3. Validate & inspect:**

```bash
policyshield validate ./policies/
policyshield lint ./policies/rules.yaml
policyshield trace show ./traces/trace.jsonl
```

See the [Quick Start Guide](docs/QUICKSTART.md) for the full walkthrough.

---

## How It Works

```
LLM calls web_fetch(url="...?email=john@corp.com")
      │
      ▼
  PolicyShield pre-call check
      │
      ├─ PII detected (email) → rule no-pii-external → BLOCK
      │
      ▼
  Agent gets structured explanation + counterexample
      │
      ▼
  LLM replans → web_fetch(url="...?email=[REDACTED]")
      │
      ▼
  PolicyShield → ALLOW → tool executes
```

---

## Features

| Category | What you get |
|----------|-------------|
| **YAML DSL** | Declarative rules with regex, glob, exact match, session conditions |
| **Verdicts** | `ALLOW` · `BLOCK` · `REDACT` · `APPROVE` (human-in-the-loop) |
| **PII Detection** | EMAIL, PHONE, CREDIT_CARD, SSN, IBAN, IP, PASSPORT, DOB + custom patterns |
| **Async Engine** | Full `async`/`await` support for FastAPI, aiohttp, async agents |
| **Approval Flow** | InMemory, CLI, Telegram, and Webhook backends with caching strategies |
| **Rate Limiting** | Sliding-window per tool/session, configurable in YAML |
| **Hot Reload** | File-watcher auto-reloads rules on change |
| **Input Sanitizer** | Normalize args, block prompt injection patterns |
| **OpenTelemetry** | OTLP export to Jaeger/Grafana (spans + metrics) |
| **Trace & Audit** | JSONL log, stats, violations, CSV/HTML export |
| **Rule Testing** | YAML test cases for policies (`policyshield test`) |
| **Rule Linter** | Static analysis: duplicates, broad patterns, missing messages, conflicts |
| **Policy Diff** | Compare rule sets, detect additions/removals/changes |
| **Config File** | Unified `policyshield.yaml` with env-var support and JSON Schema |

---

## Integrations

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

### Nanobot

```python
from nanobot.agent.loop import AgentLoop

loop = AgentLoop(
    model="gpt-4",
    shield_config={"rules": "policies/rules.yaml"},
)
```

---

## Rules DSL

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

rate_limits:
  - tool: web_fetch
    max_calls: 10
    window_seconds: 60
    per_session: true

pii_patterns:
  - name: EMPLOYEE_ID
    pattern: "EMP-\\d{6}"
```

---

## CLI

```bash
policyshield validate ./policies/          # Validate rules
policyshield lint ./policies/rules.yaml    # Static analysis (6 checks)
policyshield test ./policies/              # Run YAML test cases

policyshield trace show ./traces/trace.jsonl
policyshield trace violations ./traces/trace.jsonl
policyshield trace stats ./traces/trace.jsonl --format json
policyshield trace export ./traces/trace.jsonl -f html
```

---

## Examples

| Example | Description |
|---------|-------------|
| [`examples/langchain_demo.py`](examples/langchain_demo.py) | LangChain tool wrapping |
| [`examples/async_demo.py`](examples/async_demo.py) | Async engine usage |
| [`examples/nanobot_shield_example.py`](examples/nanobot_shield_example.py) | Nanobot integration |
| [`examples/policies/`](examples/policies/) | Production-ready rule sets (security, compliance, full) |

---

## Development

```bash
git clone https://github.com/policyshield/policyshield.git
cd policyshield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,langchain]"

pytest tests/ -v                 # 437 tests
ruff check policyshield/ tests/  # Lint
```

---

## Roadmap

| Version | Status |
|---------|--------|
| **v0.1** | ✅ Core: YAML DSL, verdicts, PII, repair loop, trace, CLI |
| **v0.2** | ✅ Linter, hot reload, rate limiter, approval flow, LangChain adapter |
| **v0.3** | ✅ Async engine, CrewAI/Nanobot, OTel, webhooks, rule testing, policy diff |
| **v1.0** | 🚧 Stable API, PyPI publish, dashboard UI |

---

## License

[MIT](LICENSE)