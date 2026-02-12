# 🛡️ PolicyShield

[![PyPI Version](https://img.shields.io/pypi/v/policyshield?color=blue)](https://pypi.org/project/policyshield/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/policyshield?color=green)](https://pypi.org/project/policyshield/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/mishabar410/PolicyShield/actions/workflows/ci.yml/badge.svg)](https://github.com/mishabar410/PolicyShield/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://mishabar410.github.io/PolicyShield/)
[![Coverage: 92%](https://img.shields.io/badge/coverage-92%25-brightgreen.svg)](#development)

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
```

Or from source:

```bash
git clone https://github.com/mishabar410/PolicyShield.git
cd PolicyShield
pip install -e ".[dev]"
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
from policyshield.shield import ShieldEngine

engine = ShieldEngine("rules.yaml")

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

## Using with Nanobot

PolicyShield integrates with [nanobot](https://github.com/nanobot-sh/nanobot) to enforce policies on all tool calls your agent makes.

### Step 1. Install PolicyShield alongside nanobot

```bash
# In your nanobot project:
pip install policyshield
```

### Step 2. Create rules for your agent

Create `policies/rules.yaml` in your project root:

```yaml
shield_name: my-nanobot
version: 1
rules:
  # Block dangerous shell commands
  - id: block-rm-rf
    when:
      tool: exec
      args_match:
        command: { contains: "rm -rf" }
    then: block
    message: "Destructive shell commands are not allowed."

  # Redact PII from any outgoing messages
  - id: redact-pii-messages
    when:
      tool: send_message
    then: redact

  # Block all file deletion
  - id: block-delete
    when:
      tool: delete_file
    then: block
    message: "File deletion is disabled."
```

### Step 3. Run nanobot through PolicyShield

The simplest way — just prefix your usual command:

```bash
policyshield nanobot --rules policies/rules.yaml agent -m "Hello!"
policyshield nanobot --rules policies/rules.yaml gateway
```

Or if you create `AgentLoop` in your own Python code:

```python
from nanobot.agent.loop import AgentLoop
from policyshield.integrations.nanobot import shield_agent_loop

loop = AgentLoop(bus=bus, provider=provider, workspace=workspace)
shield_agent_loop(loop, rules_path="policies/rules.yaml")  # ← one line
```

That's it. Every tool call your agent makes will now pass through PolicyShield. Blocked tools return an error message to the LLM, which replans automatically.

### What happens under the hood

`shield_agent_loop()` monkey-patches your existing loop instance (no nanobot source changes needed):

1. **Wraps the ToolRegistry** — every `execute()` call is checked against your rules
2. **Filters blocked tools from LLM context** — the LLM never sees tools it can't use
3. **Injects constraints into the system prompt** — the LLM knows what's forbidden
4. **Scans tool results for PII** — post-call audit and tainting
5. **Tracks sessions** — rate limits work per-conversation

### Optional: standalone mode (no AgentLoop)

You can also use PolicyShield with nanobot's `ToolRegistry` directly, without `AgentLoop`:

```python
from policyshield.integrations.nanobot.installer import install_shield

# Create a shielded registry
registry = install_shield(rules_path="policies/rules.yaml")

# Register your tools
registry.register_func("echo", lambda message="": f"Echo: {message}")
registry.register_func("delete_file", lambda path="": f"Deleted {path}")

# This works:
result = await registry.execute("echo", {"message": "hello"})
# → "Echo: hello"

# This is blocked:
result = await registry.execute("delete_file", {"path": "/etc/passwd"})
# → "🛡️ BLOCKED: File deletion is disabled."
```

### Configuration options

```python
shield_agent_loop(
    loop,
    rules_path="policies/rules.yaml",  # Required. Path to YAML rules
    mode="ENFORCE",       # ENFORCE (default) | AUDIT (log only) | DISABLED
    fail_open=True,       # True (default): shield errors don't block tools
)
```

See the [full nanobot integration guide](docs/nanobot_integration.md) for approval flows, custom PII patterns, rate limiting, and more.

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

policyshield trace show ./traces/trace.jsonl
policyshield trace violations ./traces/trace.jsonl
policyshield trace stats ./traces/trace.jsonl --format json
policyshield trace export ./traces/trace.jsonl -f html

# Run nanobot with PolicyShield enforcement
policyshield nanobot --rules rules.yaml agent -m "Hello!"
policyshield nanobot --rules rules.yaml gateway

# Initialize a new project
policyshield init --preset security --no-interactive
```

---

## Docker

```bash
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
| [`nanobot_shield_example.py`](examples/nanobot_shield_example.py) | Nanobot standalone — run this to see PolicyShield in action |
| [`nanobot_shield_agentloop.py`](examples/nanobot_shield_agentloop.py) | AgentLoop configuration reference |
| [`nanobot_rules.yaml`](examples/nanobot_rules.yaml) | Example policy rules for nanobot |
| [`langchain_demo.py`](examples/langchain_demo.py) | LangChain tool wrapping |
| [`async_demo.py`](examples/async_demo.py) | Async engine usage |
| [`policies/`](examples/policies/) | Production-ready rule sets (security, compliance, full) |

---

## Development

```bash
git clone https://github.com/mishabar410/PolicyShield.git
cd PolicyShield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,langchain]"

pytest tests/ -v                 # 570 tests
ruff check policyshield/ tests/  # Lint
ruff format --check policyshield/ tests/  # Format check
```

📖 **Documentation**: [mishabar410.github.io/PolicyShield](https://mishabar410.github.io/PolicyShield/)

---

## Roadmap

| Version | Status |
|---------|--------|
| **v0.1** | ✅ Core: YAML DSL, verdicts, PII, trace, CLI |
| **v0.2** | ✅ Linter, hot reload, rate limiter, approval flow, LangChain |
| **v0.3** | ✅ Async engine, CrewAI, OTel, webhooks, rule testing, policy diff |
| **v0.4** | ✅ Nanobot: monkey-patch, CLI wrapper, session propagation, PII scan |
| **v0.5** | ✅ DX: PyPI publish, docs site, GitHub Action, Docker, CLI init |
| **v1.0** | 📋 Stable API, dashboard UI, performance benchmarks |

See [ROADMAP.md](ROADMAP.md) for the full roadmap including v0.6–v1.0 and future ideas.

---

## License

[MIT](LICENSE)