# 🛡️ PolicyShield

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#development)

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

## Three Pillars

### 1. Rules — YAML DSL

Human-readable policies in a familiar format:

```yaml
rules:
  - id: no-destructive-shell
    when:
      tool: exec
      args_match:
        command: { regex: "rm\\s+-rf|mkfs|dd\\s+if=" }
    then: block
    severity: critical

  - id: rate-limit-web
    when:
      tool: web_fetch
      session:
        tool_count.web_fetch: { gt: 20 }
    then: block
```

### 2. Shield — Runtime Enforcement

Middleware between LLM and tools. Verdicts:
- **ALLOW** — tool call proceeds
- **BLOCK** — tool call blocked, agent gets counterexample
- **APPROVE** — human-in-the-loop required
- **REDACT** — PII masked in arguments or results

### 3. Trace — Audit Log

Every decision recorded in JSONL:

```bash
policyshield trace show ./traces/trace.jsonl
policyshield trace violations ./traces/trace.jsonl
```

## Examples

See [`examples/policies/`](examples/policies/) for production-ready rule sets:

| File | Description |
|------|-------------|
| [`security.yaml`](examples/policies/security.yaml) | Destructive commands, PII, downloads, workspace boundaries |
| [`compliance.yaml`](examples/policies/compliance.yaml) | PII redaction, rate limiting, shell audit logging |
| [`minimal.yaml`](examples/policies/minimal.yaml) | Minimal example with detailed comments |

## Development

```bash
git clone https://github.com/policyshield/policyshield.git
cd policyshield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check policyshield/ tests/

# Coverage
pytest tests/ --cov=policyshield --cov-report=term-missing
```

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/QUICKSTART.md) | 5-minute setup guide |
| [CLAUDE.md](CLAUDE.md) | Project vision, positioning, strategy |
| [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) | Technical spec: YAML DSL, matcher, verdicts, PII, trace |
| [INTEGRATION_SPEC.md](INTEGRATION_SPEC.md) | Nanobot integration: architecture, ShieldedToolRegistry, approval flow |

## Roadmap

| Version | Features |
|---------|----------|
| **v0.1** ✅ | YAML DSL + BLOCK/ALLOW/REDACT/APPROVE + L0 PII + Repair loop + JSONL trace + CLI |
| **v0.2** | Human-in-the-loop approval (Telegram/Discord) + Batch approve |
| **v0.3** | Rule linter + Advanced rate limiting + Hot reload |
| **v0.4** | LangChain / CrewAI adapters |
| **v1.0** | Stable API + PyPI publish |

---

## License

[MIT](LICENSE)