# PolicyShield

**Declarative firewall for AI agent tool calls.**

PolicyShield lets you define YAML rules that control what tools an AI agent can use, when, and how — without modifying agent code.

## Key Features

- 🛡️ **Declarative rules** — YAML-based, no code changes needed
- 🔗 **Chain rules** — Temporal conditions for multi-step attack detection
- 🔍 **PII detection** — Built-in redaction for sensitive data
- 🚨 **Kill switch** — `policyshield kill` for instant emergency stop
- 🍯 **Honeypot tools** — Decoy tools that catch prompt injection
- 🩺 **Doctor** — 10-check health scanner with A–F grading
- ⚙️ **Auto-rules** — `policyshield generate-rules --from-openclaw`
- ✅ **Approval flows** — Human-in-the-loop for risky operations
- 📊 **Tracing** — Full audit trail of every tool call
- 🔄 **Replay & Simulation** — Re-run traces against new rules
- 🤖 **AI Rule Writer** — Generate rules from natural language
- 🌐 **HTTP Server** — Framework-agnostic REST API for tool call policy enforcement
- 🔌 **OpenClaw Plugin** — Native plugin with before/after hooks
- 🔗 **Integrations** — LangChain, CrewAI
- 🧪 **Testing** — Validate rules before deployment
- 🚀 **CLI** — Scaffold, validate, lint, test, serve from the command line
- 🕐 **Conditional Rules** — Context-based: time of day, day of week, custom context
- 🧠 **LLM Guard** — Async threat detection middleware with caching
- 📝 **NL Policy Compiler** — `policyshield compile` — natural language → YAML rules
- 💾 **Bounded Sessions** — LRU + TTL session storage with Redis support

## Quick Start

```bash
pip install policyshield

# Scaffold a new project with secure defaults
policyshield init --preset secure --no-interactive

# Check your security posture
policyshield doctor

# Validate your rules
policyshield validate policies/

# Start the HTTP server
pip install "policyshield[server]"
policyshield server --rules policies/rules.yaml --port 8100
```

## How It Works

```yaml
# policies/rules.yaml
shield_name: my-policy
version: 1

rules:
  - id: block-file-delete
    when:
      tool: delete_file
    then: block
    severity: high
    message: "File deletion is not allowed."
```

```python
from policyshield.shield.engine import ShieldEngine

engine = ShieldEngine(rules="policies/rules.yaml")
result = engine.check("delete_file", {"path": "/data"})
print(result.verdict)  # Verdict.BLOCK
```

## Next Steps

- [Installation](getting-started/installation.md)
- [Quick Start Guide](getting-started/quickstart.md)
- [Writing Rules](guides/writing-rules.md)
- [OpenClaw Integration](integrations/openclaw.md)
- [API Reference](api/core.md)
