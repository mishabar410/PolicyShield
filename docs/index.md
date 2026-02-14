# PolicyShield

**Declarative firewall for AI agent tool calls.**

PolicyShield lets you define YAML rules that control what tools an AI agent can use, when, and how — without modifying agent code.

## Key Features

- 🛡️ **Declarative rules** — YAML-based, no code changes needed
- 🔍 **PII detection** — Built-in redaction for sensitive data
- ✅ **Approval flows** — Human-in-the-loop for risky operations
- 📊 **Tracing** — Full audit trail of every tool call
- 🔌 **Integrations** — LangChain, CrewAI, FastAPI
- 🧪 **Testing** — Validate rules before deployment
- 🚀 **CLI** — Scaffold, validate, lint, test from the command line

## Quick Start

```bash
pip install policyshield

# Scaffold a new project
policyshield init --preset security --no-interactive

# Validate your rules
policyshield validate policies/

# Lint for best practices
policyshield lint policies/rules.yaml
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

## Next Steps

- [Installation](getting-started/installation.md)
- [Quick Start Guide](getting-started/quickstart.md)
- [Writing Rules](guides/writing-rules.md)
- [API Reference](api/core.md)
