# Nanobot Integration Guide

PolicyShield integrates with [nanobot](https://github.com/nanobot-sh/nanobot) to enforce security policies on AI agent tool calls. **No nanobot source code changes required.**

## Quick Start

### Option A: CLI wrapper (recommended)

The easiest way — just prefix your usual nanobot command:

```bash
# Instead of:
nanobot agent -m "Hello!"

# Run:
policyshield nanobot --rules policies/rules.yaml agent -m "Hello!"

# Gateway mode:
policyshield nanobot --rules policies/rules.yaml gateway

# Audit mode (log only, don't block):
policyshield nanobot --rules policies/rules.yaml --mode AUDIT gateway
```

### Option B: Python API

If you create `AgentLoop` in your own code:

```python
from nanobot.agent.loop import AgentLoop
from policyshield.integrations.nanobot import shield_agent_loop

# Create your agent as usual
loop = AgentLoop(bus=bus, provider=provider, workspace=workspace)

# Add PolicyShield (one line)
shield_agent_loop(loop, rules_path="policies/rules.yaml")
```

### Option C: Standalone registry (no AgentLoop)

```python
from policyshield.integrations.nanobot.installer import install_shield

registry = install_shield(rules_path="policies/rules.yaml")
registry.register_func("echo", lambda message="": message)

result = await registry.execute("echo", {"message": "hello"})     # ✓ Allowed
result = await registry.execute("delete_file", {"path": "/etc"})  # ✗ Blocked
```

## What Happens Under the Hood

`shield_agent_loop()` monkey-patches the AgentLoop instance:

1. **Wraps the ToolRegistry** — every `execute()` call is checked against your rules
2. **Filters blocked tools from LLM context** — the model never sees tools it can't use
3. **Injects constraints into the system prompt** — the model knows what's forbidden
4. **Scans tool results for PII** — post-call audit and tainting
5. **Tracks sessions** — rate limits work per-conversation

## Features

### Pre-call Enforcement

Every `execute()` call passes through PolicyShield's `check()`:
- **BLOCK** — returns a structured error message, tool never executes
- **REDACT** — PII in arguments is masked, tool executes with sanitized params
- **APPROVE** — returns a pending-approval message (see Approval Flow below)
- **ALLOW** — tool executes normally

### Post-call PII Scan

After tool execution, results are scanned for PII. Detected PII types are recorded as session taints for audit and rate-limiting purposes.

### LLM Context Enrichment

`get_constraints_summary()` generates a human-readable policy summary that's injected into the LLM system prompt. This helps the model avoid making tool calls that would be blocked.

### Definition Filtering

`get_definitions()` excludes unconditionally blocked tools from the schemas sent to the LLM, preventing wasted tokens on tools that will always be rejected.

### Approval Flow

For `APPROVE` verdicts, wire up an approval backend:

```python
from policyshield.approval.cli_backend import CLIBackend
from policyshield.integrations.nanobot.installer import install_shield

registry = install_shield(
    rules_path="policies/rules.yaml",
    approval_backend=CLIBackend(),
)
```

Available backends: `CLIBackend`, `InMemoryBackend`, `TelegramBackend`, `WebhookBackend`.

## Configuration

```python
shield_agent_loop(
    loop,
    rules_path="policies/rules.yaml",  # Required
    mode="ENFORCE",       # ENFORCE (default) | AUDIT (log only) | DISABLED
    fail_open=True,       # True (default): shield errors don't block tools
)
```

Or via CLI:

```bash
policyshield nanobot \
    --rules policies/rules.yaml \
    --mode ENFORCE \
    gateway --port 18790
```

## Example Rules

```yaml
shield_name: my-agent
version: 1
rules:
  - id: block-rm
    description: Block destructive rm commands
    when:
      tool: exec
      args:
        command:
          contains: "rm "
    then: BLOCK
    message: Destructive commands are not allowed

  - id: redact-messages
    description: Redact PII from outgoing messages
    when:
      tool: send_message
    then: REDACT

  - id: approve-file-write
    description: Require approval for file writes
    when:
      tool: write_file
    then: APPROVE
    approval_strategy: per_rule
```

## Examples

- [`examples/nanobot_shield_example.py`](../examples/nanobot_shield_example.py) — standalone integration demo
- [`examples/nanobot_rules.yaml`](../examples/nanobot_rules.yaml) — example rules file
