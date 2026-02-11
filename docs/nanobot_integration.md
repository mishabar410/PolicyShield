# Nanobot Integration Guide

PolicyShield integrates with [nanobot](https://github.com/nanobot-sh/nanobot) to enforce security policies on AI agent tool calls.

## Quick Start

### AgentLoop (recommended)

```python
from nanobot.agent.loop import AgentLoop

loop = AgentLoop(
    bus=bus,
    provider=provider,
    workspace=workspace,
    shield_config={
        "rules_path": "policies/rules.yaml",
        "mode": "ENFORCE",    # ENFORCE | AUDIT | DISABLED
        "fail_open": True,
    },
)
```

This automatically:
1. Wraps the `ToolRegistry` with `ShieldedToolRegistry`
2. Propagates session IDs for rate limiting
3. Injects policy constraints into the LLM system prompt
4. Filters blocked tools from `get_definitions()`
5. Scans tool results for PII (post-call)
6. Propagates shield to spawned subagents

### Standalone

```python
from policyshield.integrations.nanobot.installer import install_shield

registry = install_shield(
    rules_path="policies/rules.yaml",
    mode="ENFORCE",
    fail_open=True,
)
registry.register_func("echo", lambda message="": message)
result = await registry.execute("echo", {"message": "hello"})
```

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

### Subagent Propagation

When `shield_config` is provided to `AgentLoop`, it's automatically passed to `SubagentManager`. Each spawned subagent gets its own `ShieldedToolRegistry` with the same policy rules.

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
- [`examples/nanobot_shield_agentloop.py`](../examples/nanobot_shield_agentloop.py) — AgentLoop configuration reference
- [`examples/nanobot_rules.yaml`](../examples/nanobot_rules.yaml) — example rules file
