# Quick Start Guide

Get PolicyShield running in 5 minutes.

## 1. Install

```bash
pip install policyshield
```

## 2. Create Rules

Create a file `policies/rules.yaml`:

```yaml
shield_name: my-agent
version: 1

rules:
  - id: no-delete
    description: "Block file deletion"
    when:
      tool: delete_file
    then: block
    message: "File deletion is not allowed."

  - id: allow-reads
    when:
      tool: read_file
    then: allow
```

See [`examples/policies/`](../examples/policies/) for more examples.

## 3. Validate Rules

```bash
policyshield validate ./policies/
```

Expected output:

```
✓ Valid: my-agent v1
  Rules: 2 total, 2 enabled
  ✓ no-delete → BLOCK [MEDIUM]
  ✓ allow-reads → ALLOW [MEDIUM]
```

## 4. Integrate with Your Agent

```python
from policyshield.shield import ShieldEngine

engine = ShieldEngine("./policies/rules.yaml")

# Check before executing a tool call
result = engine.check("delete_file", {"path": "/important/data"})
if result.verdict.name == "BLOCK":
    print(f"Blocked: {result.message}")
else:
    # Proceed with tool execution
    pass
```

### With ShieldedToolRegistry

```python
from policyshield.integrations.nanobot import install_shield

registry = install_shield("./policies/rules.yaml")
registry.register("read_file", my_read_file_func)
registry.register("delete_file", my_delete_file_func)

# Automatically checks policy before execution
result = registry.execute("read_file", {"path": "/tmp/log"})  # ✓ Allowed
result = registry.execute("delete_file", {"path": "/data"})    # ✗ PolicyViolation
```

## 5. Enable Trace Logging

```python
from policyshield.shield import ShieldEngine
from policyshield.trace.recorder import TraceRecorder

with TraceRecorder("./traces/") as tracer:
    engine = ShieldEngine("./policies/rules.yaml", trace_recorder=tracer)
    result = engine.check("delete_file", {"path": "/data"})
```

## 6. View Traces

```bash
# Show all trace entries
policyshield trace show ./traces/trace_*.jsonl

# Show only violations
policyshield trace violations ./traces/trace_*.jsonl

# Filter by tool
policyshield trace show ./traces/trace_*.jsonl --tool delete_file
```

## Next Steps

- Read the [Technical Specification](../TECHNICAL_SPEC.md) for detailed architecture
- See [example policies](../examples/policies/) for production-ready rule sets
- Enable AUDIT mode to test rules without blocking: `ShieldEngine(rules, mode=ShieldMode.AUDIT)`
