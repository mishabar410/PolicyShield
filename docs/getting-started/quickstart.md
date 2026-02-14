# Quick Start

## 1. Initialize a project

```bash
policyshield init --preset security --no-interactive
```

This creates:
- `policies/rules.yaml` — Your rule definitions
- `tests/test_rules.yaml` — Auto-generated test cases
- `policyshield.yaml` — Configuration file

## 2. Review your rules

```yaml
# policies/rules.yaml
shield_name: security-policy
version: 1

rules:
  - id: block-shell-injection
    description: "Block destructive shell commands"
    when:
      tool: exec
      args_match:
        command:
          regex: "rm\\s+-rf|mkfs|dd\\s+if="
    then: block
    severity: critical
    message: "Destructive shell commands are not allowed."
```

## 3. Validate and lint

```bash
policyshield validate policies/
policyshield lint policies/rules.yaml
```

## 4. Run tests

```bash
policyshield test tests/
```

## 5. Use in your agent

```python
from policyshield.shield.engine import ShieldEngine

engine = ShieldEngine(rules="policies/rules.yaml")

# Check a tool call
result = engine.check("exec", {"command": "rm -rf /"})
print(result.verdict)  # Verdict.BLOCK
print(result.message)  # "Destructive shell commands are not allowed."

# Safe calls pass through
result = engine.check("web_search", {"query": "best restaurants"})
print(result.verdict)  # Verdict.ALLOW
```

## 6. Or start the HTTP server

```bash
pip install "policyshield[server]"
policyshield server --rules policies/rules.yaml --port 8100
```

```bash
curl -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tool": "exec", "args": {"command": "rm -rf /"}}'
# → {"verdict": "BLOCK", "message": "Destructive shell commands are not allowed."}
```

## Next steps

- [Writing Rules](../guides/writing-rules.md)
- [CLI Reference](../guides/cli.md)
- [OpenClaw Integration](../integrations/openclaw.md)
- [Presets](../guides/presets.md)
