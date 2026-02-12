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
from policyshield import ShieldEngine

engine = ShieldEngine.from_yaml("policies/rules.yaml")
verdict = engine.evaluate(tool="exec", args={"command": "rm -rf /"})
print(verdict)  # Verdict.BLOCK
```

## Next steps

- [Writing Rules](../guides/writing-rules.md)
- [CLI Reference](../guides/cli.md)
- [Integrations](../integrations/langchain.md)
