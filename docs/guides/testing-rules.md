# Testing Rules

## Test file structure

```yaml
# tests/test_rules.yaml
tests:
  - name: "Block rm -rf"
    tool: exec
    args:
      command: "rm -rf /"
    expect:
      verdict: block
      rule_id: block-shell-injection
      message_contains: "Destructive"

  - name: "Allow safe read"
    tool: file_read
    args:
      path: "/workspace/readme.md"
    expect:
      verdict: allow
```

## Running tests

```bash
# Test all YAML files in tests/
policyshield test tests/

# Test a specific file
policyshield test tests/test_rules.yaml

# Verbose output
policyshield test tests/ --verbose
```

## Test assertions

| Field | Description |
|-------|-------------|
| `verdict` | Expected verdict: `block`, `allow`, `redact`, `approve` |
| `rule_id` | ID of the rule that should match |
| `message_contains` | Substring that must appear in the message |

## Auto-generated tests

`policyshield init` generates test cases automatically for each rule:

```bash
policyshield init --preset security --no-interactive
cat tests/test_rules.yaml
```
