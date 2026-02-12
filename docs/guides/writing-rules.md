# Writing Rules

## Rule structure

Each rule is a YAML object with these fields:

```yaml
- id: unique-rule-id
  description: "Human-readable description"
  when:
    tool: tool_name        # Regex or exact match
    args_match:            # Optional: match specific arguments
      key:
        regex: "pattern"
    session:               # Optional: match session context
      user_role: admin
    sender:                # Optional: match caller identity
      name: "agent-name"
  then: block              # block | allow | redact | approve
  severity: high           # critical | high | medium | low
  message: "Explanation"
  enabled: true            # Optional, default: true
```

## Verdicts

| Verdict | Behavior |
|---------|----------|
| `block` | Reject the tool call entirely |
| `allow` | Permit the tool call |
| `redact` | Allow but redact sensitive data |
| `approve` | Require human approval first |

## Tool matching

Tools are matched using regex patterns:

```yaml
tool: exec             # Exact match
tool: ".*"             # Match all tools (warning: broad)
tool: "file_.*"        # Match file_read, file_write, etc.
```

You can also specify a list of tools:

```yaml
tool:
  - exec
  - shell_run
  - subprocess
```

## Argument matching

```yaml
args_match:
  command:
    regex: "rm\\s+-rf"   # Block rm -rf commands
  path:
    contains: "/etc"     # Block access to /etc
```

## Session and sender context

```yaml
when:
  session:
    user_role: admin
  sender:
    name: "untrusted-agent"
```
