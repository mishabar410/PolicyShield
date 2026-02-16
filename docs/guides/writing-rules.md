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

## Chain rules

Chain rules let you define **temporal conditions** — blocking a tool call when a specific tool was called within a time window. Use `when.chain` to detect multi-step attack patterns like data exfiltration.

```yaml
- id: anti-exfiltration
  when:
    tool: send_email
    chain:
      - tool: read_database
        within_seconds: 120
  then: block
  severity: critical
  message: "Data exfiltration: read_database → send_email"
```

### Chain step fields

| Field | Required | Description |
|-------|----------|-------------|
| `tool` | ✅ | Tool name that must have been called previously |
| `within_seconds` | ✅ | Time window to search (seconds) |
| `min_count` | ❌ | Minimum number of calls required (default: 1) |
| `verdict` | ❌ | Filter previous calls by verdict (e.g., `allow`) |

### Multi-step chains

```yaml
- id: retry-storm
  when:
    tool: exec
    chain:
      - tool: exec
        within_seconds: 10
        min_count: 5
  then: block
  message: "Retry storm detected: too many exec calls in 10 seconds"
```
