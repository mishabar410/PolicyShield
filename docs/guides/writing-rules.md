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

## Conditional rules

Conditional rules use `when.context` to enforce policies based on runtime context — time of day, day of week, or arbitrary key-value conditions passed via `engine.check()`.

### Time-based conditions

```yaml
- id: block-after-hours
  when:
    tool: deploy
    context:
      time_of_day: "!09:00-18:00"   # Block outside business hours
      day_of_week: "!Mon-Fri"       # Block on weekends
  then: block
  message: "Deploy allowed only Mon-Fri 9-18"
```

### Custom context conditions

Pass arbitrary context to the engine:

```python
result = engine.check("deploy", {"env": "prod"}, context={
    "user_role": "developer",
    "environment": "production",
})
```

```yaml
- id: admin-only-delete
  when:
    tool: delete_*
    context:
      user_role: "!admin"           # Block if NOT admin
  then: block
  message: "Only admins can delete"
```

### Context fields

| Field | Format | Description |
|-------|--------|-------------|
| `time_of_day` | `HH:MM-HH:MM` | Time range (local). Prefix `!` to negate |
| `day_of_week` | `Mon-Fri` | Day range. Prefix `!` to negate |
| `<custom_key>` | string | Matched against context dict. Prefix `!` to negate |
