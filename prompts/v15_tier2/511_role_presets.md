# 511 — Role-Based Init Presets

## Goal

Add role-specific presets to `policyshield init --preset <role>`: `coding-agent`, `data-analyst`, `customer-support`.

## Context

- Currently available: `minimal`, `security`, `compliance`, `openclaw`
- New presets generate rules tailored to common agent roles
- Each preset includes appropriate tool restrictions and approval flows

## Code

### Modify: `policyshield/cli/init_scaffold.py`

Add new preset YAML templates:

**coding-agent**: blocks `exec_command`, `delete_file`, requires approval for `write_file`, allows `read_file`, `search`.

**data-analyst**: blocks network tools, allows database reads, requires approval for writes, includes PII detection.

**customer-support**: blocks all system tools, allows CRM reads, requires approval for account modifications.

### Template format

```yaml
shield_name: coding-agent-shield
version: "1"
rules:
  - id: block-dangerous-exec
    when: { tool: exec_command }
    then: BLOCK
    message: "Direct command execution blocked"
  - id: approve-file-write
    when: { tool: write_file }
    then: APPROVE
    message: "File write requires human approval"
  - id: allow-reads
    when: { tool: read_file }
    then: ALLOW
```

## Tests

- Test each preset generates valid rules
- Test `policyshield init --preset coding-agent` creates correct files
- Test `policyshield validate` passes on generated rules

## Self-check

```bash
pytest tests/test_init_scaffold.py -v
policyshield init --preset coding-agent --no-interactive /tmp/test-agent && policyshield validate /tmp/test-agent/policies/
```

## Commit

```
feat(cli): add coding-agent, data-analyst, customer-support presets
```
