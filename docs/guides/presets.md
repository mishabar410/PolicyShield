# Presets

PolicyShield includes three built-in presets for common use cases.

## Minimal

Basic rules for getting started. Includes soft-blocking shell execution.

```bash
policyshield init --preset minimal
```

## Security

Production-ready security rules including:

- Block destructive shell commands
- Block PII in web requests
- Block writes outside workspace
- Approve network downloads

```bash
policyshield init --preset security
```

## Compliance

Compliance-focused rules including:

- Redact PII in all tool calls
- Require approval for delete operations
- Rate-limit API calls
- Audit all shell commands

```bash
policyshield init --preset compliance
```

## Custom presets

Create your own rules by editing the generated `policies/rules.yaml`:

```bash
policyshield init --preset minimal
# Edit policies/rules.yaml to add your rules
policyshield validate policies/
policyshield lint policies/rules.yaml
```
