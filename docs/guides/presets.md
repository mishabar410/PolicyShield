# Presets

PolicyShield includes four built-in presets for common use cases.

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

## OpenClaw

Rules specifically designed for [OpenClaw](https://github.com/AgenturAI/OpenClaw) integration. Includes 11 rules covering:

- Block destructive shell commands (`rm -rf`, `mkfs`, etc.)
- Redact PII in web requests, messages, and search
- Block access to sensitive paths (`/etc/shadow`, SSH keys)
- Approve file deletion operations
- Rate-limit exec tool (60 calls per session)
- Rate-limit web fetch (10 calls per minute)
- Block subdomain enumeration

```bash
policyshield init --preset openclaw
```

## Custom presets

Create your own rules by editing the generated `policies/rules.yaml`:

```bash
policyshield init --preset minimal
# Edit policies/rules.yaml to add your rules
policyshield validate policies/
policyshield lint policies/rules.yaml
```
