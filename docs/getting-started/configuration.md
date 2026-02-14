# Configuration

PolicyShield reads configuration from `policyshield.yaml` in your project root.

## Configuration file

```yaml
# policyshield.yaml
mode: ENFORCE       # ENFORCE | AUDIT | DISABLED
fail_open: true     # Allow calls when shielding fails

trace:
  enabled: true
  output_dir: ./traces

```

## Options

| Key | Default | Description |
|-----|---------|-------------|
| `mode` | `ENFORCE` | Enforcement mode |
| `fail_open` | `true` | Fail-open behavior on errors |
| `trace.enabled` | `true` | Enable trace recording |
| `trace.output_dir` | `./traces` | Trace output directory |

## Modes

- **ENFORCE** — Block/redact/approve as rules dictate
- **AUDIT** — Log violations but allow all calls
- **DISABLED** — No enforcement, no logging

## CLI config commands

```bash
# Validate config file
policyshield config validate

# Show resolved config
policyshield config show
```
