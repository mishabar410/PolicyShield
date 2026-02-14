# CLI Reference

## Commands

### `policyshield init`

Scaffold a new PolicyShield project.

```bash
policyshield init [directory] [--preset PRESET] [--no-interactive]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `directory` | `./policyshield-project` | Output directory |
| `--preset` | `minimal` | Preset: `minimal`, `security`, `compliance`, `openclaw` |
| `--no-interactive` | — | Non-interactive mode |

### `policyshield validate`

Validate rule YAML files.

```bash
policyshield validate <path>
```

### `policyshield lint`

Check rules for best practices (6 static checks).

```bash
policyshield lint <path>
```

### `policyshield test`

Run YAML test cases against your rules.

```bash
policyshield test <path> [--verbose]
```

### `policyshield server`

Start the HTTP policy enforcement server.

```bash
policyshield server --rules <path> [--port PORT] [--host HOST] [--mode MODE] [--workers N]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `--rules` | (required) | Path to rules YAML file |
| `--port` | `8100` | Server port |
| `--host` | `0.0.0.0` | Server host |
| `--mode` | `enforce` | Mode: `enforce`, `audit`, `disabled` |
| `--workers` | `1` | Number of uvicorn workers |

**Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/check` | POST | Pre-call policy check |
| `/api/v1/post-check` | POST | Post-call PII scanning |
| `/api/v1/health` | GET | Health check |
| `/api/v1/constraints` | GET | Human-readable policy summary |

### `policyshield trace`

Trace commands for audit log analysis.

```bash
# Show trace entries
policyshield trace show <trace-file>

# Show violations only
policyshield trace violations <trace-file>

# Aggregate stats
policyshield trace stats --dir <trace-dir> [--format json|table]

# Search traces
policyshield trace search --tool <name> --verdict <verdict>

# Cost estimation
policyshield trace cost --dir <trace-dir> --model <model>

# Export to CSV or HTML
policyshield trace export <trace-file> -f <format>

# Live web dashboard
policyshield trace dashboard [--port PORT] [--prometheus]
```

### `policyshield diff`

Compare two rule files.

```bash
policyshield diff <old-rules> <new-rules>
```
