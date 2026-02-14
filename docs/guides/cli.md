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
| `--preset` | `minimal` | Preset: `minimal`, `security`, `compliance` |
| `--no-interactive` | — | Non-interactive mode |

### `policyshield validate`

Validate rule YAML files.

```bash
policyshield validate <path>
```

### `policyshield lint`

Check rules for best practices.

```bash
policyshield lint <path>
```

### `policyshield test`

Run rule test cases.

```bash
policyshield test <path> [--verbose]
```

### `policyshield trace export`

Export traces to a file.

```bash
policyshield trace export --format json --output traces.json
```
