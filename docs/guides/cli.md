# CLI Reference

## Commands

### `policyshield init`

Scaffold a new PolicyShield project.

```bash
policyshield init [directory] [--preset PRESET] [--nanobot] [--no-interactive]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `directory` | `./policyshield-project` | Output directory |
| `--preset` | `minimal` | Preset: `minimal`, `security`, `compliance` |
| `--nanobot` | — | Include nanobot-specific rules |
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

### `policyshield nanobot`

Run nanobot with PolicyShield enforcement.

```bash
policyshield nanobot --rules <rules.yaml> [--mode MODE] [--fail-open|--fail-closed] -- [nanobot args...]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `--rules` | *required* | Path to rules YAML |
| `--mode` | `ENFORCE` | `ENFORCE`, `AUDIT`, `DISABLED` |
| `--fail-open` | — | Allow calls on shield errors |
| `--fail-closed` | — | Block calls on shield errors |

### `policyshield trace export`

Export traces to a file.

```bash
policyshield trace export --format json --output traces.json
```
