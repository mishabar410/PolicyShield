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

## Approval Backend

The APPROVE verdict requires a backend to handle approval requests. The server auto-selects based on environment variables:

| Env Var | Description |
|---------|-------------|
| `POLICYSHIELD_TELEGRAM_TOKEN` | Telegram Bot API token (from [@BotFather](https://t.me/BotFather)) |
| `POLICYSHIELD_TELEGRAM_CHAT_ID` | Chat or group ID to send approval requests to |

- **Both set** → Telegram backend (sends messages with ✅/❌ inline buttons)
- **Not set** → InMemory backend (manage via `/api/v1/respond-approval` REST endpoint)

```bash
# Telegram mode
POLICYSHIELD_TELEGRAM_TOKEN="..." \
POLICYSHIELD_TELEGRAM_CHAT_ID="..." \
policyshield server --rules rules.yaml --port 8100

# InMemory mode (default)
policyshield server --rules rules.yaml --port 8100
```

## AI Rule Generation

The `policyshield generate` command can use LLMs to generate rules. Set the appropriate environment variable:

| Env Var | Description |
|---------|-------------|
| `OPENAI_API_KEY` | OpenAI API key (for `--provider openai`, the default) |
| `ANTHROPIC_API_KEY` | Anthropic API key (for `--provider anthropic`) |

Install the AI extras: `pip install "policyshield[ai]"`

```bash
# Generate rules with OpenAI
OPENAI_API_KEY="sk-..." policyshield generate "Block file deletions"

# Generate rules with Anthropic
ANTHROPIC_API_KEY="..." policyshield generate "Block file deletions" --provider anthropic
```
