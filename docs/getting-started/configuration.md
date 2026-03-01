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

## Slack Approval Backend

In addition to Telegram, you can use Slack for approval notifications:

| Env Var | Description |
|---------|-------------|
| `POLICYSHIELD_SLACK_WEBHOOK_URL` | Slack Incoming Webhook URL |

- **Set** → Slack backend (sends approval requests via webhook)
- **Not set** → Falls back to Telegram (if configured) or InMemory

```bash
POLICYSHIELD_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..." \
policyshield server --rules rules.yaml --port 8100
```

## LLM Guard

LLM Guard is an optional async middleware that adds LLM-based threat detection to the pipeline. Without it, PolicyShield uses only regex-based rules (0ms overhead). With it, tool call arguments are analyzed by an LLM for threats (+200-500ms).

| Env Var | Description |
|---------|-------------|
| `OPENAI_API_KEY` | Required for LLM Guard (uses OpenAI models) |
| `POLICYSHIELD_LLM_GUARD_ENABLED` | Enable LLM Guard (`true`/`false`, default: `false`) |
| `POLICYSHIELD_LLM_GUARD_MODEL` | Model to use (default: `gpt-4o-mini`) |
| `POLICYSHIELD_LLM_GUARD_TIMEOUT` | Max seconds per LLM check (default: `2.0`) |
| `POLICYSHIELD_LLM_GUARD_CACHE_TTL` | Cache TTL in seconds (default: `300`) |
| `POLICYSHIELD_LLM_GUARD_FAIL_OPEN` | Behavior on LLM failure: `true` = allow, `false` = block |

```python
# Pipeline with LLM Guard:
# Tool Call → Sanitizer → Regex Rules → [LLM Guard] → Verdict
```

## NL Policy Compiler

Compile natural language descriptions into validated YAML rules:

```bash
OPENAI_API_KEY="sk-..." policyshield compile "Block file deletions" -o rules.yaml
OPENAI_API_KEY="sk-..." policyshield compile --file restrictions.md -o rules.yaml
```

The compiler uses a two-stage pipeline: LLM generates YAML → `policyshield validate` verifies. If validation fails, the LLM auto-corrects.
