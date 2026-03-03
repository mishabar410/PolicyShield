# Telegram Bot

PolicyShield includes a Telegram bot that lets you manage rules and the kill switch directly from Telegram — and compile new rules from natural language.

## Setup

```bash
pip install "policyshield[server]"

export TELEGRAM_BOT_TOKEN="your-bot-token"   # from @BotFather
export OPENAI_API_KEY="your-api-key"          # for NL compilation

policyshield bot --rules rules.yaml --server-url http://localhost:8100
```

| Argument | Default | Description |
|----------|---------|-------------|
| `--rules` | `rules.yaml` | Path to YAML rules file |
| `--server-url` | `http://localhost:8100` | PolicyShield server URL |
| `--admin-token` | — | Admin token for authenticated server commands |

Environment variables: `TELEGRAM_BOT_TOKEN`, `POLICYSHIELD_SERVER_URL`, `POLICYSHIELD_ADMIN_TOKEN`.

## Commands

| Command | Description |
|---------|-------------|
| `/start` | Welcome message and instructions |
| `/help` | List available commands |
| `/status` | Server health, rules count, mode |
| `/rules` | View active rules summary |
| `/kill [reason]` | Emergency kill switch — blocks ALL tool calls |
| `/resume` | Resume normal operation |
| `/compile <description>` | Preview YAML generated from natural language |
| `/apply <description>` | Compile + save + reload in one step |

## Natural Language → Live Rules

Send a plain-text policy description and the bot compiles it to validated YAML, then shows a preview with Deploy/Cancel buttons:

```
You:  Block all exec calls containing 'rm' and redact PII in send_message

Bot:  📜 Generated YAML:
      - id: block-rm-commands
        when:
          tool: exec
          args_match:
            command: { contains: rm }
        then: block
      [✅ Deploy] [❌ Cancel]
```

On **Deploy**:
1. Atomically writes rules to the rules file (temp file + `os.replace`)
2. Merges by rule ID — no duplicates
3. Backs up old rules file
4. Calls `/api/v1/reload` to hot-reload the engine

## Apply command

`/apply` is the most powerful command — it generates rules via LLM, replaces conflicting rules for the same tool, and reloads the engine in one step. New rules get `priority: 0` to override existing defaults.

## OpenClaw + Telegram

With the [OpenClaw plugin](openclaw.md) installed, you can use `/policyshield` as a prefix in your OpenClaw Telegram chat:

```
/policyshield status
/policyshield apply "Block file deletions and limit web_fetch to 30 per session"
```

## Architecture

```
  Telegram Chat
       │
       │ /apply "Block delete_file"
       ▼
  ┌────────────────────────┐
  │   PolicyBot            │
  │   (long-polling loop)  │
  └────────┬───────────────┘
           │
     ┌─────┴──────┐
     ▼             ▼
  PolicyCompiler   PolicyShield Server
  (LLM → YAML)    (/api/v1/reload)
```
