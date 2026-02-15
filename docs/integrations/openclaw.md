# OpenClaw Integration

PolicyShield integrates natively with [OpenClaw](https://github.com/AgenturAI/OpenClaw) as a plugin
that intercepts every tool call and enforces declarative YAML-based security policies.

> Verified with **OpenClaw 2026.2.13** and **PolicyShield 0.8.1**.

## Architecture

```
┌──────────────────────────────────────────┐
│             OpenClaw Agent               │
│                                          │
│   LLM → tool_call(name, args)            │
│               │                          │
│               ▼                          │
│   ┌────────────────────────────────┐     │
│   │   PolicyShield Plugin (TS)     │     │
│   │                                │     │
│   │  before_agent_start            │     │
│   │    → inject policy constraints │     │
│   │  before_tool_call              │     │
│   │    → BLOCK / REDACT / APPROVE  │     │
│   │  after_tool_call               │     │
│   │    → scan output for PII       │     │
│   └────────────┬───────────────────┘     │
│                │ HTTP (localhost)         │
│                ▼                         │
│   ┌────────────────────────────────┐     │
│   │   PolicyShield Server          │     │
│   │   (Python + FastAPI)           │     │
│   │                                │     │
│   │   /api/v1/check                │     │
│   │   /api/v1/post-check           │     │
│   │   /api/v1/constraints          │     │
│   │   /api/v1/health               │     │
│   └────────────────────────────────┘     │
└──────────────────────────────────────────┘
```

The plugin communicates with the PolicyShield server over HTTP on every tool call.
The server evaluates YAML rules and returns a verdict: **ALLOW**, **BLOCK**, **REDACT**, or **APPROVE**.

---

## Step-by-Step Setup

### Step 1: Install and start the PolicyShield server

```bash
pip install "policyshield[server]"

# Generate rules optimized for OpenClaw tools
policyshield init --preset openclaw --no-interactive
# → creates rules.yaml with 11 rules (see below)

# Start the server (default port: 8100)
policyshield server --rules rules.yaml --port 8100
```

Verify the server is running:

```bash
curl http://localhost:8100/api/v1/health
# → {"status":"ok","shield_name":"openclaw-policy","version":1,"rules_count":11,"mode":"ENFORCE"}
```

### Step 2: Install the PolicyShield plugin into OpenClaw

```bash
# From npm (published package)
npm install --prefix ~/.openclaw/extensions/policyshield @policyshield/openclaw-plugin
cp -r ~/.openclaw/extensions/policyshield/node_modules/@policyshield/openclaw-plugin/* \
     ~/.openclaw/extensions/policyshield/

# Or from a local directory (for development)
cp -r ./plugins/openclaw ~/.openclaw/extensions/policyshield
cd ~/.openclaw/extensions/policyshield && npm install
```

After installation, the plugin files are located at:

```
~/.openclaw/extensions/policyshield/
```

### Step 3: Configure the plugin

Add the plugin entry to `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "enabled": true,
    "entries": {
      "policyshield": {
        "enabled": true,
        "config": {
          "url": "http://localhost:8100",
          "fail_open": true,
          "timeout_ms": 5000
        }
      }
    }
  }
}
```

### Step 4: Verify the plugin is loaded

```bash
openclaw plugins info policyshield
```

Expected output:

```
PolicyShield
id: policyshield
PolicyShield — runtime policy enforcement for AI agent tool calls

Status: loaded
Source: ~/.openclaw/extensions/policyshield/dist/index.js
Version: 0.8.1
✓ Connected to PolicyShield server
```

If you see `⚠ PolicyShield server unreachable`, check that:

1. The PolicyShield server is running
2. The URL is correct (`openclaw config set plugins.entries.policyshield.config.url ...`)
3. The port matches (default is `8100`)

### Step 5: Test with a real agent

```bash
# Run an agent with a dangerous prompt — PolicyShield should block it
openclaw agent --local --session-id test -m "Run the shell command: rm -rf /"

# Expected response: "I'm unable to execute that command as it is considered
# destructive and is blocked by policy."
```

---

## Plugin Hooks

| Hook | When | What it does |
|------|------|-------------|
| `before_agent_start` | Agent session starts | Fetches `/api/v1/constraints` and injects all active rules into the LLM system prompt |
| `before_tool_call` | Before every tool execution | Calls `/api/v1/check` → returns ALLOW, BLOCK, REDACT, or APPROVE |
| `after_tool_call` | After every tool execution | Calls `/api/v1/post-check` → scans tool output for PII leaks |

### Verdict Handling

| Verdict | Plugin Action |
|---------|--------------|
| **ALLOW** | Tool call proceeds normally |
| **BLOCK** | Tool call is cancelled, agent receives block reason message |
| **REDACT** | Tool arguments are modified (PII masked), then tool call proceeds |
| **APPROVE** | Plugin polls `/api/v1/check-approval` until human approves/denies or timeout |

---

## Configuration Reference

All settings are configured via the OpenClaw CLI:

```bash
openclaw config set plugins.entries.policyshield.config.<key> <value>
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `url` | string | `http://localhost:8100` | PolicyShield server URL |
| `mode` | string | `enforce` | `enforce` (block/redact active) or `disabled` (passthrough) |
| `fail_open` | boolean | `true` | Allow tool calls when server is unreachable |
| `timeout_ms` | number | `5000` | HTTP request timeout per check (ms) |
| `approve_timeout_ms` | number | `60000` | Max time to wait for human approval (ms) |
| `approve_poll_interval_ms` | number | `2000` | Polling interval for approval status (ms) |
| `max_result_bytes` | number | `10000` | Max bytes of tool output sent for PII scanning |

---

## OpenClaw Preset Rules

Generate rules specifically for OpenClaw's built-in tools:

```bash
policyshield init --preset openclaw
```

This generates 11 rules covering:

| Category | Rules |
|----------|-------|
| **Block** | Destructive shell commands (`rm -rf`, `mkfs`, `dd if=`) |
| **Block** | Remote code execution (`curl \| sh`, `wget \| bash`) |
| **Block** | Secrets exfiltration (`curl ... $API_KEY`) |
| **Block** | Environment variable dumps (`env`, `printenv`) |
| **Redact** | PII in outgoing messages, file writes, and file edits |
| **Approve** | Writing to sensitive files (`.env`, `.pem`, `.key`, SSH keys) |
| **Rate-limit** | `exec` tool (60 calls per session) |
| **Rate-limit** | `web_fetch` tool (30 calls per session) |

OpenClaw's built-in tools recognized by the preset:
`exec`, `read`, `write`, `edit`, `message`, `web_fetch`, `web_search`, `browser`,
`canvas`, `image`, `gateway`, `cron`, `tts`, `memory_search`, `memory_get`,
`sessions_send`, `sessions_spawn`, `sessions_list`, `sessions_history`,
`session_status`, `agents_list`.

---

## Graceful Degradation

When `fail_open: true` (default):

- **Server unreachable**: tool calls are allowed with a warning logged
- **Timeout**: tool calls proceed as if allowed
- **Server error**: tool calls proceed as if allowed
- All failures are recorded on the server-side audit trail

When `fail_open: false`:

- **Server unreachable**: tool calls are **blocked**
- This is the safer option for production deployments

---

## Docker Deployment

Run the PolicyShield server in Docker alongside OpenClaw:

```bash
docker build -f Dockerfile.server -t policyshield-server .
docker run -d \
  -p 8100:8100 \
  -v ./rules.yaml:/app/rules.yaml \
  --name policyshield \
  policyshield-server
```

Or use docker-compose:

```yaml
services:
  policyshield:
    build:
      context: .
      dockerfile: Dockerfile.server
    ports:
      - "8100:8100"
    volumes:
      - ./rules.yaml:/app/rules.yaml
    restart: unless-stopped
```

Then point the OpenClaw plugin to the Docker container:

```bash
openclaw config set plugins.entries.policyshield.config.url http://localhost:8100
```

---

## Troubleshooting

### Plugin shows "server unreachable"

```
⚠ PolicyShield server unreachable — running in degraded mode
```

**Fix:** Check the server URL and port:

```bash
# Verify server is running
curl http://localhost:8100/api/v1/health

# Update plugin URL if using a different port
openclaw config set plugins.entries.policyshield.config.url http://localhost:<PORT>
```

### Plugin ID mismatch warning

```
plugins.entries.policyshield: plugin id mismatch (manifest uses "policyshield", entry hints "openclaw-plugin")
```

**Fix:** This is a cosmetic warning from the install process. It doesn't affect functionality.
To silence it, ensure the extension directory name matches the plugin ID:

```bash
mv ~/.openclaw/extensions/openclaw-plugin ~/.openclaw/extensions/policyshield
```

### Agent can't find API key

```
No API key found for provider "anthropic"
```

**Fix:** Set the model provider and API key:

```bash
# Set the agent model to OpenAI (or your preferred provider)
openclaw config set agents.list '[{"id":"main","model":"openai/gpt-4o-mini"}]'

# Create the auth profile
mkdir -p ~/.openclaw/agents/main/agent
cat > ~/.openclaw/agents/main/agent/auth-profiles.json << EOF
{
  "openai": {
    "apiKey": "sk-..."
  }
}
EOF
```

### Plugin not listed

```bash
# List all plugins
openclaw plugins list

# Check plugin details
openclaw plugins info policyshield
```

If the plugin is missing, reinstall:

```bash
npm install --prefix ~/.openclaw/extensions/policyshield @policyshield/openclaw-plugin
cp -r ~/.openclaw/extensions/policyshield/node_modules/@policyshield/openclaw-plugin/* \
     ~/.openclaw/extensions/policyshield/
```

---

## Compatibility

### Version Matrix

| PolicyShield Server | PolicyShield Plugin | OpenClaw | Status |
|---------------------|---------------------|----------|--------|
| 0.9.x               | 0.9.x               | ≥ 2026.2 | ✅ Verified (E2E) |
| 0.8.x               | 0.8.x               | ≥ 2026.2 | ✅ Verified (unit tests) |
| ≤ 0.7.x             | ≤ 0.7.x             | —        | ❌ Incompatible (API mismatch) |

> **Important:** Server and plugin versions should always match (both 0.9.x).
> Cross-version combinations (e.g., server 0.8 + plugin 0.9) are not tested.

### How We Verify

- **E2E tests** run on every PR: Docker Compose stack with real OpenClaw + PolicyShield
- **SDK type sync** checked weekly: CI compares our stubs with upstream OpenClaw types
- **Plugin unit tests** with mocked API cover all hook signatures

---

## Limitations & Trade-offs

### Output PII Scanning — Cannot Block

The `after_tool_call` hook in OpenClaw's plugin SDK returns `void`. This means:

- ✅ PolicyShield **detects** PII in tool output (email, phone, SSN, etc.)
- ✅ PolicyShield **logs** PII detection as an audit event
- ✅ PolicyShield **taints** the session (if `taint_chain` is enabled)
- ❌ PolicyShield **cannot modify or block** the output — it has already been delivered to the agent

**Mitigation:** Enable `taint_chain` in your rules to block subsequent outgoing calls (like `send_message`, `web_fetch`) after PII is detected in output:

```yaml
taint_chain:
  enabled: true
  outgoing_tools: [send_message, web_fetch, exec]
```

This prevents the agent from **leaking** PII to external services, even though it has already **seen** the PII.

### Two-Process Architecture

PolicyShield runs as a separate Python process from OpenClaw (Node.js). This means:

- **Latency:** Each tool call adds an HTTP round-trip (~1-5ms on localhost)
- **Deployment:** Two processes to manage (or use Docker Compose)
- **Failure mode:** If PolicyShield crashes, behavior depends on `fail_open` config

### Regex-Based PII Detection

Current PII detection uses regex patterns (Level 0). This means:

- ✅ Fast (<1ms per scan)
- ❌ May produce false positives (e.g., numbers that look like phone numbers)
- ❌ Cannot detect semantic PII (e.g., "call John at his home number")
- 🔜 NER-based detection (Level 1) is on the roadmap

---

## Upgrading

See the [Migration Guide](openclaw-migration.md) for version-specific upgrade instructions.
