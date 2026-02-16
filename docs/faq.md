# Frequently Asked Questions

## General

### What is PolicyShield?

PolicyShield is a declarative runtime firewall for AI agent tool calls. It sits between the LLM's decision to call a tool and the actual tool execution, enforcing security policies defined in YAML.

### How is PolicyShield different from prompt engineering?

Prompt engineering asks the LLM to behave well. PolicyShield **enforces** behavior regardless of what the LLM decides. Even if the LLM ignores instructions and tries to run `rm -rf /`, PolicyShield blocks it before execution.

### Does PolicyShield require a GPU?

No. PolicyShield is pure Python with no ML inference. It uses pattern matching, not AI, so it runs on any CPU with <5ms latency per check.

### Which LLM frameworks does PolicyShield support?

Any framework that makes tool calls. Native adapters exist for:
- **OpenClaw** (native plugin)
- **LangChain** (callback handler)
- **CrewAI** (tool wrapper)

Any other framework can integrate via the HTTP server API.

---

## Rules & Configuration

### What format are rules written in?

YAML. Here's a minimal rule:

```yaml
rules:
  - id: block-shell
    when:
      tool: exec
    then: BLOCK
    message: "Shell execution blocked"
```

### What verdicts are available?

| Verdict | Behavior |
|---------|----------|
| `ALLOW` | Tool call proceeds normally |
| `BLOCK` | Tool call is prevented |
| `REDACT` | PII is masked in arguments, tool call proceeds |
| `APPROVE` | Tool call paused until human approves/denies |

### Can I match tool arguments?

Yes, using `args_match`:

```yaml
- id: block-dangerous-urls
  when:
    tool: web_fetch
    args_match:
      url: { contains: "malware.com" }
  then: BLOCK
```

Supported matchers: `eq`, `contains`, `not_contains`, `regex`, `not_regex`, `gt`, `lt`.

### Can I use regex in rules?

Yes:

```yaml
args_match:
  command: { regex: "rm\\s+-rf" }
```

### How do I test rules without a server?

Use the playground command:

```bash
# Interactive mode
policyshield playground --rules rules.yaml

# Single check
policyshield playground --rules rules.yaml --tool exec --args '{"command": "rm -rf /"}'
```

### Does PolicyShield support hot-reloading?

Yes. Start the server with `--reload`:

```bash
policyshield server --rules rules.yaml --reload
```

Rules are automatically reloaded when the YAML file changes.

---

## PII Detection

### What PII types are detected?

Built-in patterns:
- Email addresses
- Phone numbers
- Social Security Numbers (SSN)
- Credit card numbers
- IP addresses
- Passport numbers

You can add custom patterns in your rules file:

```yaml
pii_patterns:
  - name: EMPLOYEE_ID
    pattern: "EMP-\\d{6}"
```

### Does PII detection use AI/ML?

Currently, PII detection is regex-based (L0). NER-based detection (L1) using spaCy/Presidio is on the roadmap.

### Can I disable PII detection?

PII detection only runs for rules with `then: REDACT`. If you don't have any REDACT rules, no PII scanning occurs.

---

## Deployment

### How do I run PolicyShield in production?

```bash
# Install with server extras
pip install policyshield[server]

# Start with strict defaults
POLICYSHIELD_API_TOKEN="your-secret-token" \
policyshield server --rules rules.yaml --host 127.0.0.1 --port 8100
```

Or use Docker:

```bash
docker run -p 8100:8100 -v ./rules.yaml:/app/rules.yaml \
  policyshield server --rules /app/rules.yaml
```

### What is `fail_open` vs `fail_closed`?

| Setting | Behavior when server is unreachable |
|---------|--------------------------------------|
| `fail_open: true` | Tool calls are ALLOWED (less safe, more available) |
| `fail_open: false` | Tool calls are BLOCKED (safe, but agent stops working) |

**Production recommendation:** `fail_open: false` (fail-closed).

### What's the performance impact?

Negligible. Benchmarks on commodity hardware:

| Operation | p50 | p99 |
|-----------|-----|-----|
| Sync check (ALLOW) | 0.01ms | 0.01ms |
| Sync check (BLOCK) | 0.01ms | 0.01ms |
| Async check | 0.05ms | 0.10ms |

The <5ms overhead is invisible compared to LLM inference time (seconds).

---

## Human-in-the-Loop (APPROVE)

### How does the APPROVE flow work?

1. Rule with `then: APPROVE` matches a tool call
2. PolicyShield returns a pending approval ID
3. Human reviews via Telegram or REST API
4. Once approved/denied, the agent continues

### What approval backends are supported?

- **Telegram** — receive approval requests as bot messages
- **REST API** — POST to `/api/v1/approve/{request_id}`
- **InMemory** — for testing, approvals via the same REST API

### What happens if nobody approves?

The tool call stays pending until the configured timeout expires. The timeout behavior depends on the client integration.

---

## Troubleshooting

### "Connection refused" when starting OpenClaw plugin

Make sure the PolicyShield server is running:

```bash
policyshield server --rules rules.yaml --port 8100
```

Then verify: `curl http://localhost:8100/api/v1/health`

### Rules aren't matching

1. Validate your rules: `policyshield validate rules.yaml`
2. Lint for issues: `policyshield lint rules.yaml`
3. Test with playground: `policyshield playground --rules rules.yaml`
4. Check tool name matches exactly (case-sensitive)

### PII not being detected

Check that your rule uses `then: REDACT` and the PII pattern matches your data format. Test with:

```bash
policyshield playground --rules rules.yaml \
  --tool send_email \
  --args '{"body": "Contact john@example.com"}'
```

---

## Chain Rules

### What are chain rules?

Chain rules let you define **temporal conditions** that detect multi-step attack patterns. For example, you can block `send_email` if `read_database` was called within the last 2 minutes — catching data exfiltration.

### How do chain rules work?

PolicyShield maintains a per-session `EventRingBuffer` that records recent tool calls. When a chain rule is evaluated, the buffer is searched for matching prior events within the specified time window.

### Can I chain multiple steps?

Yes. Each chain step is an independent condition. All must match for the rule to trigger:

```yaml
chain:
  - tool: read_database
    within_seconds: 120
  - tool: download_file
    within_seconds: 60
```

---

## AI Rule Generation

### How do I generate rules with AI?

```bash
# Set your API key
export OPENAI_API_KEY="sk-..."

# Generate rules from natural language
policyshield generate "Block all file deletions and require approval for deploys"
```

You can also use `--template` mode for offline generation without an API key.

### Which LLM providers are supported?

- **OpenAI** (default) — `gpt-4o`, `gpt-4o-mini`, etc.
- **Anthropic** — `claude-sonnet-4-20250514`, etc.

Install the AI extras: `pip install "policyshield[ai]"`

### Can I generate rules without an API key?

Yes, use template mode: `policyshield generate --template --tools <tool1> <tool2>`. This classifies tools by danger level and generates rules from built-in templates.
