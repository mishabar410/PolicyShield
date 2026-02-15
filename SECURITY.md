# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.9.x   | ✅ Current |
| 0.8.x   | ⚠️ Critical fixes only |
| < 0.8   | ❌ No longer supported |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please email **mb050574@gmail.com** with:

1. Description of the vulnerability
2. Steps to reproduce
3. Affected version(s)
4. Potential impact assessment

We will acknowledge receipt within **48 hours** and provide a detailed response within **5 business days**.

## Threat Model

PolicyShield operates as a runtime firewall between an LLM's tool-call decisions and the actual tool execution. The threat model addresses risks specific to this position in the stack.

### Assets Protected

| Asset | Description |
|-------|-------------|
| **Tool execution boundary** | Preventing unauthorized or dangerous tool calls from executing |
| **PII in tool arguments** | Email, phone, SSN, credit card, passport numbers in outgoing calls |
| **PII in tool output** | Sensitive data returned by tools (detected but not blocked — see Limitations) |
| **Audit trail integrity** | JSONL trace records of all tool calls and verdicts |
| **Rule confidentiality** | YAML policy rules may reveal security posture |

### Threat Categories

#### T1: Rule Bypass via Argument Obfuscation

**Risk:** An LLM could encode arguments to evade regex-based rules (e.g., base64-encoding a shell command, Unicode homoglyphs in PII).

**Mitigation:**
- Input sanitizer normalizes Unicode, decodes common encodings before rule evaluation
- Rules support regex patterns that can match encoded forms
- Defense-in-depth: PolicyShield is one layer, not the only layer

**Residual risk:** Novel encoding schemes may bypass regex patterns. NER-based PII detection (L1) is on the roadmap to address semantic evasion.

#### T2: Server Denial of Service

**Risk:** Flooding the `/api/v1/check` endpoint to slow down or crash the server, causing `fail_open` to allow all calls.

**Mitigation:**
- `fail_open: false` option blocks all calls when server is unreachable
- FastAPI with uvicorn handles concurrent requests efficiently
- Performance budget: <5ms p99 per check minimizes resource consumption per request

**Recommendation:** Deploy behind a reverse proxy (nginx, Caddy) with rate limiting in production.

#### T3: Tampering with Rules File

**Risk:** An attacker with filesystem access modifies `rules.yaml` to weaken policies.

**Mitigation:**
- Rules file should be read-only for the PolicyShield process
- Hot-reload watches for changes but does not validate file integrity
- Git-tracked rules provide change audit trail

**Recommendation:** Use file integrity monitoring (AIDE, OSSEC) on rule files in production.

#### T4: Prompt Injection via Tool Arguments

**Risk:** Crafted tool arguments contain prompt injection payloads that could influence subsequent LLM behavior.

**Mitigation:**
- Input sanitizer detects common prompt injection patterns
- PolicyShield evaluates arguments as data, not instructions — it is not an LLM
- BLOCK verdict prevents the tool from executing, cutting the injection chain

#### T5: API Token Exposure

**Risk:** The `POLICYSHIELD_API_TOKEN` or Telegram bot token could be leaked.

**Mitigation:**
- Tokens are passed via environment variables, never in config files
- Bearer token authentication on all API endpoints when `POLICYSHIELD_API_TOKEN` is set
- Telegram token is server-side only, never exposed to the plugin

**Recommendation:** Rotate tokens regularly. Use secrets management (Vault, AWS Secrets Manager) in production.

#### T6: Audit Trail Tampering

**Risk:** An attacker modifies or deletes JSONL trace files to cover tracks.

**Mitigation:**
- Trace files are append-only during runtime
- Export to external systems (OpenTelemetry → Jaeger/Grafana) provides tamper-resistant copies

**Recommendation:** Forward traces to a centralized, immutable logging system (ELK, Loki, CloudWatch).

### Limitations (Explicit)

| Limitation | Impact | Mitigation |
|-----------|--------|------------|
| PII detection is regex-based (L0) | False positives/negatives possible | Custom patterns + NER on roadmap |
| `after_tool_call` cannot block output | PII in tool output is logged but not redacted | Enable `taint_chain` to block subsequent outgoing calls |
| Two-process architecture | HTTP round-trip adds ~1-5ms latency | Acceptable vs LLM inference time (seconds) |
| No rule file signature verification | Modified rules are loaded without integrity check | Use file integrity monitoring |
| No encryption at rest for traces | JSONL files contain tool call details | Encrypt filesystem or use encrypted logging backend |

### Security Configuration Checklist

For production deployments:

```yaml
# rules.yaml — use strict defaults
default_verdict: BLOCK          # Zero-trust: block unmatched calls
```

```bash
# Environment — set all security vars
export POLICYSHIELD_API_TOKEN="<random-32-char-token>"
export POLICYSHIELD_TELEGRAM_TOKEN="..."      # If using Telegram approval
export POLICYSHIELD_TELEGRAM_CHAT_ID="..."

# Server — bind to localhost only
policyshield server --rules rules.yaml --port 8100 --host 127.0.0.1
```

```json
// OpenClaw plugin config — fail-closed for production
{
  "plugins": {
    "entries": {
      "policyshield": {
        "config": {
          "fail_open": false,
          "timeout_ms": 3000
        }
      }
    }
  }
}
```

## Disclosure Policy

- We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure)
- Security fixes are released as patch versions (e.g., 0.9.1)
- CVE identifiers are requested for confirmed vulnerabilities
- Credit is given to reporters unless they prefer anonymity
