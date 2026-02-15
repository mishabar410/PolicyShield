# Use Cases

Real-world scenarios where PolicyShield protects AI agent deployments.

## 🏦 Financial Services

**Problem:** AI agent processes customer requests and can access account APIs, transfer funds, and generate reports. Risk of unauthorized transactions, data leakage, or social engineering via prompt injection.

```yaml
rules:
  - id: block-large-transfers
    when:
      tool: transfer_funds
      args_match:
        amount: { gt: 10000 }
    then: approve
    message: "Transfers over $10,000 require human approval"

  - id: redact-account-numbers
    when:
      tool: [send_email, generate_report, web_fetch]
    then: redact
    message: "Account numbers and SSNs redacted from outgoing data"

  - id: rate-limit-transactions
    when:
      tool: transfer_funds
      session:
        tool_count.transfer_funds: { gt: 5 }
    then: block
    message: "Transaction rate limit exceeded"

pii_patterns:
  - name: ACCOUNT_NUMBER
    pattern: "\\b\\d{10,12}\\b"
```

---

## 🏥 Healthcare / HIPAA

**Problem:** AI assistant accesses patient records, generates summaries, and communicates with staff. PHI (Protected Health Information) must never leave the system unredacted.

```yaml
shield_name: hipaa-agent
version: 1
rules:
  - id: redact-phi-outgoing
    when:
      tool: [send_message, send_email, web_fetch, write_file]
    then: redact
    message: "PHI redacted before transmission"

  - id: block-external-export
    when:
      tool: web_fetch
      args_match:
        url: { not_contains: "internal.hospital.org" }
    then: block
    message: "External API calls blocked — PHI containment"

  - id: approve-record-modification
    when:
      tool: update_patient_record
    then: approve
    message: "Patient record changes require clinician approval"

pii_patterns:
  - name: MRN
    pattern: "MRN[:\\s]?\\d{7,10}"
  - name: DIAGNOSIS_CODE
    pattern: "\\b[A-Z]\\d{2}\\.\\d{1,4}\\b"
```

---

## 🛡️ DevOps / Infrastructure Agent

**Problem:** AI agent manages servers, deploys code, and runs shell commands. A single hallucinated command could take down production.

```yaml
shield_name: devops-agent
version: 1
rules:
  - id: block-destructive-commands
    when:
      tool: exec
      args_match:
        command: { regex: "rm\\s+-rf|mkfs|dd\\s+if=|:(){ :|:& };:|shutdown|reboot|init\\s+0" }
    then: block
    severity: critical
    message: "Destructive system command blocked"

  - id: approve-production-deploy
    when:
      tool: exec
      args_match:
        command: { contains: "deploy" }
        environment: { eq: "production" }
    then: approve
    message: "Production deployments require approval"

  - id: block-env-dump
    when:
      tool: exec
      args_match:
        command: { regex: "^(env|printenv|set)$" }
    then: block
    message: "Environment variable dumps blocked — secrets protection"

  - id: rate-limit-commands
    when:
      tool: exec
      session:
        tool_count.exec: { gt: 50 }
    then: block
    message: "Command execution rate limit — possible runaway loop"

rate_limits:
  - tool: exec
    max_calls: 50
    window_seconds: 300
    per_session: true
```

---

## 📧 Customer Support Agent

**Problem:** AI handles customer conversations, accesses CRMs, and sends emails. Must not leak customer data or send inappropriate responses.

```yaml
shield_name: support-agent
version: 1
rules:
  - id: redact-pii-in-replies
    when:
      tool: [send_email, send_message, post_to_slack]
    then: redact
    message: "Customer PII redacted from outgoing messages"

  - id: approve-refunds
    when:
      tool: process_refund
      args_match:
        amount: { gt: 100 }
    then: approve
    message: "Refunds over $100 require supervisor approval"

  - id: block-account-deletion
    when:
      tool: delete_account
    then: block
    message: "Account deletion is not allowed via AI agent"

  - id: block-bulk-emails
    when:
      tool: send_email
      session:
        tool_count.send_email: { gt: 10 }
    then: block
    message: "Bulk email sending blocked — possible spam"
```

---

## 🔬 Research / Data Science Agent

**Problem:** AI agent queries databases, generates visualizations, and shares results. Must not expose raw datasets or proprietary formulas.

```yaml
shield_name: research-agent
version: 1
rules:
  - id: block-raw-data-export
    when:
      tool: [web_fetch, send_email]
      args_match:
        body: { regex: "SELECT\\s+\\*|EXPORT|DUMP" }
    then: block
    message: "Raw data export blocked — use aggregated views only"

  - id: redact-pii-in-results
    when:
      tool: [write_file, send_message]
    then: redact
    message: "PII redacted from research outputs"

  - id: approve-external-sharing
    when:
      tool: share_document
      args_match:
        visibility: { eq: "external" }
    then: approve
    message: "External document sharing requires PI approval"
```

---

## Getting Started

All use cases above use standard PolicyShield YAML rules. To try one:

```bash
# 1. Install
pip install policyshield

# 2. Save any of the above as rules.yaml
# 3. Validate
policyshield validate rules.yaml
policyshield lint rules.yaml

# 4. Test
policyshield test rules.yaml
```

See the [Writing Rules](guides/writing-rules.md) guide for the full DSL reference.
