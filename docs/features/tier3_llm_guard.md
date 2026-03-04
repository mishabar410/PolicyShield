# 🧠 Tier 3 — LLM Guard (Advanced Capabilities)

Architecture: **LLM Guard as optional middleware** in the pipeline. Without LLM — everything works at 0ms. With LLM — +200-500ms, but catches what regex cannot. Enabled per-rule.

```
Tool Call → Sanitizer → Regex Rules → [LLM Guard] → Verdict
```

> **v0.14.0 status:** Core LLM Guard middleware is implemented with async threat detection, response caching, and fail-open/closed behavior. The capabilities below are **planned for future releases**.

---

### Semantic PII Detection

LLM-based PII as a second pass after regex — catches context-dependent PII that patterns miss.

- **Effort**: Medium | **Latency**: +300ms

### Intent Classification

LLM sees **intent**: agent read DB → calls `send_http` with the same data → exfiltration.

```yaml
llm_guard:
  checks:
    - intent_classification
    - exfiltration_detection
  on_suspicious: APPROVE
  on_malicious: BLOCK
```

- **Effort**: Large | **Latency**: +500ms

### Explainable Verdicts

LLM generates explanations on block:

```json
{
  "verdict": "BLOCK",
  "explanation": "Agent attempted to send database contents via HTTP.",
  "risk_score": 0.92,
  "recommendation": "If intended, add rule 'allow-export-reports'"
}
```

- **Effort**: Small | **Latency**: +200ms

### Anomaly Detection

Statistical baseline: "agent usually calls read_file 5-10 times", 200 delete calls = anomaly.

- **Effort**: Large | **Latency**: +5ms (statistics) or +500ms (LLM)

### Multi-Step Plan Analysis

Evaluate the agent's entire plan before execution:

```
Plan: 1) read_database → 2) format_csv → 3) send_email
Risk: HIGH — data from step 1 leaves system at step 3
```

- **Effort**: Large (requires access to agent's plan) | **Latency**: +500ms
