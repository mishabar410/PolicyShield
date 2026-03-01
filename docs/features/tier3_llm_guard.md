# 🧠 Tier 3 — LLM Guard (partially implemented in v0.14.0)

Архитектура: **LLM Guard как опциональный middleware** в pipeline. Без LLM — всё работает как сейчас (0ms). С LLM — +200-500ms, но ловит то, что regex не может. Включается per-rule.

```
Tool Call → Sanitizer → Regex Rules → [LLM Guard] → Verdict
```

> **v0.14.0 status:** Core LLM Guard middleware is implemented with async threat detection, response caching, and fail-open/closed behavior. Advanced capabilities (semantic PII, intent classification, multi-step plan analysis) are planned for future releases.

**Почему отдельный tier:** меняет value proposition с «бесплатный 0ms фаервол» на «платный медленный фаервол». Мощно, но не для первого знакомства.

### Prompt Injection Guard

LLM-классификатор проверяет аргументы тулов на prompt injection:

```yaml
sanitizer:
  prompt_injection_guard:
    enabled: true
    model: gpt-4o-mini
    action: BLOCK
```

- **Усилия**: Средние | **Latency**: +300ms

### Semantic PII Detection

LLM-based PII как второй проход после regex:

```yaml
pii:
  llm_scan: true
  llm_model: gpt-4o-mini
```

- **Усилия**: Средние | **Latency**: +300ms

### Intent Classification

LLM видит **намерение**: агент прочитал БД → вызывает `send_http` с теми же данными → exfiltration.

```yaml
llm_guard:
  checks:
    - intent_classification
    - exfiltration_detection
  on_suspicious: APPROVE
  on_malicious: BLOCK
```

- **Усилия**: Большие | **Latency**: +500ms

### Explainable Verdicts

LLM генерирует объяснение при блокировке:

```json
{
  "verdict": "BLOCK",
  "explanation": "Agent attempted to send database contents via HTTP.",
  "risk_score": 0.92,
  "recommendation": "If intended, add rule 'allow-export-reports'"
}
```

- **Усилия**: Маленькие | **Latency**: +200ms

### Anomaly Detection

Статистический baseline: «агент обычно делает read_file 5-10 раз», 200 вызовов delete — аномалия.

- **Усилия**: Большие | **Latency**: +5ms (статистика) или +500ms (LLM)

### Multi-Step Plan Analysis

Оценка плана агента целиком до выполнения:

```
Plan: 1) read_database → 2) format_csv → 3) send_email
Risk: HIGH — data from step 1 leaves system at step 3
```

- **Усилия**: Большие (нужен доступ к плану агента) | **Latency**: +500ms
