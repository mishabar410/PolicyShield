# 🟡 Tier 2 — Medium Impact (после v1.0)

> **Перенесено в Tier 1.5 как v1.0-blockers:** Config Validation на старте, Retry/Backoff для Telegram,
> Idempotency, Approval Audit Trail. См. [tier1_5_critical.md](tier1_5_critical.md).

### ~~Config Validation на старте~~ → перенесено в Tier 1.5

> **Moved up.** Сервер не падает при невалидном конфиге — должен быть fail-fast. См. Tier 1.5.

### ~~Retry/Backoff для Telegram и Webhook~~ → перенесено в Tier 1.5

> **Moved up.** Без retry approval молча пропадает. См. Tier 1.5.

### ~~Idempotency / Request Deduplication~~ → перенесено в Tier 1.5

> **Moved up.** Agent retry → дублирование approvals → confusion. См. Tier 1.5.

### ~~Approval Audit Trail~~ → перенесено в Tier 1.5

> **Moved up.** Кто одобрил и когда — обязательно для compliance. См. Tier 1.5.

### Circuit Breaker для Approval Backends 🔴

Если Telegram или Webhook backend недоступен — approvals висят вечно. Нужен circuit breaker: после N ошибок переключиться на fallback (другой backend или auto-BLOCK).

```yaml
approval:
  backend: telegram
  circuit_breaker:
    failure_threshold: 3
    reset_timeout: 60s
    fallback: BLOCK
```

- **Усилия**: Средние (~80 строк)
- **Ценность**: Высокая — resilience, иначе один сбой Telegram кладёт весь approval flow

### Approval Backend Healthcheck 🔴

`policyshield doctor` проверяет конфиг, но нет **runtime** проверки что Telegram бот жив и может доставлять уведомления. Нужен периодический ping + метрика.

- **Усилия**: Маленькие (~30 строк, `/readyz` интеграция)
- **Ценность**: Высокая — без этого approvals могут молча пропадать

### Rule Simulate / What-If Analysis

Есть `policyshield replay` для трейсов, но нет простого "что будет если я добавлю это правило" без наличия трейсов.

```bash
policyshield simulate --rule new_rule.yaml --tool exec --args '{"cmd":"ls"}'
# Verdict: ALLOW (no rule matched)
# If new_rule.yaml applied: BLOCK (rule block-exec)
```

- **Усилия**: Маленькие (~50 строк, обёртка над engine.check)
- **Ценность**: Средняя — проще отлаживать правила без production трейсов

### Audit Log Rotation & Retention

JSONL трейсы растут бесконечно. Нет ротации, TTL, или max-size. Диск заполнится.

```yaml
trace:
  max_size: 100MB
  rotation: daily
  retention: 30d
```

- **Усилия**: Средние (RotatingFileHandler или кастомный)
- **Ценность**: Высокая для production

### TLS для HTTP сервера

Bearer token есть, но без TLS токен летит plaintext.

```bash
policyshield server --rules rules.yaml --tls-cert cert.pem --tls-key key.pem
```

- **Усилия**: Маленькие (uvicorn `ssl_certfile`/`ssl_keyfile`)
- **Ценность**: Высокая — enterprise security

### Rate Limit на HTTP API

Rate limiter есть для tool calls внутри engine, но нет для самого HTTP API. Если API открыт — DoS вектор.

- **Усилия**: Маленькие (FastAPI middleware, `slowapi`)
- **Ценность**: Средняя — hardening

### Approval Metrics (Prometheus)

Prometheus метрики есть для verdicts, но нет метрик на approval flow: pending count, avg response time, timeout rate.

- **Усилия**: Маленькие (~20 строк counters/gauges)
- **Ценность**: Средняя — SLA мониторинг

### Shadow Mode

Новые правила работают параллельно, но не блокируют — только логируют:

```
policyshield shadow rules_v2.yaml --duration 1h
```

- **Усилия**: Средние (dual-path в engine)
- **Ценность**: Высокая — безопасный деплой правил

### Output/Response Policy

Проверка не только аргументов, но и **ответов** тулов:

```yaml
output_policy:
  max_size: 10MB
  block_patterns: [base64_blob, executable_content]
  rules:
    - when: { tool: read_database, output_contains: "password" }
      then: REDACT
```

- **Усилия**: Средние (вторая pipeline для output)
- **Ценность**: Высокая — сейчас output проверяется только на PII

### Plugin System (extensible detectors)

Generic API для подключения кастомных детекторов и хуков:

```python
from policyshield.plugins import detector

@detector("credit_score_leak")
def check_credit_score(args: dict) -> bool:
    return "credit_score" in str(args)
```

- **Усилия**: Средние (plugin registry + hooks)
- **Ценность**: Высокая — расширяемость без форков

### Multi-file Rule Validation

`policyshield lint` работает с одним файлом. Когда появится `include:` / `extends:` — нужна lint проверка **всего дерева** правил с учётом наследования и конфликтов между файлами.

```bash
policyshield lint --recursive ./rules/
# ✅ base.yaml: 5 rules OK
# ✅ overrides.yaml: 2 rules OK
# ⚠️  overrides.yaml:rule-3 shadows base.yaml:rule-2 (same tool pattern, lower priority)
# ❌ team_a.yaml:rule-7 conflicts with base.yaml:rule-1 (contradicting verdicts)
```

- **Усилия**: Средние (расширить lint + rule resolver)
- **Ценность**: Высокая — без этого `include:` / `extends:` развалится на больших проектах

### Dead Rule Detection

Правила, которые никогда не сработали:

```
policyshield lint --check unused --traces traces/
```

- **Усилия**: Маленькие (cross-ref traces × rules)
- **Ценность**: Средняя — гигиена правил

### Dynamic Rules — загрузка по HTTP/S3

Центральный сервер правил для флота агентов:

```yaml
rules:
  source: https://policies.internal/rules.yaml
  signature_key: ${POLICY_SIGN_KEY}
  refresh: 30s
```

- **Усилия**: Средние
- **Ценность**: Высокая для production multi-agent

### Rule Composition

`include:`, `extends:`, `priority:` — переиспользование и наследование правил.

```yaml
include:
  - ./base_rules.yaml
  - ./team_overrides.yaml
```

- **Усилия**: Средние
- **Ценность**: Средняя — нужно для больших конфигов

### Budget Caps

Не «10 вызовов в минуту», а «не больше $5 за сессию»:

```yaml
budget:
  max_per_session: 5.00
  max_per_hour: 20.00
  currency: USD
```

- **Усилия**: Средние (интеграция с cost estimator)
- **Ценность**: Средняя — для платных API

### Global & Adaptive Rate Limiting

Текущий rate limiter — per-tool sliding window. Не хватает:
- **Global rate limit** (все тулы в сумме)
- **Adaptive**: при аномальном поведении автоматически ужесточить
- **Per-user/role** (связано с RBAC)

- **Усилия**: Средние
- **Ценность**: Средняя — production hardening

### Compliance Reports

PDF/HTML отчёт для аудиторов:

```
policyshield report --period 30d --format pdf
```

- **Усилия**: Средние (aggregator + jinja2 шаблоны)
- **Ценность**: Высокая для enterprise

### Incident Timeline

Авто-генерация таймлайна сессии при инциденте:

```
policyshield incident session_abc123 --format html
```

- **Усилия**: Средние (trace reader + HTML renderer)
- **Ценность**: Высокая — post-mortem

### Canary Deployments для правил

Новые правила на 5% сессий → мониторинг → 100%:

```yaml
rules:
  - id: new-strict-rule
    canary: 5%
    promote_after: 24h
```

- **Усилия**: Средние (session hash routing)
- **Ценность**: Высокая для production

### `policyshield migrate` — миграция конфига

При обновлении между версиями (v0.x → v1.0) формат YAML может измениться. Автоматическая миграция вместо ручного разбора changelog.

```bash
policyshield migrate --from 0.11 --to 1.0 rules.yaml
# Migrated 3 rules: renamed 'then' → 'verdict', added 'severity' defaults
```

- **Усилия**: Маленькие (~80 строк, YAML transformer)
- **Ценность**: Средняя — снижает трение при обновлениях
