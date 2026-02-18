# 🟡 Tier 2 — Medium Impact ✅ (Implemented in v0.12)

> All 20 features implemented and tested (1192 tests passing).
>
> **Перенесено в Tier 1.5 как v1.0-blockers:** Config Validation на старте, Retry/Backoff для Telegram,
> Idempotency, Approval Audit Trail. См. [tier1_5_critical.md](tier1_5_critical.md).

## Phase 1: Resilience & Approval (401–407) ✅

### Circuit Breaker для Approval Backends ✅

Если Telegram или Webhook backend недоступен — circuit breaker переключается на fallback (BLOCK).

→ `policyshield/approval/circuit_breaker.py`

### Approval Backend Healthcheck ✅

Runtime проверка что Telegram бот жив. Периодический ping + `/readyz` интеграция.

→ `policyshield/approval/base.py`

### Rule Simulate / What-If Analysis ✅

`policyshield simulate --rule new_rule.yaml --tool exec --args '{"cmd":"ls"}'`

→ `policyshield/cli/main.py`

### Audit Log Rotation & Retention ✅

JSONL трейсы с ротацией, max-size, TTL.

→ `policyshield/trace/recorder.py`

### TLS для HTTP сервера ✅

`policyshield server --rules rules.yaml --tls-cert cert.pem --tls-key key.pem`

→ `policyshield/cli/main.py`

### Rate Limit на HTTP API ✅

FastAPI middleware для `/check` и `/post-check` эндпоинтов.

→ `policyshield/server/rate_limiter.py`, `policyshield/server/app.py`

### Approval Metrics (Prometheus) ✅

Метрики: pending count, avg response time, timeout rate.

→ `policyshield/server/metrics.py`

## Phase 2: Rules Engine (408–414) ✅

### Shadow Mode ✅

Новые правила работают параллельно, но не блокируют — только логируют.

→ `policyshield/shield/base_engine.py`

### Output/Response Policy ✅

Проверка ответов тулов: max_size, block_patterns, output rules.

→ `policyshield/core/models.py`

### Plugin System (extensible detectors) ✅

Generic API для подключения кастомных детекторов.

→ `policyshield/plugins/__init__.py`

### Multi-file Rule Validation ✅

Lint проверка всего дерева правил с учётом наследования и конфликтов.

→ `policyshield/lint/cross_file.py`

### Dead Rule Detection ✅

Правила, которые никогда не сработали (cross-ref traces × rules).

→ `policyshield/lint/dead_rules.py`

### Dynamic Rules — загрузка по HTTP/HTTPS ✅

Центральный сервер правил для флота агентов с периодическим обновлением.

→ `policyshield/shield/remote_loader.py`

### Rule Composition ✅

`include:`, `extends:` — переиспользование и наследование правил.

→ `policyshield/core/parser.py`

## Phase 3: Observability (415–418) ✅

### Budget Caps ✅

Per-session и per-hour USD-based cost limits.

→ `policyshield/shield/budget.py`

### Global & Adaptive Rate Limiting ✅

Global rate limit + adaptive burst detection с auto-cooldown.

→ `policyshield/shield/rate_limiter.py`

### Compliance Reports ✅

HTML отчёт для аудиторов: verdicts, violations, PII stats, rule coverage.

→ `policyshield/reporting/compliance.py`

### Incident Timeline ✅

Хронологический таймлайн сессии для post-mortem анализа.

→ `policyshield/reporting/incident.py`

## Phase 4: Operations (419–420) ✅

### Canary Deployments для правил ✅

Hash-based session bucketing, auto-promote after configurable duration.

→ `policyshield/shield/canary.py`

### `policyshield migrate` — миграция конфига ✅

Sequential migration chain: 0.11 → 0.12 → 1.0.

→ `policyshield/migration/migrator.py`
