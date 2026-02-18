# PolicyShield v1.2 — Prompt Chain: Tier 1.5 Production Readiness

Цепочка из 5 групповых промптов, покрывающих ~48 фич Tier 1.5. Каждый промпт покрывает одну логическую группу фич.

## Главная цель

Довести PolicyShield до production-ready состояния: закрыть все v1.0-blockers, hardening HTTP layer, approval flow, security, lifecycle, и DX.

## Группы (промпты)

| # | Промпт | Группа | Кол-во фич | Основные файлы |
|---|--------|--------|------------|----------------|
| 301 | [Server Hardening](301_server_hardening.md) | HTTP Layer Protection | 8 | `app.py`, `models.py` |
| 302 | [Approval Flow](302_approval_flow.md) | Human-in-the-Loop | 7 | `base_engine.py`, `memory.py`, `telegram.py` |
| 303 | [Security & Data](303_security_data.md) | Data Protection | 6 | `app.py`, `detectors.py`, `recorder.py` |
| 304 | [Lifecycle & Reliability](304_lifecycle.md) | Startup/Shutdown/Reload | 10 | `app.py`, `base_engine.py`, `cli/main.py` |
| 305 | [DX & Adoption](305_dx_adoption.md) | SDK, CLI, Integrations | 17 | новые файлы, `cli/main.py` |

## Зависимости между промптами

```
301 (Server Hardening)      ← ни от кого
302 (Approval Flow)         ← ни от кого (параллельно с 301)
303 (Security & Data)       ← после 301 (использует exception handler из 301)
304 (Lifecycle & Reliability) ← после 301 (fail-open/closed зависит от error handler)
305 (DX & Adoption)         ← после 301–304 (SDK оборачивает готовое API)
```

> Промпты 301 и 302 **независимы** и могут выполняться параллельно. 303 и 304 зависят от 301. 305 идёт последним.

## Рекомендуемый порядок выполнения

```
Фаза 1 (параллельно): 301 + 302
Фаза 2 (параллельно): 303 + 304
Фаза 3:               305
```

## Правила

1. **Атомарность:** каждая фича внутри промпта = код + тесты + коммит
2. **Регрессий нет:** перед каждым коммитом — `pytest tests/ -q` (все тесты проходят)
3. **Последовательность:** фичи внутри промпта выполняются строго по порядку
4. **Обратная совместимость:** все новые фичи опциональны, ничего не ломают
5. **Lint:** `ruff check policyshield/ tests/` и `ruff format --check policyshield/ tests/` проходят
6. **Версия бампится один раз:** после last prompt → bump до v1.2.0
