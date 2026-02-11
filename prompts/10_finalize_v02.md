# Prompt 10 — Finalize v0.2

## Цель

Финальная сборка v0.2: E2E-тесты для новых фич, обновление документации, CHANGELOG, bump версии, тег v0.2.0.

## Что сделать

### 1. E2E-тесты: `tests/test_e2e_v02.py`

Минимум 12 E2E-сценариев, каждый использует полный pipeline:

```
test_e2e_lint_catches_errors               — lint правил с ошибками → найдены все
test_e2e_hot_reload_updates_engine         — изменить YAML → engine подхватит новые правила
test_e2e_inn_blocked_by_pii_rule           — ИНН в web_fetch → BLOCK
test_e2e_custom_pii_pattern                — кастомный паттерн из YAML → детектирует
test_e2e_rate_limit_blocks_excess          — превысить лимит → BLOCK
test_e2e_rate_limit_window_reset           — подождать окно → снова ALLOW
test_e2e_approval_approved                 — APPROVE + respond(True) → ALLOW
test_e2e_approval_denied                   — APPROVE + respond(False) → BLOCK
test_e2e_approval_timeout                  — APPROVE + no response → BLOCK
test_e2e_batch_approve_auto                — второй вызов auto-approved
test_e2e_trace_stats_output                — trace stats → корректная статистика
test_e2e_full_pipeline                     — загрузка YAML → check → trace → stats → lint → всё работает
```

### 2. Обновить `README.md`

Добавить секции для всех v0.2 фич:
- Rule Linter
- Hot Reload
- RU PII Patterns
- Rate Limiting
- Human-in-the-Loop Approval (InMemory, CLI, Telegram)
- Batch Approve
- Trace Stats
- LangChain Adapter

### 3. Создать `CHANGELOG.md`

```markdown
# Changelog

## [0.2.0] - 2025-02-XX

### Added
- Rule linter with 6 static checks (`policyshield lint`)
- Hot reload of YAML rules (file watcher)
- RU PII patterns: INN, SNILS, passport, phone
- Custom PII patterns from YAML
- Sliding window rate limiter with YAML config
- Human-in-the-loop APPROVE verdict
- Approval backends: InMemory, CLI, Telegram
- Batch approve with caching strategies
- Trace stats aggregation (`policyshield trace stats`)
- LangChain BaseTool adapter

### Fixed
- [from v0.1 bugs found in E2E] case-insensitive severity, tool lists, args_match shorthand

## [0.1.0] - 2025-02-11

### Added
- Core models (Verdict, RuleConfig, ShieldResult, etc.)
- YAML rule parser with includes and env vars
- PII detector (EMAIL, PHONE, CREDIT_CARD, SSN, IBAN, IP, PASSPORT, DOB)
- Rule matcher with regex, glob, and exact match
- ShieldEngine orchestrator
- Session manager with tool call tracking
- Trace recorder (JSONL)
- CLI: validate, trace show, trace violations
- Nanobot integration
- 10 E2E test scenarios
```

### 4. Обновить `pyproject.toml`

- Bump `version = "0.2.0"`
- Убедиться что все optional dependencies корректны

### 5. Bump версии

```bash
# pyproject.toml
version = "0.2.0"

# policyshield/__init__.py
__version__ = "0.2.0"
```

### 6. Обновить `CLAUDE.md`

- Отметить v0.2 фичи как done
- Обновить roadmap

### 7. Обновить `examples/`

Добавить:
- `examples/policies/full.yaml` — пример с rate_limits, pii_patterns, approval_strategy
- `examples/langchain_demo.py` — пример LangChain интеграции

## Самопроверки

```bash
# Все тесты проходят (старые + новые)
pytest tests/ -q

# Lint чист
ruff check policyshield/ tests/

# Coverage ≥ 85%
pytest tests/ --cov=policyshield --cov-fail-under=85

# Build проходит
python -m build

# CLI работает
policyshield lint examples/policies/
policyshield trace stats demo_traces/trace_*.jsonl
policyshield --version  # → 0.2.0
```

## Коммит + тег

```bash
git add -A
git commit -m "release: PolicyShield v0.2.0

- Rule linter, Hot reload, Advanced PII (RU)
- Rate limiter, Approval flow (InMemory/CLI/Telegram)
- Batch approve, Trace stats, LangChain adapter
- 12 new E2E tests, CHANGELOG, updated docs"

git tag v0.2.0 -m "PolicyShield v0.2.0"
git push && git push --tags
```
