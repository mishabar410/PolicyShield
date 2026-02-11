# PolicyShield v0.2 — Prompt Chain

Цепочка из 10 атомарных промптов для реализации v0.2.

## Фичи v0.2

| # | Промпт | Основная фича |
|---|--------|---------------|
| 01 | Rule Linter | `policyshield lint` — статический анализ YAML-правил |
| 02 | Hot Reload | Перезагрузка правил без перезапуска агента (watchdog) |
| 03 | Advanced PII | RU-паттерны (ИНН, СНИЛС, паспорт, телефон RU) + кастомные паттерны из YAML |
| 04 | Rate Limiter Engine | Полноценный rate limiter: sliding window, per-tool, per-session |
| 05 | Approval Backend (ABC) | Абстрактный ApprovalBackend + InMemoryBackend + CLI approve |
| 06 | Telegram Approval | TelegramApprovalBackend — отправка approve-запроса в Telegram |
| 07 | Batch Approve | Кэш одобрений: approve-once-per-session, approve-by-pattern |
| 08 | Trace Stats | `policyshield trace stats` — агрегированная статистика из JSONL |
| 09 | LangChain Adapter | `PolicyShieldTool` обёртка для LangChain `BaseTool` |
| 10 | Finalize v0.2 | README, CHANGELOG, E2E-тесты, bump до v0.2.0, тег |

## Правила

1. **Атомарность:** каждый промпт = код + тесты + коммит
2. **Регрессий нет:** перед коммитом — `pytest tests/ -q` (все тесты проходят)
3. **Линт чист:** `ruff check policyshield/ tests/` без ошибок
4. **Покрытие:** ≥85% (`pytest --cov --cov-fail-under=85`)
5. **Последовательность:** промпты выполняются строго по порядку
