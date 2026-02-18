# PolicyShield v0.8 — Prompt Chain: Аудит-фиксы

Цепочка из 7 атомарных промптов: удаление мусора → SDK stubs → client fixes → index.ts hardening → тесты → интеграция → документация.

## Контекст

По результатам аудита v0.7 выявлены проблемы:

1. `openclaw/` директория (5167 файлов) — мусор в репо
2. SDK stubs (`openclaw-plugin-sdk.d.ts`) — ссылаются на неправильный репо, могут расходиться с реальным API
3. `client.ts` — дублирует audit-mode логику сервера, глотает ошибки молча
4. `index.ts` — hardcoded APPROVE polling (60s/2s), magic number 10000 в slice
5. Тесты — все мокнутые, E2E скипается, нет type-checking теста
6. Нет простого способа установки для пользователя OpenClaw
7. README/документация — не описывает простой путь интеграции

## Фазы

### Фаза 0: Cleanup (промпт 61)

| # | Промпт | Основная задача |
|---|--------|-----------------|
| 61 | Repo Cleanup | Удалить `openclaw/`, добавить в `.gitignore`, вычистить ссылки на `nicepkg/openclaw` |

### Фаза 1: Plugin Quality (промпты 62–65)

| # | Промпт | Основная задача |
|---|--------|-----------------|
| 62 | SDK Stubs Sync | Синхронизировать `openclaw-plugin-sdk.d.ts` с реальным `openclaw/src/plugins/types.ts` |
| 63 | Client Hardening | Убрать audit-mode из клиента, добавить логирование ошибок вместо silent catch |
| 64 | Plugin Logic Fixes | Сделать APPROVE polling конфигурируемым, убрать magic number, добавить error logging |
| 65 | Plugin Tests Overhaul | Обновить тесты + type-check тест + реальный (не-skipped) E2E scaffold |

### Фаза 2: Integration & Docs (промпты 66–67)

| # | Промпт | Основная задача |
|---|--------|-----------------|
| 66 | npm Package Setup | `package.json` с правильными metadata, build pipeline, publish-ready |
| 67 | Integration Docs | README с 3-step quickstart, openclaw.yaml пример, troubleshooting |

## Зависимости между промптами

```
61 (Cleanup)         ← ни от кого не зависит
62 (SDK Stubs)       ← после 61 (openclaw/ уже удалён)
63 (Client)          ← после 62 (стубы уже обновлены)
64 (Plugin Logic)    ← после 63 (клиент уже исправлен)
65 (Tests)           ← после 64
66 (npm Package)     ← после 65
67 (Docs)            ← после 66
```

## Правила

1. **Атомарность:** каждый промпт = код + тесты + коммит
2. **Регрессий нет:** перед коммитом — `pytest tests/ -q` (все Python тесты проходят)
3. **TS чист:** `cd plugins/openclaw && npx tsc --noEmit` без ошибок
4. **Последовательность:** промпты выполняются строго по порядку
