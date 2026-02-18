# Prompt 73 — OpenClaw API Разведка

## Статус: ✅ ВЫПОЛНЕН

## Результаты

Полный отчёт: [`tests/e2e-openclaw/RESEARCH.md`](../../tests/e2e-openclaw/RESEARCH.md)

### Краткие выводы

| Вопрос | Результат |
|--------|-----------|
| Docker-образ на Docker Hub/GHCR? | ❌ Нет. Только Dockerfile (node:22-bookworm, pnpm) |
| REST API для tool calls? | ❌ Нет. Gateway = WebSocket на порту 18789 |
| Механизм загрузки плагинов | ✅ `~/.openclaw/extensions/`, `plugins.load.paths`, workspace |
| Test mode без LLM | ❌ Нет. Нужен реальный API key |
| SDK exports hook types | ❌ Нет. Barrel не экспортирует `PluginHook*` |

### Влияние на промпты 74-76

1. **Docker Compose (74):** Нужно собирать образ из исходников — нет `docker pull`
2. **E2E Scenarios (75):** Нельзя вызывать tools через REST. Только WebSocket 
   или программный dispatch хуков
3. **CI Job (76):** Сборка образа ~5 мин, нужен LLM API key в CI secrets

### Рекомендация

E2E с реальным OpenClaw **слишком дорогие и хрупкие** для CI:
- Сборка из исходников (~5 мин)
- LLM API key обязателен (стоимость + недетерминированность)
- WebSocket — сложная тестовая инфраструктура

Наш `openclaw-compat.test.ts` уже тестирует реальный integration surface 
(plugin loading, hook dispatch, config, error handling) за ~1 секунду.

**Предлагаемая стратегия:**
- **Tier 1 (есть):** `openclaw-compat.test.ts` — программный dispatch хуков
- **Tier 2 (добавить):** Smoke test с реальным `openclaw` loader 
- **Tier 3 (будущее):** Ручной Docker Compose с LLM key для release validation

## Самопроверка

- [x] Docker-образ: знаем — нет публичного, есть Dockerfile
- [x] Tool call API: знаем — нет REST, только WebSocket
- [x] Plugin loading: знаем — `extensions/` dir, `plugins.load.paths`
- [x] Test mode: знаем — нет, нужен LLM
- [x] Plugin SDK: подтвердили — hook types не экспортируются

## Коммит

```
docs: add OpenClaw E2E research findings

- No public Docker image (build from source only)
- No REST API for tool calls (WebSocket gateway)
- No test mode (requires LLM API key)
- Plugin discovery: extensions dir + config paths
- SDK barrel does not export hook types

Impact: E2E prompts 74-76 need revision
Refs: tests/e2e-openclaw/RESEARCH.md
```
