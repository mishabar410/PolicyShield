# Промпт 12 — Интеграционные тесты (end-to-end)

## Контекст

Все компоненты v0.1 готовы:
- Core models (промпт 02)
- YAML parser (промпт 03)
- PII detector (промпт 04)
- Matcher engine (промпт 05)
- Verdict builder (промпт 06)
- Session manager (промпт 07)
- Trace recorder (промпт 08)
- ShieldEngine (промпт 09)
- ShieldedToolRegistry (промпт 10)
- CLI (промпт 11)

Теперь нужно написать end-to-end тесты, которые проверяют **всю цепочку** от YAML-правил до финального вердикта, покрывая реалистичные сценарии использования.

## Задача

Создай файл `tests/test_e2e.py` и тестовые fixtures.

### Тестовые правила

Создай директорию `tests/fixtures/policies/` с файлом `security.yaml`:

```yaml
shield: test-security
version: 1

rules:
  - id: no-destructive-shell
    description: "Block destructive shell commands"
    when:
      tool: exec
      args_match:
        command:
          regex: "rm\\s+-rf|mkfs|dd\\s+if=|format\\s+c:"
    then: block
    severity: critical
    message: "Destructive shell commands are not allowed. Use non-destructive alternatives."

  - id: no-pii-external
    description: "Block PII in external requests"
    when:
      tool: [web_fetch, web_search]
      args_match:
        any_field:
          contains_pattern: "pii"
    then: block
    severity: high
    message: "PII detected. Redact personal data before making external requests."

  - id: rate-limit-web
    description: "Rate limit web tool usage"
    when:
      tool: web_fetch
      session:
        tool_count.web_fetch:
          gt: 10
    then: block
    severity: medium
    message: "Too many web requests. Reduce frequency."

  - id: allow-read
    description: "Always allow file reads"
    when:
      tool: read_file
    then: allow
```

### Тестовые сценарии (все async)

Для каждого теста: загрузить правила из fixtures, создать ShieldEngine, прогнать сценарий.

1. **Сценарий: Деструктивная shell-команда**
   - `check("exec", {"command": "rm -rf /tmp/data"})` → BLOCK
   - message содержит "Destructive" и "non-destructive"
   - `check("exec", {"command": "ls -la"})` → ALLOW

2. **Сценарий: PII в web-запросе (repair loop)**
   - `check("web_fetch", {"url": "https://api.com", "body": "email: john@corp.com"})` → BLOCK, pii_matches содержит EMAIL
   - Агент "исправился": `check("web_fetch", {"url": "https://api.com", "body": "email: [REDACTED]"})` → ALLOW
   - Это **полный repair loop** — именно так работает PolicyShield в продакшне

3. **Сценарий: Rate limiting**
   - Вызвать `check("web_fetch", {"url": "https://api.com"})` 11 раз с одним session_id
   - Первые 10 → ALLOW
   - 11-й → BLOCK, message содержит "Too many"

4. **Сценарий: Разные sessions изолированы**
   - 6 вызовов web_fetch с session_id="s1", 6 с session_id="s2"
   - Ни один не заблокирован (каждая сессия < 10)

5. **Сценарий: Trace записывается**
   - Создать engine с trace, выполнить 3 check()-а (1 BLOCK, 2 ALLOW)
   - Прочитать trace файл → 3 записи
   - Запись с BLOCK содержит rule_id="no-destructive-shell"

6. **Сценарий: PII taints в session**
   - check с PII → session.taints содержит EMAIL
   - Следующий check без PII — taints всё ещё содержат EMAIL (taints не очищаются)

7. **Сценарий: Post-call PII scan**
   - check("read_file", {"path": "/data"}) → ALLOW
   - post_check("read_file", "File content: SSN 123-45-6789") → маскированный result

8. **Сценарий: AUDIT mode**
   - Создать engine с mode=AUDIT
   - check("exec", {"command": "rm -rf /"}) → verdict ALLOW (не блокирует)
   - Trace запись содержит "would_block" или rule_id (зависит от реализации — проверить что trace существует)

9. **Сценарий: CLI validate на тестовых правилах**
   - Вызвать CLI `policyshield validate tests/fixtures/policies/` → exit 0, stdout содержит "4 rules"

10. **Сценарий: Полная интеграция с ShieldedToolRegistry**
    - Создать mock ToolRegistry (как в промпте 10)
    - Обернуть в ShieldedToolRegistry
    - execute("exec", {"command": "rm -rf /"}) → BLOCK (оригинальный execute не вызван)
    - execute("read_file", {"path": "/tmp"}) → ALLOW (оригинальный execute вызван)

## Защитные условия

- Все интеграционные тесты используют fixtures из `tests/fixtures/` — не хардкоди YAML в тестах
- Для тестов с trace — используй `tmp_path`
- Не используй реальные nanobot — только mock
- **Ключевая проверка:** после этого промпта запусти ВСЕ тесты проекта. Все должны пройти:

## Проверки перед коммитом

```bash
ruff check policyshield/
pytest tests/ -v --tb=short
pytest tests/ --cov=policyshield --cov-report=term-missing
```

Проверь coverage: target ≥ 85% на основных модулях (shield/, core/). Если ниже — добавь недостающие тесты.

## Коммит

```
git add -A && git commit -m "test: end-to-end integration tests — 10 scenarios, fixtures, coverage ≥85%"
```
