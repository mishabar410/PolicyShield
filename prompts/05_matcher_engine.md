# Промпт 05 — Matcher Engine

## Контекст

Модели (RuleConfig, RuleSet) — промпт 02. Парсер YAML — промпт 03. Теперь нужен движок, который для данного tool call находит подходящие правила. Спецификация — раздел 4 `TECHNICAL_SPEC.md`.

Matcher — чистая функция: принимает (tool_name, args, session_state) и RuleSet, возвращает список подходящих правил. Никаких побочных эффектов.

## Задача

Создай файл `policyshield/shield/matcher.py`:

### Класс `MatcherEngine`

**Конструктор:**
- Принимает `rule_set: RuleSet`
- Создаёт индекс правил по tool name (dict: str → list[RuleConfig]) для быстрого lookup. Правила, в которых `when.tool` — это список, индексируются по каждому элементу.
- Правила без `when.tool` (если вдруг) — добавляются в wildcard-группу и проверяются всегда.
- Компилирует все regex-паттерны из `args_match` один раз при создании (precompile).

**Метод `match(tool_name: str, args: dict, session: SessionState | None = None) -> list[RuleConfig]`:**

Порядок проверок для каждого правила:

1. **ToolMatcher** — `when.tool` может быть строкой или списком строк. Проверить, что `tool_name` совпадает. Поддержка wildcard `"*"` — матчит любой tool.

2. **ArgsMatcher** — `when.args_match` — это словарь, где ключ — имя поля (или `any_field`), значение — словарь с предикатом. Поддерживаемые предикаты:
   - `regex` — regex-совпадение: `re.search(pattern, str(value))`
   - `contains` — подстрока: `substring in str(value)`
   - `starts_with` — префикс: `str(value).startswith(prefix)`
   - `eq` — точное равенство: `str(value) == expected`
   - `contains_pattern: "pii"` — специальный предикат, **не реализуй логику PII здесь**. Просто зафиксируй как `pii_check_required: True` в результате. PII-проверка будет вызываться из ShieldEngine.
   
   `any_field` — предикат применяется ко ВСЕМ строковым значениям args. Если хотя бы одно совпало — match.

3. **SessionMatcher** — `when.session` — словарь. Ключи вида `tool_count.{tool_name}` сравниваются с `session.tool_counts`. Предикаты сравнения: `gt`, `lt`, `gte`, `lte`, `eq`.

Правило матчится, если **все** условия в `when` выполнены (AND-логика).

**Метод `find_best_match(tool_name: str, args: dict, session: SessionState | None = None) -> RuleConfig | None`:**

Из всех матчей выбрать наиболее строгий (приоритет): BLOCK > APPROVE > REDACT > ALLOW. При равном verdict-е — выбрать правило с более высокой severity.

### Вспомогательный класс `CompiledRule`

Внутренний класс, хранящий скомпилированные предикаты для одного правила (regex-объекты, parsed session predicates). Используй его для индекса, чтобы не парсить `when` при каждом вызове `match()`.

## Тесты

Напиши `tests/test_matcher.py`:

1. **Простой tool match** — правило `when: {tool: exec}`, вызов `match("exec", {})` → правило найдено. Вызов `match("read_file", {})` → пусто.

2. **Tool list** — правило `when: {tool: [web_fetch, web_search]}`, вызов `match("web_fetch", {})` → найдено. `match("exec", {})` → пусто.

3. **Wildcard** — правило `when: {tool: "*"}` → матчит любой tool.

4. **Args regex** — правило с `args_match: {command: {regex: "rm\\s+-rf"}}`, вызов `match("exec", {"command": "rm -rf /"})` → найдено. `match("exec", {"command": "ls"})` → пусто.

5. **Args contains** — `args_match: {url: {contains: "internal.corp"}}`.

6. **Args any_field** — `args_match: {any_field: {contains: "secret"}}`, аргументы `{"title": "my file", "content": "the secret key"}` → найдено.

7. **Session matcher** — правило `when: {tool: web_fetch, session: {tool_count.web_fetch: {gt: 5}}}`. Создать SessionState с `tool_counts={"web_fetch": 6}` → найдено. С `tool_counts={"web_fetch": 3}` → пусто.

8. **AND-логика** — правило с tool + args_match. Tool совпадает, args нет → пусто.

9. **find_best_match приоритет** — два правила: одно ALLOW, одно BLOCK для того же tool → вернуть BLOCK-правило.

10. **Пустой RuleSet** — `match(anything)` → пустой список, `find_best_match` → None.

## Защитные условия

- Matcher не должен импортировать PIIDetector — PII-проверка будет в ShieldEngine
- Matcher — чистая логика, без побочных эффектов (без записи в файлы, без мутации state)
- Все предыдущие тесты проходят

## Проверки перед коммитом

```bash
ruff check policyshield/
pytest tests/ -v
```

## Коммит

```
git add -A && git commit -m "feat(shield): matcher engine — tool, args, session matchers with precompilation"
```
