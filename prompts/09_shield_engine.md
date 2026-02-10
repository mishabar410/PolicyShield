# Промпт 09 — ShieldEngine (оркестратор)

## Контекст

Все компоненты готовы:
- Matcher (промпт 05) — находит подходящие правила
- PIIDetector (промпт 04) — сканирует PII
- SessionManager (промпт 07) — управляет сессиями
- VerdictBuilder (промпт 06) — формирует counterexample
- TraceRecorder (промпт 08) — пишет аудитный лог

Теперь нужен оркестратор, который вызывает их в правильном порядке. Спецификация — раздел 6 `TECHNICAL_SPEC.md` (ShieldEngine flow).

## Задача

Создай файл `policyshield/shield/engine.py`:

### Класс `ShieldEngine`

**Конструктор:**
- `rule_set: RuleSet`
- `pii_config: dict | None = None` — конфигурация PII (enabled, custom_patterns, post_call_scan). Если None — PII выключен.
- `trace_config: dict | None = None` — конфигурация trace (enabled, output_dir, privacy_mode). Если None — trace выключен.
- `session_ttl: int = 3600`
- `mode: ShieldMode = ShieldMode.ENFORCE`

Внутри создаёт все подкомпоненты: `MatcherEngine`, `PIIDetector` (если enabled), `SessionManager`, `VerdictBuilder`, `TraceRecorder` (если enabled).

**Метод `async check(tool_name: str, args: dict, session_id: str = "default") -> ShieldResult`:**

Это главная точка входа. Flow:

1. **Mode check** — если `mode == DISABLED` → сразу ALLOW
2. **Session lookup** — `session_manager.get_or_create(session_id)`
3. **PII pre-scan** — если PII enabled: `pii_detector.scan_dict(args)` → список PIIMatch
4. **Rule matching** — `matcher.find_best_match(tool_name, args, session)`:
   - Если `contains_pattern: "pii"` в правиле и PII обнаружен → правило считается сматченным
   - Если `contains_pattern: "pii"` в правиле и PII НЕ обнаружен → правило НЕ матчится
5. **Verdict build:**
   - Если нет матча → `verdict_builder.build_allow()`
   - BLOCK → `verdict_builder.build_block(rule, tool_name, args, pii_matches)`
   - REDACT → замаскировать PII в args через `pii_detector.mask()`, `verdict_builder.build_redact(...)`
   - APPROVE → `verdict_builder.build_approve_pending(...)` (полноценный approval flow — в промпте 12)
6. **Audit mode** — если `mode == AUDIT`: всегда ALLOW, но trace записывает что *было бы*
7. **Session update** — `session_manager.increment(session_id, tool_name)`, добавить taints если PII найден
8. **Trace record** — если trace enabled: записать TraceRecord
9. **Timing** — замерить время выполнения check(), записать в latency_ms

Вернуть `ShieldResult`.

**Метод `async post_check(tool_name: str, result: str, session_id: str = "default") -> str`:**

Post-call PII scan результата tool call:
- Если PII config и `post_call_scan` включены — `pii_detector.scan(result)`
- Если PII найден — замаскировать и вернуть маскированный результат
- Если PII не найден — вернуть оригинальный result
- Записать trace (отдельная запись с `tool=tool_name+"_result"`)

**Метод `reload_rules(rule_set: RuleSet) -> None`:**
- Обновить MatcherEngine новым RuleSet (hot reload)

**Метод `get_status() -> dict`:**
- Вернуть: mode, число правил, статистика SessionManager

### Реэкспорт

В `policyshield/shield/__init__.py` реэкспортируй `ShieldEngine` и `ShieldMode`.

## Тесты

Напиши `tests/test_engine.py`:

1. **ALLOW — нет правил** — пустой RuleSet, любой tool call → verdict=ALLOW
2. **BLOCK — простое правило** — правило `when: {tool: exec}, then: block`, вызов `check("exec", {})` → verdict=BLOCK, message содержит "exec"
3. **BLOCK с PII** — правило `when: {tool: web_fetch, args_match: {any_field: {contains_pattern: "pii"}}}, then: block`. Args содержат email → verdict=BLOCK, pii_matches не пустой
4. **ALLOW — PII правило, но нет PII** — то же правило, args без PII → verdict=ALLOW (правило не матчится)
5. **REDACT** — правило с then=redact, args с email → verdict=REDACT, modified_args содержит маскированный email
6. **AUDIT mode** — mode=AUDIT, правило BLOCK → ShieldResult verdict=ALLOW (но trace записан, если включён)
7. **DISABLED mode** — mode=DISABLED → verdict=ALLOW без каких-либо проверок
8. **Session increment** — после check() → session.total_calls увеличился
9. **Session taint** — PII найден → session.taints содержит тип PII
10. **post_check с PII** — result содержит email → возвращает маскированную строку
11. **post_check без PII** — result без PII → возвращает оригинал
12. **Trace запись** — включить trace с tmp_path, вызвать check → trace файл содержит запись
13. **Timing** — latency_ms в TraceRecord > 0
14. **reload_rules** — загрузить новый RuleSet, старые правила больше не матчатся

Для тестов с trace используй `tmp_path`, для тестов без trace — передавай `trace_config=None`.

## Защитные условия

- ShieldEngine — единая точка входа, **не обходи** отдельные компоненты
- Если PIIDetector бросает исключение — ShieldEngine должен поймать его и продолжить с ALLOW (fail-open поведение с ошибкой в trace). Никакое внутреннее исключение не должно "всплыть" и сломать AgentLoop.
- Все предыдущие тесты проходят

## Проверки перед коммитом

```bash
ruff check policyshield/
pytest tests/ -v
```

## Коммит

```
git add -A && git commit -m "feat(shield): ShieldEngine orchestrator — check, post_check, audit mode, fail-open"
```
