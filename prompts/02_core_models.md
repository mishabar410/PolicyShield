# Промпт 02 — Базовые модели данных

## Контекст

В промпте 01 была создана структура проекта. Теперь нужно определить все базовые типы данных, на которых будет строиться остальная система. Спецификация моделей — в разделах 3–8 файла `TECHNICAL_SPEC.md`.

Не пиши пока никакой логики — только модели данных (dataclasses / Pydantic models). Каждый последующий модуль будет импортировать модели из `policyshield.core`.

## Задача

Создай файл `policyshield/core/models.py` со следующими моделями:

### Enums

1. **Verdict** — enum с вариантами: `ALLOW`, `BLOCK`, `APPROVE`, `REDACT`.
2. **Severity** — enum с вариантами: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
3. **PIIType** — enum с вариантами: `EMAIL`, `PHONE`, `CREDIT_CARD`, `SSN`, `IBAN`, `IP_ADDRESS`, `PASSPORT`, `DATE_OF_BIRTH`, `CUSTOM`.
4. **ShieldMode** — enum с вариантами: `ENFORCE`, `AUDIT`, `DISABLED`.

### Модели данных

5. **ArgsMatcherConfig** — конфигурация одного матчера для аргументов. Поля: `field` (str, имя поля или "any_field"), `predicate` (str — тип предиката: "regex", "contains", "starts_with", "contains_pattern"), `value` (str — значение для проверки). Все поля обязательны.

6. **RuleConfig** — одно правило из YAML. Поля: `id` (str), `description` (str, optional, default ""), `when` (словарь с настройками матчеров), `then` (Verdict), `message` (str, optional), `severity` (Severity, default LOW), `enabled` (bool, default True). Важно: `when` пока принимай как dict, не пытайся типизировать вложенную структуру — это задача парсера в промпте 03.

7. **RuleSet** — набор правил. Поля: `shield_name` (str), `version` (int), `rules` (list[RuleConfig]). Добавь метод `enabled_rules() -> list[RuleConfig]`, который возвращает только правила с `enabled=True`.

8. **PIIMatch** — найденный PII. Поля: `pii_type` (PIIType), `field` (str — имя поля, где найден), `span` (tuple[int, int] — позиция в строке), `masked_value` (str — замаскированное значение, e.g. `j***@c***.com`).

9. **ShieldResult** — результат проверки одного tool call. Поля: `verdict` (Verdict), `rule_id` (str | None), `message` (str — текст для агента), `pii_matches` (list[PIIMatch], default []), `original_args` (dict | None), `modified_args` (dict | None — для REDACT).

10. **SessionState** — состояние сессии. Поля: `session_id` (str), `created_at` (datetime), `tool_counts` (dict[str, int], default пустой — счётчик вызовов per tool), `total_calls` (int, default 0), `taints` (set[PIIType], default пустой). Добавь метод `increment(tool_name: str)` который увеличивает `tool_counts[tool_name]` и `total_calls`.

11. **TraceRecord** — одна запись аудитного лога. Поля: `timestamp` (datetime), `session_id` (str), `tool` (str), `verdict` (Verdict), `rule_id` (str | None), `pii_types` (list[str], default []), `latency_ms` (float), `args_hash` (str | None — SHA256 хеш аргументов для приватности).

Все модели используй как Pydantic `BaseModel` (кроме enums). Добавь `model_config = ConfigDict(frozen=True)` для всех неизменяемых моделей (все кроме SessionState). Для SessionState — `frozen=False` (он мутируется).

Реэкспортируй все модели из `policyshield/core/__init__.py`.

## Тесты

Напиши `tests/test_models.py`:
- Создание каждой модели с минимальными аргументами — проверить что не падает
- Создание RuleConfig с `then=Verdict.BLOCK` — проверить `rule.then == Verdict.BLOCK`
- Создание RuleSet и вызов `enabled_rules()` — проверить фильтрацию
- Создание SessionState, вызов `increment("exec")` дважды — проверить `tool_counts["exec"] == 2` и `total_calls == 2`
- Создание PIIMatch и проверка полей
- Создание ShieldResult с verdict=ALLOW и пустым списком pii_matches
- Проверить что frozen-модели действительно immutable (pytest.raises при попытке присвоить)

## Проверки перед коммитом

```bash
ruff check policyshield/
pytest tests/ -v
```

Все тесты из предыдущих промптов тоже должны проходить (test_import.py + test_models.py).

## Коммит

```
git add -A && git commit -m "feat(core): add base data models — Rule, Verdict, PII, Session, Trace"
```
