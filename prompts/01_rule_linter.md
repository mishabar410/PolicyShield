# Prompt 01 — Rule Linter

## Цель

Добавить CLI-команду `policyshield lint <path>`, которая статически анализирует YAML-правила и находит потенциальные проблемы: дубликаты ID, невалидные regex, конфликтующие правила, unreachable rules, слишком широкие паттерны.

## Контекст

- Существующий CLI: `policyshield/cli/main.py` (validate, trace show, trace violations)
- Парсер: `policyshield/core/parser.py` — `load_rules()` возвращает `RuleSet`
- Модели: `policyshield/core/models.py` — `RuleConfig`, `RuleSet`

## Что сделать

### 1. Создать `policyshield/lint/linter.py`

Класс `RuleLinter` с методом `lint(ruleset: RuleSet) -> list[LintWarning]`.

Проверки (каждая — отдельный метод):

1. **`check_duplicate_ids`** — два правила с одинаковым `id`
   - Severity: ERROR
   
2. **`check_invalid_regex`** — `args_match` содержит невалидный regex (не компилируется через `re.compile`)
   - Severity: ERROR
   
3. **`check_broad_tool_pattern`** — `tool: ".*"` или `tool: ".+"` — слишком широкий паттерн, ловит всё
   - Severity: WARNING
   
4. **`check_missing_message`** — правило с `then: block` без `message` (агент не получит объяснения)
   - Severity: WARNING
   
5. **`check_conflicting_verdicts`** — два правила с одинаковым `when.tool` и пересекающимися `args_match`, но разными вердиктами
   - Severity: WARNING
   
6. **`check_disabled_rules`** — `enabled: false` — не ошибка, но информация
   - Severity: INFO

### 2. Создать `policyshield/lint/__init__.py`

Экспорт: `RuleLinter`, `LintWarning`.

### 3. Создать модель `LintWarning`

```python
@dataclass
class LintWarning:
    level: str          # ERROR, WARNING, INFO
    rule_id: str        # ID правила (или "*" если глобальная проблема)
    check: str          # Имя проверки (duplicate_ids, invalid_regex, ...)
    message: str        # Человекочитаемое описание
```

### 4. Добавить CLI-команду `lint`

В `policyshield/cli/main.py`:
- Подкоманда `lint <path>` — загружает правила, запускает `RuleLinter.lint()`, выводит результаты
- Формат вывода:
  ```
  ✗ ERROR [no-shell] duplicate_ids: Duplicate rule ID 'no-shell' (first seen in rule #1)
  ⚠ WARNING [catch-all] broad_tool_pattern: Tool pattern '.*' matches all tools
  ℹ INFO [old-rule] disabled_rules: Rule is disabled
  
  2 errors, 1 warning, 1 info
  ```
- Exit code: 1 если есть ERROR, 0 если только WARNING/INFO

### 5. Тесты: `tests/test_linter.py`

Минимум 12 тестов:

```
test_lint_clean_rules_no_warnings         — корректный набор правил → пустой список
test_lint_duplicate_ids                    — два правила с id="foo" → ERROR
test_lint_invalid_regex                    — args_match с невалидным regex → ERROR
test_lint_broad_tool_wildcard             — tool: ".*" → WARNING
test_lint_missing_message_on_block        — then: block без message → WARNING
test_lint_missing_message_on_allow        — then: allow без message → OK (не нужен)
test_lint_conflicting_verdicts            — два правила на один tool, block vs allow → WARNING
test_lint_disabled_rule_info              — enabled: false → INFO
test_lint_multiple_issues                 — набор с несколькими проблемами → все найдены
test_cli_lint_valid_file                   — CLI: lint хороший файл → exit 0
test_cli_lint_file_with_errors             — CLI: lint файл с ошибками → exit 1
test_cli_lint_nonexistent_file             — CLI: lint несуществующий файл → exit 1
```

## Самопроверки

```bash
# Все тесты проходят (включая старые 152)
pytest tests/ -q

# Lint чист
ruff check policyshield/ tests/

# Coverage ≥ 85%
pytest tests/ --cov=policyshield --cov-fail-under=85

# CLI работает
policyshield lint examples/policies/security.yaml
policyshield lint examples/policies/  # директория
```

## Коммит

```
feat(lint): add rule linter with 6 static checks

- Add RuleLinter with checks: duplicate_ids, invalid_regex,
  broad_tool_pattern, missing_message, conflicting_verdicts,
  disabled_rules
- Add `policyshield lint` CLI command
- Add 12+ tests for linter
```
