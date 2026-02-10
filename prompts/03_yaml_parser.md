# Промпт 03 — YAML DSL парсер

## Контекст

В промпте 02 были созданы модели данных (RuleConfig, RuleSet и т.д.). Теперь нужно реализовать загрузку и валидацию YAML-файлов с правилами и преобразование их в RuleSet. Спецификация формата YAML — в разделе 3 `TECHNICAL_SPEC.md`.

## Задача

Создай файл `policyshield/core/parser.py` с функциями:

### 1. `parse_rule_file(path: Path) -> RuleSet`

Загружает один YAML-файл и возвращает `RuleSet`. Логика:
- Прочитать YAML через `yaml.safe_load`
- Верхний уровень должен содержать: `shield` (str), `version` (int), `rules` (list)
- Для каждого элемента `rules` — создать `RuleConfig`:
  - `id` — обязателен, должен быть уникален в рамках файла
  - `then` — обязателен, преобразовать строку "block" → `Verdict.BLOCK` (case-insensitive)
  - `when` — обязателен, оставить как dict (парсинг when-блока — задача matcher-а, не парсера)
  - Остальные поля — опциональны
- При любой ошибке формата — бросить `PolicyShieldParseError` с понятным сообщением: какой файл, какое правило, что не так

### 2. `load_rules(directory: Path) -> RuleSet`

Загружает все `*.yaml` и `*.yml` файлы из директории (не рекурсивно). Объединяет в один RuleSet:
- `shield_name` = имя директории
- `version` = максимальный version из файлов
- `rules` = все правила из всех файлов
- Проверить уникальность `id` **между файлами** — при коллизии бросить ошибку

### 3. `validate_rule_set(rule_set: RuleSet) -> list[str]`

Валидация загруженного RuleSet. Вернуть список предупреждений/ошибок (строки). Проверки:
- Нет правил с одинаковым `id`
- У каждого правила `when` содержит хотя бы `tool`
- `then` — валидный Verdict
- Если `severity: critical`, то `then` должен быть `block` (предупреждение, не ошибка)

### 4. Исключение `PolicyShieldParseError`

Создай `policyshield/core/exceptions.py` с классом `PolicyShieldParseError(Exception)`. Реэкспортируй из `core/__init__.py`.

## Тесты

Напиши `tests/test_parser.py`:

Создай фикстуру `tmp_path` с тестовыми YAML-файлами:

1. **Валидный файл** — 3 правила (block, allow, approve), проверить что parse_rule_file возвращает RuleSet с 3 правилами, типы Verdict правильные
2. **Несколько файлов** — создать 2 YAML-файла в tmp_path, вызвать load_rules, проверить объединение
3. **Дублирующийся id** — два файла с одинаковым rule id → `PolicyShieldParseError`
4. **Невалидный YAML** — сломанный синтаксис → `PolicyShieldParseError`
5. **Отсутствующее обязательное поле** — правило без `then` → `PolicyShieldParseError`
6. **Кейс-инсенситивность verdict** — `then: BLOCK`, `then: block`, `then: Block` → все парсятся в `Verdict.BLOCK`
7. **Пустая директория** — load_rules возвращает RuleSet с пустым rules
8. **validate_rule_set** — передать RuleSet без `tool` в when — проверить что возвращает предупреждение

## Защитные условия

- Импорты из `policyshield.core.models` должны работать (не сломай модели)
- Все тесты предыдущих промптов (test_import, test_models) должны проходить

## Проверки перед коммитом

```bash
ruff check policyshield/
pytest tests/ -v
```

## Коммит

```
git add -A && git commit -m "feat(core): YAML DSL parser — load_rules, validate, error handling"
```
