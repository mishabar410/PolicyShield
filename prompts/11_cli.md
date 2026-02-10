# Промпт 11 — CLI: validate и trace

## Контекст

Все runtime-компоненты готовы. Теперь нужен CLI для работы с правилами и трейсом. Спецификация — раздел 9 `TECHNICAL_SPEC.md`.

CLI использует только уже созданные компоненты — парсер, валидатор, чтение файлов. Никакой новой логики.

## Задача

Создай файл `policyshield/cli/main.py`:

Используй `argparse` (не добавляй новую зависимость). Точка входа — функция `app()` (уже прописана в pyproject.toml как `policyshield`).

### Команда `policyshield validate <path>`

- `<path>` — путь к YAML-файлу или директории с правилами
- Загрузить правила через `load_rules()` или `parse_rule_file()`
- Вызвать `validate_rule_set()`
- Вывести результат:
  - Если ок: `"✅ {N} rules loaded, no errors"` + список правил (id, then, description) в виде таблицы
  - Если ошибки: `"❌ Validation errors:"` + список ошибок, exit code 1
  - Если файл не найден / невалидный YAML: понятная ошибка, exit code 1

### Команда `policyshield trace show <path>`

- `<path>` — путь к JSONL trace-файлу
- Прочитать файл, распарсить каждую строку как JSON
- Вывести таблицу: `timestamp | session | tool | verdict | rule | pii`
- Опции:
  - `--verdict <BLOCK|ALLOW|...>` — фильтр по вердикту
  - `--session <id>` — фильтр по сессии
  - `--limit <N>` — максимальное число записей (default 100)

### Команда `policyshield trace violations <path>`

- Показать только записи с verdict != ALLOW
- Те же фильтры что у `trace show`

### Общее

- `policyshield --version` → вывести `policyshield.__version__`
- `policyshield --help` → описание команд
- При ошибочной команде — help, exit code 1

## Тесты

Напиши `tests/test_cli.py`:

Используй `subprocess.run` для запуска CLI — это более реалистично чем вызов функций:

1. **validate — валидный файл** — создать YAML во tmp-файле, `policyshield validate <path>` → exit code 0, stdout содержит "✅" и число правил
2. **validate — невалидный** — YAML без обязательных полей → exit code 1
3. **validate — директория** — создать tmp-директорию с 2 YAML → exit code 0
4. **validate — несуществующий путь** — exit code 1, stderr содержит "not found" или ошибку
5. **trace show** — создать JSONL с 3 записями, `policyshield trace show <path>` → exit code 0, stdout содержит 3 записи
6. **trace show —verdict BLOCK** — из 3 записей (2 ALLOW, 1 BLOCK) → показать 1
7. **trace violations** — из 3 записей (2 ALLOW, 1 BLOCK) → показать 1
8. **--version** — вывод содержит версию
9. **--help** — exit code 0

Для тестов через subprocess: убедись что `policyshield` доступен в PATH (после `pip install -e .`). Если нет — используй `sys.executable -m policyshield.cli.main` как fallback.

**Альтернативно:** если subprocess усложняет, тестируй через вызов `app()` напрямую с mock `sys.argv`. Оба подхода приемлемы.

## Защитные условия

- CLI не должен импортировать nanobot-специфичные модули — он работает standalone
- При любой ошибке — понятный текст, не Python traceback (обработай исключения)
- Все предыдущие тесты проходят

## Проверки перед коммитом

```bash
ruff check policyshield/
pytest tests/ -v
policyshield --version
policyshield --help
```

## Коммит

```
git add -A && git commit -m "feat(cli): policyshield validate + trace show/violations"
```
