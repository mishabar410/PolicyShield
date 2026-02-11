# Prompt 02 — Hot Reload

## Цель

Добавить возможность перезагрузки YAML-правил без перезапуска агента. ShieldEngine будет следить за изменениями файлов правил и автоматически перезагружать их при изменении.

## Контекст

- `ShieldEngine.reload_rules(path)` уже существует в `engine.py` (перезагрузка вручную)
- Правила грузятся через `load_rules()` из `parser.py`
- Нужно: file watcher + thread-safe swap правил

## Что сделать

### 1. Создать `policyshield/shield/watcher.py`

Класс `RuleWatcher`:

```python
class RuleWatcher:
    """Watches YAML rule files for changes and triggers reload."""
    
    def __init__(
        self,
        path: str | Path,
        callback: Callable[[RuleSet], None],
        poll_interval: float = 2.0,   # секунды между проверками
    ):
        ...

    def start(self) -> None:
        """Start watching in a background daemon thread."""
        
    def stop(self) -> None:
        """Stop watching."""
        
    @property
    def is_alive(self) -> bool:
        """Return True if watcher thread is running."""
```

**Механизм:**
- Polling-based (без watchdog-зависимости): каждые `poll_interval` секунд проверяет mtime всех `.yaml` файлов в директории
- Хранит `dict[Path, float]` — маппинг файл → последний mtime
- При изменении: вызывает `load_rules(path)`, и если успешно — вызывает `callback(new_ruleset)`
- При ошибке парсинга: логирует warning, НЕ заменяет текущие правила (fail-safe)
- Daemon thread — не блокирует завершение программы

### 2. Обновить `ShieldEngine`

- Новый параметр конструктора: `watch: bool = False`
- Если `watch=True` и `rules` — путь к файлу/директории, создать `RuleWatcher`
- Thread-safe swap правил: использовать `threading.Lock` для замены `self._matcher` и `self._ruleset`
- Метод `start_watching() -> None`
- Метод `stop_watching() -> None`
- При `__del__` или context manager exit: `stop_watching()`

### 3. Тесты: `tests/test_watcher.py`

Минимум 8 тестов:

```
test_watcher_detects_file_change          — изменить файл → callback вызван
test_watcher_no_change_no_callback        — файл не менялся → callback не вызван
test_watcher_invalid_yaml_keeps_old       — записать невалидный YAML → callback не вызван, старые правила работают
test_watcher_start_stop                   — start/stop корректно завершается
test_watcher_daemon_thread                — thread.daemon == True
test_engine_watch_flag_creates_watcher    — ShieldEngine(watch=True) → watcher создан
test_engine_reload_thread_safe            — параллельные check() и reload → нет race condition
test_engine_watch_updates_rules           — изменить YAML → engine.rule_count() обновился
```

**Важно:** тесты с file watcher используют `tmp_path` для временных файлов и `time.sleep()` для ожидания poll cycle. Timeout ≤ 5 секунд.

### 4. Обновить CLI

В `app()` добавить глобальный флаг `--watch`, который при использовании с validate будет следить за файлом:

```bash
policyshield validate --watch ./policies/   # перезагружает при изменении
```

## Самопроверки

```bash
# Все тесты проходят
pytest tests/ -q

# Lint чист
ruff check policyshield/ tests/

# Coverage ≥ 85%
pytest tests/ --cov=policyshield --cov-fail-under=85

# Ручная проверка hot reload
python -c "
from policyshield.shield import ShieldEngine
e = ShieldEngine('examples/policies/security.yaml', watch=True)
print(f'Rules: {e.rule_count()}')
# В другом терминале: добавить правило в security.yaml
# Подождать 3 секунды
import time; time.sleep(3)
print(f'Rules after: {e.rule_count()}')
e.stop_watching()
"
```

## Коммит

```
feat(reload): add file watcher for hot reload of YAML rules

- Add RuleWatcher with polling-based file change detection
- Add watch=True parameter to ShieldEngine
- Thread-safe rule swap with Lock
- Fail-safe: invalid YAML does not replace working rules
- Add 8+ tests for watcher functionality
```
