# Промпт 10 — ShieldedToolRegistry (интеграция с nanobot)

## Контекст

ShieldEngine (промпт 09) готов. Теперь нужно создать адаптер, который позволяет PolicyShield работать внутри nanobot. Спецификация — разделы 3-6 `INTEGRATION_SPEC.md`.

**Важно:** nanobot — внешняя зависимость. Мы НЕ добавляем его в зависимости пакета. Интеграция работает на основе duck typing: `ShieldedToolRegistry` наследуется от `ToolRegistry`, но nanobot — optional dependency. Если nanobot не установлен, импорт `policyshield.integrations.nanobot` должен бросить `ImportError` с понятным сообщением.

## Задача

### 1. Файл `policyshield/integrations/nanobot/registry.py`

#### Класс `ShieldedToolRegistry`

Наследуется от `nanobot.agent.tools.registry.ToolRegistry`.

**Конструктор:**
- `original_registry: ToolRegistry` — оригинальный реестр с зарегистрированными tools
- `engine: ShieldEngine` — движок PolicyShield
- Скопировать все зарегистрированные tools из original_registry (через `self._tools = original_registry._tools.copy()`)

**Переопределённый метод `async execute(name: str, params: dict) -> str`:**

Flow (соответствует разделу 4.1 INTEGRATION_SPEC):
1. Получить session_id из contextvars (см. ниже). Если не установлен — использовать "default".
2. Вызвать `engine.check(name, params, session_id)` → ShieldResult
3. Обработка verdict:
   - **ALLOW**: вызвать `super().execute(name, params)` → result
   - **BLOCK**: вернуть `engine.verdict_builder.format_counterexample(shield_result)` как строку (НЕ вызывая оригинальный execute)
   - **REDACT**: вызвать `super().execute(name, shield_result.modified_args)` (маскированные аргументы)
   - **APPROVE**: пока (в v0.1) вернуть pending-сообщение
4. Post-call: если verdict != BLOCK и `engine` настроен на post_call_scan — `engine.post_check(name, result, session_id)`
5. Вернуть result

**Из метода не должно вылетать исключений PolicyShield.** Если ShieldEngine бросает ошибку — залогировать (Python logging) и вызвать оригинальный `super().execute()` (fail-open).

### 2. Файл `policyshield/integrations/nanobot/context.py`

Определить contextvars для передачи session_id:

- `shield_session_var: ContextVar[str]` — хранит текущий session_id
- Функция `set_session(session_id: str)` — установить
- Функция `get_session() -> str` — получить (default "default")

### 3. Файл `policyshield/integrations/nanobot/installer.py`

Функция `install_shield(agent_loop, config: dict) -> ShieldEngine`:

1. Загрузить правила из `config["rules_path"]` через `load_rules()`
2. Создать `ShieldEngine` с конфигурацией из `config`
3. Создать `ShieldedToolRegistry(agent_loop.tools, engine)`
4. Подменить `agent_loop.tools` на ShieldedToolRegistry
5. Вернуть ShieldEngine (для доступа к status/reload)

### 4. Реэкспорт

В `policyshield/integrations/nanobot/__init__.py`:
- Попробовать `from nanobot.agent.tools.registry import ToolRegistry`
- Если ImportError — бросить `ImportError("nanobot is required for this integration. Install it: pip install nanobot")`
- Экспортировать: `ShieldedToolRegistry`, `install_shield`, `set_session`, `get_session`

## Тесты

Напиши `tests/test_nanobot_integration.py`:

**Поскольку nanobot может быть не установлен** в dev-среде, **создай mock ToolRegistry** для тестирования:

```python
# В начале файла — mock nanobot если не установлен
import sys
from unittest.mock import MagicMock

# Создать mock-модуль nanobot если не установлен
if "nanobot" not in sys.modules:
    mock_nanobot = MagicMock()
    # Определить минимальный ToolRegistry mock
    class MockToolRegistry:
        def __init__(self):
            self._tools = {}
        async def execute(self, name, params):
            return f"executed {name}"
        def register(self, tool):
            self._tools[tool.name] = tool
        def get_definitions(self):
            return []
    mock_nanobot.agent.tools.registry.ToolRegistry = MockToolRegistry
    sys.modules["nanobot"] = mock_nanobot
    sys.modules["nanobot.agent"] = mock_nanobot.agent
    sys.modules["nanobot.agent.tools"] = mock_nanobot.agent.tools
    sys.modules["nanobot.agent.tools.registry"] = mock_nanobot.agent.tools.registry
```

Тесты:
1. **ALLOW flow** — ShieldEngine с пустыми правилами, execute("read_file", {"path": "/tmp"}) → вызов оригинального execute → result содержит "executed"
2. **BLOCK flow** — правило block для exec, execute("exec", {"command": "rm -rf /"}) → result содержит "BLOCKED", оригинальный execute НЕ вызван
3. **REDACT flow** — правило redact, args с email → оригинальный execute вызван с маскированными args
4. **Fail-open** — сломать ShieldEngine (mock check() бросает Exception) → оригинальный execute вызван, ошибка залогирована
5. **Context var session** — set_session("tg:123"), вызвать execute → ShieldEngine получает session_id="tg:123"
6. **install_shield** — создать mock agent_loop с MockToolRegistry, вызвать install_shield → agent_loop.tools стал ShieldedToolRegistry

## Защитные условия

- nanobot — optional dependency. Тесты работают с mock.
- Если nanobot не установлен — только `policyshield.integrations.nanobot` бросает ImportError. Вся остальная библиотека работает.
- ShieldedToolRegistry fail-open: любая ошибка PolicyShield → fallback к оригинальному execute
- Все предыдущие тесты проходят

## Проверки перед коммитом

```bash
ruff check policyshield/
pytest tests/ -v
```

## Коммит

```
git add -A && git commit -m "feat(integrations): ShieldedToolRegistry for nanobot — execute override, fail-open, contextvars"
```
