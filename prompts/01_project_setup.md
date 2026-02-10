# Промпт 01 — Инициализация проекта

## Контекст

Ты реализуешь PolicyShield — декларативный firewall для tool calls AI-агентов. Полная техническая спецификация: `TECHNICAL_SPEC.md`. Интеграция с nanobot: `INTEGRATION_SPEC.md`.

Сейчас — первый шаг: создание структуры проекта, зависимостей и базовой инфраструктуры.

## Задача

1. Создай `pyproject.toml` с метаданными проекта:
   - Имя пакета: `policyshield`
   - Версия: `0.1.0`
   - Python: `>=3.10`
   - Зависимости: `pyyaml`, `pydantic>=2.0`
   - Dev-зависимости (optional group `dev`): `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`
   - Точка входа CLI: `policyshield` → `policyshield.cli.main:app`
   - Build backend: `hatchling`

2. Создай структуру директорий с пустыми `__init__.py`:
   ```
   policyshield/
   ├── __init__.py          (экспортировать __version__ = "0.1.0")
   ├── core/
   │   ├── __init__.py
   ├── shield/
   │   ├── __init__.py
   ├── integrations/
   │   ├── __init__.py
   │   └── nanobot/
   │       ├── __init__.py
   ├── trace/
   │   ├── __init__.py
   └── cli/
       ├── __init__.py
   ```

3. Создай `ruff.toml` с настройками линтера (line-length=120, target-version="py310").

4. Создай `tests/` директорию с пустым `conftest.py` и `tests/__init__.py`.

## Тесты

Напиши `tests/test_import.py`:
- Проверить, что `import policyshield` работает
- Проверить, что `policyshield.__version__ == "0.1.0"`
- Проверить, что все подмодули импортируются без ошибок: `policyshield.core`, `policyshield.shield`, `policyshield.trace`, `policyshield.cli`, `policyshield.integrations`, `policyshield.integrations.nanobot`

## Проверки перед коммитом

```bash
cd /Users/misha/PolicyShield
pip install -e ".[dev]"
ruff check policyshield/
pytest tests/ -v
```

Все тесты должны пройти, ruff не должен выдать ошибок.

## Коммит

```
git add -A && git commit -m "chore: init project structure, pyproject.toml, dev tooling"
```
