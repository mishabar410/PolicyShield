# Промпт 13 — Финализация: примеры, документация, публикация

## Контекст

Код v0.1 готов и протестирован. Теперь нужно добавить примеры использования, обновить README с реальными инструкциями, и подготовить пакет к публикации.

## Задача

### 1. Примеры правил

Создай директорию `examples/policies/` с тремя файлами:

**`examples/policies/security.yaml`** — правила безопасности:
- Блокировка деструктивных shell-команд (rm -rf, mkfs, dd)
- Блокировка network tools с PII (web_fetch, web_search)
- Approval для curl/wget команд
- Блокировка записи за пределами workspace

**`examples/policies/compliance.yaml`** — правила compliance:
- Запрет отправки PII во внешние API
- Rate limiting (10 web-запросов на сессию)
- Лог всех shell-команд (allow с trace)

**`examples/policies/minimal.yaml`** — минимальный пример (2-3 правила) с подробными комментариями, объясняющими формат

### 2. Quick Start Guide

Создай `docs/QUICKSTART.md`:

Пошаговый guide от установки до работающей защиты:
1. `pip install policyshield`
2. Создание правил (скопировать из examples)
3. Валидация: `policyshield validate ./policies/`
4. Интеграция с nanobot (конфигурация)
5. Проверка: отправить агенту сообщение, вызывающее block → показать что видит агент и что записано в trace
6. Просмотр trace: `policyshield trace show`

### 3. Обновление README.md

Обнови главный README:
- Добавь бейджи: Python version, License, Tests (placeholder URL)
- Добавь секцию "Quick Start" — краткую версию из QUICKSTART.md
- Добавь секцию "Examples" со ссылками на example policies
- Добавь секцию "Development" с инструкциями по клонированию, установке dev-зависимостей, запуску тестов
- Убедись что все ссылки на документы (CLAUDE.md, TECHNICAL_SPEC.md, INTEGRATION_SPEC.md) рабочие

### 4. Подготовка к публикации

- Проверь что `pyproject.toml` содержит все необходимые metadata: author, license, project-urls, classifiers, keywords
- Создай `LICENSE` файл (MIT)
- Создай `.gitignore` (Python-стандартный + .venv, dist/, *.egg-info, .ruff_cache)
- Убедись что `policyshield validate examples/policies/` работает

### 5. Финальная проверка

Запусти полную проверку:

```bash
# Линтер
ruff check policyshield/ tests/

# Все тесты
pytest tests/ -v --tb=short

# Coverage
pytest tests/ --cov=policyshield --cov-report=term-missing

# CLI
policyshield --version
policyshield validate examples/policies/

# Проверка что пакет собирается
pip install build
python -m build --sdist --wheel
```

Все тесты проходят, coverage ≥ 85%, пакет собирается без ошибок.

## Коммит

```
git add -A && git commit -m "docs: examples, quickstart, README update, package metadata — v0.1.0 ready"
```

## Финальный тег

```
git tag v0.1.0
```
