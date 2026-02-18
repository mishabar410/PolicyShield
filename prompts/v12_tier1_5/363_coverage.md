# Prompt 363 — Test Coverage Gate

## Цель

Добавить coverage reporting и минимальный порог (80%) в CI.

## Контекст

- `pytest` запускается, но coverage не измеряется
- Нужно: `pytest --cov=policyshield --cov-fail-under=80`

## Что сделать

### 1. Обновить `pyproject.toml`

```toml
[tool.pytest.ini_options]
addopts = "--cov=policyshield --cov-report=term-missing --cov-fail-under=80"

[tool.coverage.run]
source = ["policyshield"]
omit = ["policyshield/presets/*", "tests/*"]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "if __name__",
    "if TYPE_CHECKING",
]
```

### 2. Добавить `pytest-cov` в dev deps

```bash
pip install pytest-cov
```

### 3. Обновить CI (если есть)

```yaml
# .github/workflows/test.yml
- run: pytest --cov=policyshield --cov-report=xml --cov-fail-under=80
```

## Тесты

```bash
# Самопроверка: запустить с coverage
pytest tests/ --cov=policyshield --cov-report=term-missing
```

## Коммит

```
ci: add test coverage gate (80% minimum via pytest-cov)
```
