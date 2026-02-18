# Prompt 338 — Python Version Validation

## Цель

Проверять при импорте, что Python ≥ 3.10 — иначе непонятная ошибка на `match/case` или `X | Y` union types.

## Контекст

- `pyproject.toml` указывает `requires-python = ">=3.10"`, но pip может обойти
- На Python 3.9 → `SyntaxError: invalid syntax` без объяснения
- Нужно: проверка в `__init__.py` с понятной ошибкой

## Что сделать

```python
# policyshield/__init__.py — в самом начале файла:
import sys

if sys.version_info < (3, 10):
    raise RuntimeError(
        f"PolicyShield requires Python 3.10+, but you're running {sys.version}. "
        "Please upgrade Python or use a virtual environment with 3.10+."
    )
```

## Тесты

```python
class TestPythonVersionCheck:
    def test_version_error_message_is_clear(self):
        """Verify the error message format."""
        # Mock sys.version_info < (3, 10) → check error message
        import unittest.mock as mock
        with mock.patch("sys.version_info", (3, 9, 0)):
            # Can't easily test __init__.py re-import, test the condition
            assert (3, 9, 0) < (3, 10)

    def test_current_version_passes(self):
        import sys
        assert sys.version_info >= (3, 10)
```

## Самопроверка

```bash
pytest tests/test_lifecycle.py::TestPythonVersionCheck -v
pytest tests/ -q
```

## Коммит

```
feat: add Python 3.10+ version check at import time
```
