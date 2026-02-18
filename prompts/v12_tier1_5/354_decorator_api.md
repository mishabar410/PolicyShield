# Prompt 354 — Decorator API

## Цель

Добавить `@shield.guard("tool_name")` декоратор для inline-защиты функций без YAML-правил.

## Контекст

- Для быстрого прототипирования: `@shield.guard("send_email")` → автоматический check
- Не заменяет YAML-правила, а дополняет (dev/testing convenience)

## Что сделать

```python
# policyshield/decorators.py
import functools
from typing import Callable
from policyshield.core.models import Verdict

def guard(tool_name: str, engine=None, on_block: str = "raise"):
    """Decorator that checks tool call before executing function.

    Args:
        tool_name: Tool name for the check
        engine: ShieldEngine instance (auto-created if None)
        on_block: "raise" | "return_none" — behavior on BLOCK verdict
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            _engine = engine or _get_default_engine()
            result = _engine.check(tool_name, kwargs)
            if result.verdict == Verdict.BLOCK:
                if on_block == "raise":
                    raise PermissionError(f"PolicyShield BLOCKED: {result.message}")
                return None
            if result.modified_args:
                kwargs.update(result.modified_args)
            return func(*args, **kwargs)
        return wrapper
    return decorator

_default_engine = None
def _get_default_engine():
    global _default_engine
    if _default_engine is None:
        from policyshield.shield.sync_engine import ShieldEngine
        _default_engine = ShieldEngine()
    return _default_engine
```

## Тесты

```python
class TestDecoratorAPI:
    def test_guard_allows(self, engine):
        @guard("safe_tool", engine=engine)
        def my_func(x=1):
            return x * 2
        assert my_func(x=5) == 10

    def test_guard_blocks(self, blocking_engine):
        @guard("blocked_tool", engine=blocking_engine, on_block="raise")
        def my_func():
            return "should not reach"
        with pytest.raises(PermissionError):
            my_func()

    def test_guard_return_none_on_block(self, blocking_engine):
        @guard("blocked_tool", engine=blocking_engine, on_block="return_none")
        def my_func():
            return "value"
        assert my_func() is None
```

## Самопроверка

```bash
pytest tests/test_dx.py::TestDecoratorAPI -v
pytest tests/ -q
```

## Коммит

```
feat: add @guard() decorator API for inline function protection
```
