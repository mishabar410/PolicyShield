# 504 — Decorator / Middleware API

## Goal

Add `@shield(engine)` decorator for wrapping Python functions with PolicyShield checks — inline integration without running a server.

## Context

- Current inline usage requires explicit `engine.check()` calls
- Decorator pattern is more Pythonic and lower-friction
- Should work with sync and async functions

## Code

### New file: `policyshield/decorators.py`

```python
"""Inline decorator API for PolicyShield."""
import functools
from typing import Any, Callable

def shield(engine, tool_name: str | None = None, session_id: str = "default"):
    """Decorator that checks tool call before executing the function.

    Usage:
        @shield(engine, tool_name="exec_command")
        def run_command(cmd: str) -> str:
            ...

        @shield(engine)  # tool_name = function name
        async def search_web(query: str) -> list:
            ...
    """
    def decorator(fn: Callable) -> Callable:
        name = tool_name or fn.__name__
        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                result = await engine.check(name, kwargs, session_id=session_id)
                if result.verdict.value == "BLOCK":
                    raise PermissionError(f"Blocked by PolicyShield: {result.message}")
                final_args = result.modified_args or kwargs
                return await fn(*args, **final_args)
            return async_wrapper
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args, **kwargs):
                result = engine.check_sync(name, kwargs, session_id=session_id)
                if result.verdict.value == "BLOCK":
                    raise PermissionError(f"Blocked by PolicyShield: {result.message}")
                final_args = result.modified_args or kwargs
                return fn(*args, **final_args)
            return sync_wrapper
    return decorator
```

### Export from `policyshield/__init__.py`

```python
from policyshield.decorators import shield
```

## Tests

### `tests/test_decorators.py`

- Test sync function decorated — ALLOW passes through
- Test sync function decorated — BLOCK raises PermissionError
- Test async function decorated
- Test REDACT modifies args
- Test `tool_name` defaults to function name

## Self-check

```bash
ruff check policyshield/decorators.py tests/test_decorators.py
pytest tests/test_decorators.py -v
```

## Commit

```
feat: add @shield() decorator for inline PolicyShield integration
```
