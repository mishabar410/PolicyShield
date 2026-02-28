"""Decorator API for inline function protection.

Provides both sync and async decorators for wrapping tool calls
with PolicyShield checks.

Usage:
    from policyshield.decorators import shield

    @shield(engine)
    def read_file(path: str) -> str: ...

    @shield(engine, tool_name="exec_command")
    async def run_command(cmd: str) -> str: ...
"""

from __future__ import annotations

import asyncio
import functools
import threading
from typing import Any, Callable

from policyshield.core.models import Verdict


def shield(
    engine: Any,
    tool_name: str | None = None,
    session_id: str = "default",
    on_block: str = "raise",
) -> Callable:
    """Decorator that checks tool call before executing the function.

    Works with both sync and async functions.

    Args:
        engine: ShieldEngine or AsyncShieldEngine instance.
        tool_name: Override tool name (defaults to function name).
        session_id: Session ID for the check.
        on_block: ``"raise"`` to raise PermissionError, ``"return_none"`` to return None.

    Raises:
        PermissionError: If the tool call is blocked and on_block="raise".
    """

    def decorator(func: Callable) -> Callable:
        name = tool_name or func.__name__

        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                result = await engine.check(name, kwargs, session_id=session_id)
                if result.verdict in (Verdict.BLOCK, Verdict.APPROVE):
                    if on_block == "raise":
                        raise PermissionError(f"PolicyShield {result.verdict.value}: {result.message}")
                    return None
                if result.modified_args:
                    kwargs.update(result.modified_args)
                return await func(*args, **kwargs)

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                result = engine.check(name, kwargs, session_id=session_id)
                if result.verdict in (Verdict.BLOCK, Verdict.APPROVE):
                    if on_block == "raise":
                        raise PermissionError(f"PolicyShield {result.verdict.value}: {result.message}")
                    return None
                if result.modified_args:
                    kwargs.update(result.modified_args)
                return func(*args, **kwargs)

            return sync_wrapper

    return decorator


# Legacy backward-compatible alias: guard(tool_name, engine=..., on_block=...)
def guard(
    tool_name: str,
    engine: Any = None,
    on_block: str = "raise",
) -> Callable:
    """Backward-compatible decorator — tool_name as first arg.

    Usage (legacy):
        @guard("exec_command", engine=engine, on_block="raise")
        def run(cmd): ...
    """
    _engine = engine or _get_default_engine()
    return shield(_engine, tool_name=tool_name, on_block=on_block)


_default_engine: Any = None
_default_engine_lock: threading.Lock = threading.Lock()


def _get_default_engine() -> Any:
    global _default_engine
    if _default_engine is not None:
        return _default_engine
    with _default_engine_lock:
        if _default_engine is not None:  # double-checked locking
            return _default_engine
        import os

        from policyshield.shield.engine import ShieldEngine

        rules_path = os.environ.get("POLICYSHIELD_RULES", "policies/rules.yaml")
        _default_engine = ShieldEngine(rules=rules_path)
    return _default_engine
