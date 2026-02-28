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
import inspect
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
                all_kwargs = _bind_args(func, args, kwargs)
                result = await engine.check(name, all_kwargs, session_id=session_id)
                if result.verdict == Verdict.BLOCK:
                    if on_block == "raise":
                        raise PermissionError(f"PolicyShield blocked: {result.message}")
                    return None
                if result.verdict == Verdict.APPROVE:
                    if on_block == "raise":
                        raise PermissionError(f"PolicyShield requires approval: {result.message}")
                    return None
                # NOTE: _rebuild_args may not correctly reconstruct calls for
                # functions with *args or **kwargs variadic signatures. In such
                # cases, the fallback is kwargs-only rebuild.
                if result.modified_args:
                    args, kwargs = _rebuild_args(func, result.modified_args, args, kwargs)
                return await func(*args, **kwargs)

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                all_kwargs = _bind_args(func, args, kwargs)
                result = engine.check(name, all_kwargs, session_id=session_id)
                if result.verdict == Verdict.BLOCK:
                    if on_block == "raise":
                        raise PermissionError(f"PolicyShield blocked: {result.message}")
                    return None
                if result.verdict == Verdict.APPROVE:
                    if on_block == "raise":
                        raise PermissionError(f"PolicyShield requires approval: {result.message}")
                    return None
                if result.modified_args:
                    args, kwargs = _rebuild_args(func, result.modified_args, args, kwargs)
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
    with _default_engine_lock:
        if _default_engine is not None:
            return _default_engine
        import os

        from policyshield.shield.engine import ShieldEngine

        rules_path = os.environ.get("POLICYSHIELD_RULES", "policies/rules.yaml")
        _default_engine = ShieldEngine(rules=rules_path)
        return _default_engine


def _bind_args(func: Callable, args: tuple, kwargs: dict) -> dict:
    """Bind positional and keyword args using the function's signature.

    Returns a merged dict so the engine can check all argument values.
    """
    try:
        sig = inspect.signature(func)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except (ValueError, TypeError):
        # Fallback: return kwargs only (e.g. for builtins without signature)
        return dict(kwargs)


def _rebuild_args(
    func: Callable,
    modified_args: dict,
    original_args: tuple,
    original_kwargs: dict,
) -> tuple[tuple, dict]:
    """Rebuild positional and keyword args from modified_args.

    Prevents 'got multiple values for argument' TypeError by correctly
    placing modified values into positional or keyword slots.
    """
    try:
        sig = inspect.signature(func)
        params = list(sig.parameters.keys())
        new_args = list(original_args)
        new_kwargs = dict(original_kwargs)

        for key, value in modified_args.items():
            if key in params:
                idx = params.index(key)
                if idx < len(new_args):
                    # Was passed as positional — update in-place
                    new_args[idx] = value
                else:
                    new_kwargs[key] = value
            else:
                new_kwargs[key] = value

        return tuple(new_args), new_kwargs
    except (ValueError, TypeError):
        # Fallback: just update kwargs (legacy behavior)
        new_kwargs = dict(original_kwargs)
        new_kwargs.update(modified_args)
        return original_args, new_kwargs
