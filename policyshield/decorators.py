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

from policyshield.core.exceptions import ApprovalRequiredError
from policyshield.core.models import Verdict


def shield(
    engine: Any,
    tool_name: str | None = None,
    session_id: str = "default",
    on_block: str = "raise",
    context: dict | None = None,
) -> Callable:
    """Decorator that checks tool call before executing the function.

    Works with both sync and async functions.

    Args:
        engine: ShieldEngine or AsyncShieldEngine instance.
        tool_name: Override tool name (defaults to function name).
        session_id: Session ID for the check.
        on_block: ``"raise"`` to raise PermissionError, ``"return_none"`` to return None.
        context: Optional context dict for context-based conditions.

    Raises:
        PermissionError: If the tool call is blocked and on_block="raise".
    """

    def decorator(func: Callable) -> Callable:
        name = tool_name or func.__name__

        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                all_kwargs = _bind_args(func, args, kwargs)
                # Issue #205: support callable session_id for per-request resolution
                sid = session_id() if callable(session_id) else session_id
                ctx = context() if callable(context) else context
                result = await engine.check(name, all_kwargs, session_id=sid, context=ctx)
                if result.verdict == Verdict.BLOCK:
                    if on_block == "raise":
                        raise PermissionError(f"PolicyShield blocked: {result.message}")
                    return None
                if result.verdict == Verdict.APPROVE:
                    if on_block == "raise":
                        raise ApprovalRequiredError(
                            f"PolicyShield requires approval: {result.message}",
                            approval_id=getattr(result, "approval_id", "") or "",
                        )
                    return {
                        "approval_required": True,
                        "approval_id": getattr(result, "approval_id", "") or "",
                        "message": result.message,
                    }
                # NOTE: _rebuild_args may not correctly reconstruct calls for
                # functions with *args or **kwargs variadic signatures. In such
                # cases, the fallback is kwargs-only rebuild.
                if result.modified_args:
                    args, kwargs = _rebuild_args(func, result.modified_args, args, kwargs)
                func_result = await func(*args, **kwargs)
                # Post-check: scan output for PII (Issue #28)
                if hasattr(engine, "post_check"):
                    try:
                        await engine.post_check(name, func_result, session_id=session_id)
                    except Exception:
                        pass  # fail-open on post_check errors
                return func_result

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                all_kwargs = _bind_args(func, args, kwargs)
                # Issue #205: support callable session_id for per-request resolution
                sid = session_id() if callable(session_id) else session_id
                ctx = context() if callable(context) else context
                result = engine.check(name, all_kwargs, session_id=sid, context=ctx)
                if result.verdict == Verdict.BLOCK:
                    if on_block == "raise":
                        raise PermissionError(f"PolicyShield blocked: {result.message}")
                    return None
                if result.verdict == Verdict.APPROVE:
                    if on_block == "raise":
                        raise ApprovalRequiredError(
                            f"PolicyShield requires approval: {result.message}",
                            approval_id=getattr(result, "approval_id", "") or "",
                        )
                    return {
                        "approval_required": True,
                        "approval_id": getattr(result, "approval_id", "") or "",
                        "message": result.message,
                    }
                if result.modified_args:
                    args, kwargs = _rebuild_args(func, result.modified_args, args, kwargs)
                func_result = func(*args, **kwargs)
                # Post-check: scan output for PII (Issue #28)
                if hasattr(engine, "post_check"):
                    try:
                        engine.post_check(name, func_result, session_id=session_id)
                    except Exception:
                        pass  # fail-open on post_check errors
                return func_result

            return sync_wrapper

    return decorator


# Legacy backward-compatible alias: guard(tool_name, engine=..., on_block=...)
def guard(
    tool_name: str,
    engine: Any = None,
    on_block: str = "raise",
    session_id: str = "default",
) -> Callable:
    """Backward-compatible decorator — tool_name as first arg.

    Usage (legacy):
        @guard("exec_command", engine=engine, on_block="raise")
        def run(cmd): ...
    """
    _engine = engine or _get_default_engine()
    return shield(_engine, tool_name=tool_name, on_block=on_block, session_id=session_id)


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
        # Issue #124: Fallback preserves positional args via enumerate
        merged = {f"arg{i}": v for i, v in enumerate(args)}
        merged.update(kwargs)
        return merged


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
        # NOTE Issue #58: Variadic (*args/**kwargs) functions may get incorrect
        # args after REDACT modification. This is a known limitation.
        new_kwargs = dict(original_kwargs)
        new_kwargs.update(modified_args)
        return original_args, new_kwargs


def cleanup_default_engine() -> None:
    """Clean up the global default engine singleton.

    Issue #208: Call this in test teardown to avoid state leakage.
    """
    global _default_engine
    with _default_engine_lock:
        _default_engine = None
