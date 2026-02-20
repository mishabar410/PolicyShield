"""Decorator API for inline function protection."""

from __future__ import annotations

import functools
from typing import Any, Callable

from policyshield.core.models import Verdict


def guard(
    tool_name: str,
    engine: Any = None,
    on_block: str = "raise",
) -> Callable:
    """Decorator that checks tool call before executing function.

    Args:
        tool_name: Tool name for the check.
        engine: ShieldEngine instance (auto-created from env if None).
        on_block: ``"raise"`` to raise PermissionError, ``"return_none"`` to return None.
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
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


_default_engine: Any = None


def _get_default_engine() -> Any:
    global _default_engine
    if _default_engine is None:
        import os

        from policyshield.shield.engine import ShieldEngine

        rules_path = os.environ.get("POLICYSHIELD_RULES", "policies/rules.yaml")
        _default_engine = ShieldEngine(rules=rules_path)
    return _default_engine
