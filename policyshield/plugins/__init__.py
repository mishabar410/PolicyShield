"""Plugin system for PolicyShield — extensible detectors and hooks."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class DetectorResult:
    """Result from a custom detector."""

    detected: bool = False
    message: str = ""
    severity: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)


# Global plugin registry
_detector_registry: dict[str, Callable] = {}
_pre_check_hooks: list[Callable] = []
_post_check_hooks: list[Callable] = []


def detector(name: str, severity: str = "medium"):
    """Decorator to register a custom detector.

    Usage::

        @detector("credit_score_leak")
        def check_credit_score(tool_name: str, args: dict) -> DetectorResult:
            if "credit_score" in str(args):
                return DetectorResult(detected=True, message="Credit score leak")
            return DetectorResult()
    """

    def wrapper(func: Callable) -> Callable:
        _detector_registry[name] = func
        logger.info("Registered detector plugin: %s", name)
        return func

    return wrapper


def pre_check_hook(func: Callable) -> Callable:
    """Register a pre-check hook (runs before rule matching)."""
    _pre_check_hooks.append(func)
    return func


def post_check_hook(func: Callable) -> Callable:
    """Register a post-check hook (runs after verdict)."""
    _post_check_hooks.append(func)
    return func


def get_detectors() -> dict[str, Callable]:
    return dict(_detector_registry)


def get_pre_check_hooks() -> list[Callable]:
    return list(_pre_check_hooks)


def get_post_check_hooks() -> list[Callable]:
    return list(_post_check_hooks)


def clear_registry() -> None:
    """Clear all registered plugins (for testing)."""
    _detector_registry.clear()
    _pre_check_hooks.clear()
    _post_check_hooks.clear()
