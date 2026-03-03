"""Sanitize args before exposing in approval channels (Telegram/API)."""

from __future__ import annotations

import re

_SECRET_PATTERNS = [
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}", re.I), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9]{32,}\b"), "[REDACTED_API_KEY]"),
    (
        re.compile(r"(?:password|passwd|pwd|secret|token)\s*[:=]\s*\S+", re.I),
        "[REDACTED]",
    ),
]
MAX_VALUE_LENGTH = 200


def _sanitize_value(value: object) -> object:
    """Recursively sanitize a single value (Issue #158)."""
    if isinstance(value, dict):
        return {k: _sanitize_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_sanitize_value(item) for item in value)

    v_str = str(value)
    for pattern, replacement in _SECRET_PATTERNS:
        v_str = pattern.sub(replacement, v_str)
    if len(v_str) > MAX_VALUE_LENGTH:
        v_str = v_str[:MAX_VALUE_LENGTH] + "… (truncated)"
    return v_str


def sanitize_args(args: dict) -> dict:
    """Mask sensitive values and truncate long strings (recursive)."""
    return {k: _sanitize_value(v) for k, v in args.items()}
