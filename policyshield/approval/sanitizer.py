"""Sanitize args before exposing in approval channels (Telegram/API)."""

from __future__ import annotations

import re

_SECRET_PATTERNS = [
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}", re.I), "[REDACTED_AWS_KEY]"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[REDACTED_API_KEY]"),
    (
        re.compile(r"(?:password|passwd|pwd|secret|token)\s*[:=]\s*\S+", re.I),
        "[REDACTED]",
    ),
]
MAX_VALUE_LENGTH = 200


def sanitize_args(args: dict) -> dict:
    """Mask sensitive values and truncate long strings."""
    sanitized = {}
    for k, v in args.items():
        v_str = str(v)
        # Redact known secret patterns
        for pattern, replacement in _SECRET_PATTERNS:
            v_str = pattern.sub(replacement, v_str)
        # Truncate
        if len(v_str) > MAX_VALUE_LENGTH:
            v_str = v_str[:MAX_VALUE_LENGTH] + "… (truncated)"
        sanitized[k] = v_str
    return sanitized
