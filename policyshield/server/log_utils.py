"""Safe logging utilities to prevent PII/secret leakage in production logs."""

from __future__ import annotations


def safe_args_summary(args: dict, max_keys: int = 5) -> str:
    """Return keys-only summary of args for safe logging."""
    keys = list(args.keys())[:max_keys]
    suffix = f" +{len(args) - max_keys} more" if len(args) > max_keys else ""
    parts = []
    for k in keys:
        v = args[k]
        if isinstance(v, str) and len(v) > 200:
            parts.append(f"{k}=<truncated>")
        else:
            parts.append(k)
    return f"keys=[{', '.join(parts)}{suffix}]"
