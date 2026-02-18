"""Safe logging utilities to prevent PII/secret leakage in production logs."""

from __future__ import annotations


def safe_args_summary(args: dict, max_keys: int = 5) -> str:
    """Return keys-only summary of args for safe logging."""
    keys = list(args.keys())[:max_keys]
    suffix = f" +{len(args) - max_keys} more" if len(args) > max_keys else ""
    return f"keys=[{', '.join(keys)}{suffix}]"
