"""Validate all configuration at startup."""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when configuration is invalid."""


def validate_env_config() -> dict[str, str]:
    """Validate environment-based configuration. Returns validated config dict."""
    errors: list[str] = []

    # Numeric env vars
    for var, default in [
        ("POLICYSHIELD_MAX_CONCURRENT_CHECKS", "100"),
        ("POLICYSHIELD_REQUEST_TIMEOUT", "30"),
        ("POLICYSHIELD_MAX_REQUEST_SIZE", "1048576"),
        ("POLICYSHIELD_APPROVAL_POLL_TIMEOUT", "30"),
        ("POLICYSHIELD_ENGINE_TIMEOUT", "5"),
    ]:
        raw = os.environ.get(var, default)
        try:
            val = float(raw) if "." in raw else int(raw)
            if val <= 0:
                errors.append(f"{var}={raw} must be positive")
        except ValueError:
            errors.append(f"{var}={raw} is not a valid number")

    # Enum-like env vars
    fail_mode = os.environ.get("POLICYSHIELD_FAIL_MODE", "closed").lower()
    if fail_mode not in ("open", "closed"):
        errors.append(f"POLICYSHIELD_FAIL_MODE={fail_mode} must be 'open' or 'closed'")

    log_format = os.environ.get("POLICYSHIELD_LOG_FORMAT", "text").lower()
    if log_format not in ("text", "json"):
        errors.append(f"POLICYSHIELD_LOG_FORMAT={log_format} must be 'text' or 'json'")

    if errors:
        raise ConfigError("Configuration errors:\n" + "\n".join(f"  - {e}" for e in errors))

    return {"fail_mode": fail_mode, "log_format": log_format}
