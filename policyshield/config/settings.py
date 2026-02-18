"""Centralized configuration from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class PolicyShieldSettings:
    """All PolicyShield configuration accessible from environment variables."""

    # Server
    host: str = field(default_factory=lambda: os.environ.get("POLICYSHIELD_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.environ.get("POLICYSHIELD_PORT", "8000")))
    # Auth
    api_token: str | None = field(default_factory=lambda: os.environ.get("POLICYSHIELD_API_TOKEN"))
    admin_token: str | None = field(default_factory=lambda: os.environ.get("POLICYSHIELD_ADMIN_TOKEN"))
    # Limits
    max_concurrent: int = field(
        default_factory=lambda: int(os.environ.get("POLICYSHIELD_MAX_CONCURRENT_CHECKS", "100"))
    )
    max_request_size: int = field(
        default_factory=lambda: int(os.environ.get("POLICYSHIELD_MAX_REQUEST_SIZE", "1048576"))
    )
    request_timeout: float = field(default_factory=lambda: float(os.environ.get("POLICYSHIELD_REQUEST_TIMEOUT", "30")))
    engine_timeout: float = field(default_factory=lambda: float(os.environ.get("POLICYSHIELD_ENGINE_TIMEOUT", "5")))
    # Behavior
    fail_mode: str = field(default_factory=lambda: os.environ.get("POLICYSHIELD_FAIL_MODE", "closed"))
    debug: bool = field(default_factory=lambda: os.environ.get("POLICYSHIELD_DEBUG", "").lower() in ("1", "true"))
    # Logging
    log_level: str = field(default_factory=lambda: os.environ.get("POLICYSHIELD_LOG_LEVEL", "INFO"))
    log_format: str = field(default_factory=lambda: os.environ.get("POLICYSHIELD_LOG_FORMAT", "text"))
    # CORS
    cors_origins: list[str] = field(
        default_factory=lambda: [
            o.strip() for o in os.environ.get("POLICYSHIELD_CORS_ORIGINS", "").split(",") if o.strip()
        ]
    )


def get_settings() -> PolicyShieldSettings:
    """Create settings from current environment."""
    return PolicyShieldSettings()
