"""Unified config loader for PolicyShield.

Loads ``policyshield.yaml``, expands ``${VAR}`` env-var references,
validates, and can build fully-configured engine instances.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from policyshield.core.models import ShieldMode

_ENV_RE = re.compile(r"\$\{([^}:]+)(?::-([^}]*))?\}")
_SCHEMA_PATH = Path(__file__).parent / "schema.json"


# ────────────────────────────────────────────────────────────────────
# Config dataclass
# ────────────────────────────────────────────────────────────────────


@dataclass
class PolicyShieldConfig:
    """Resolved configuration for the shield engine."""

    mode: ShieldMode = ShieldMode.ENFORCE
    fail_open: bool = True

    # rules
    rules_path: str = "./policies/"
    watch: bool = False
    watch_interval: float = 2.0

    # pii
    pii_enabled: bool = True

    # sanitizer
    sanitizer_enabled: bool = False
    sanitizer_max_string_length: int = 10_000
    sanitizer_blocked_patterns: list[str] = field(default_factory=list)
    sanitizer_builtin_detectors: list[str] = field(default_factory=list)

    # trace
    trace_enabled: bool = True
    trace_output_dir: str = "./traces/"
    trace_batch_size: int = 100
    trace_privacy_mode: bool = False

    # otel
    otel_enabled: bool = False
    otel_service_name: str = "policyshield"
    otel_endpoint: str | None = None

    # approval
    approval_backend: str = "inmemory"

    # rate limits (YAML list passed to RateLimiter.from_yaml_dict)
    rate_limits: list[dict] = field(default_factory=list)


# ────────────────────────────────────────────────────────────────────
# Loaders
# ────────────────────────────────────────────────────────────────────


def _expand_env(value: str) -> str:
    """Replace ``${VAR}`` and ``${VAR:-default}`` with env values."""

    def _sub(m: re.Match) -> str:
        var_name = m.group(1)
        default = m.group(2)  # None if no :-default provided
        env_val = os.environ.get(var_name)
        if env_val is not None:
            return env_val
        if default is not None:
            return default
        return m.group(0)  # Keep original ${VAR} if not found and no default

    return _ENV_RE.sub(_sub, value)


def _expand_env_recursive(obj):  # noqa: ANN001, ANN202
    if isinstance(obj, str):
        return _expand_env(obj)
    if isinstance(obj, dict):
        return {k: _expand_env_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_env_recursive(i) for i in obj]
    return obj


def load_config(
    path: str | Path | None = None,
    env_prefix: str = "POLICYSHIELD_",
) -> PolicyShieldConfig:
    """Load config from YAML with env-var expansion.

    Search order:
    1. *path* argument
    2. ``POLICYSHIELD_CONFIG`` env var
    3. ``./policyshield.yaml``
    4. Defaults
    """
    # Resolve path
    if path is None:
        path = os.environ.get("POLICYSHIELD_CONFIG")
    if path is None:
        candidate = Path("policyshield.yaml")
        if candidate.exists():
            path = candidate

    data: dict = {}
    if path is not None:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            data = raw.get("policyshield", raw)
        data = _expand_env_recursive(data)

    cfg = _build_config(data)

    # Env-var overrides (e.g. POLICYSHIELD_MODE=AUDIT)
    env_mode = os.environ.get(f"{env_prefix}MODE")
    if env_mode:
        cfg.mode = ShieldMode(env_mode.upper())

    env_fp = os.environ.get(f"{env_prefix}FAIL_OPEN")
    if env_fp is not None:
        cfg.fail_open = env_fp.lower() in ("1", "true", "yes")

    return cfg


def _get_section(data: dict, key: str, fallback: dict | None = None) -> dict:
    """Return *data[key]* if it's a dict, otherwise *fallback* (empty dict)."""
    v = data.get(key, fallback or {})
    return v if isinstance(v, dict) else {}


def _build_config(data: dict) -> PolicyShieldConfig:
    """Map raw dict to :class:`PolicyShieldConfig`."""
    mode_str = data.get("mode", "ENFORCE")
    try:
        mode = ShieldMode(mode_str.upper()) if isinstance(mode_str, str) else ShieldMode(mode_str)
    except ValueError:
        raise ValueError(f"Invalid mode: {mode_str!r}. Must be ENFORCE, AUDIT or DISABLED.")

    rules = data.get("rules", {})
    if isinstance(rules, str):
        rules = {"path": rules}

    pii = _get_section(data, "pii")
    san = _get_section(data, "sanitizer")
    trace = _get_section(data, "trace")
    otel = _get_section(data, "otel")
    approval = _get_section(data, "approval")

    # rate_limits is a list, not a section dict
    rate_limits_raw = data.get("rate_limits", [])
    if not isinstance(rate_limits_raw, list):
        rate_limits_raw = []

    return PolicyShieldConfig(
        mode=mode,
        fail_open=data.get("fail_open", True),
        rules_path=rules.get("path", "./policies/"),
        watch=rules.get("watch", False),
        watch_interval=float(rules.get("watch_interval", 2.0)),
        pii_enabled=pii.get("enabled", True),
        sanitizer_enabled=san.get("enabled", False),
        sanitizer_max_string_length=san.get("max_string_length", 10_000),
        sanitizer_blocked_patterns=san.get("blocked_patterns", []),
        sanitizer_builtin_detectors=san.get("builtin_detectors", []),
        trace_enabled=trace.get("enabled", True),
        trace_output_dir=trace.get("output_dir", "./traces/"),
        trace_batch_size=int(trace.get("batch_size", 100)),
        trace_privacy_mode=trace.get("privacy_mode", False),
        otel_enabled=otel.get("enabled", False),
        otel_service_name=otel.get("service_name", "policyshield"),
        otel_endpoint=otel.get("endpoint"),
        approval_backend=approval.get("backend", "inmemory"),
        rate_limits=rate_limits_raw,
    )


# ────────────────────────────────────────────────────────────────────
# Engine builders
# ────────────────────────────────────────────────────────────────────


def build_engine_from_config(config: PolicyShieldConfig):  # noqa: ANN201
    """Create a fully configured :class:`ShieldEngine`."""
    from policyshield.shield.engine import ShieldEngine
    from policyshield.shield.pii import PIIDetector
    from policyshield.shield.rate_limiter import RateLimiter
    from policyshield.shield.sanitizer import InputSanitizer, SanitizerConfig
    from policyshield.trace.recorder import TraceRecorder

    sanitizer = None
    if config.sanitizer_enabled:
        sanitizer = InputSanitizer(
            SanitizerConfig(
                max_string_length=config.sanitizer_max_string_length,
                blocked_patterns=config.sanitizer_blocked_patterns,
                builtin_detectors=config.sanitizer_builtin_detectors,
            )
        )

    tracer = None
    if config.trace_enabled:
        tracer = TraceRecorder(
            output_dir=config.trace_output_dir,
            batch_size=config.trace_batch_size,
            privacy_mode=config.trace_privacy_mode,
        )

    pii = PIIDetector() if config.pii_enabled else None

    rate_limiter = RateLimiter.from_yaml_dict(config.rate_limits) if config.rate_limits else None

    return ShieldEngine(
        rules=config.rules_path,
        mode=config.mode,
        pii_detector=pii,
        trace_recorder=tracer,
        fail_open=config.fail_open,
        sanitizer=sanitizer,
        rate_limiter=rate_limiter,
    )


def build_async_engine_from_config(config: PolicyShieldConfig):  # noqa: ANN201
    """Create a fully configured :class:`AsyncShieldEngine`."""
    from policyshield.shield.async_engine import AsyncShieldEngine
    from policyshield.shield.pii import PIIDetector
    from policyshield.shield.rate_limiter import RateLimiter
    from policyshield.shield.sanitizer import InputSanitizer, SanitizerConfig
    from policyshield.trace.recorder import TraceRecorder

    sanitizer = None
    if config.sanitizer_enabled:
        sanitizer = InputSanitizer(
            SanitizerConfig(
                max_string_length=config.sanitizer_max_string_length,
                blocked_patterns=config.sanitizer_blocked_patterns,
                builtin_detectors=config.sanitizer_builtin_detectors,
            )
        )

    tracer = None
    if config.trace_enabled:
        tracer = TraceRecorder(
            output_dir=config.trace_output_dir,
            batch_size=config.trace_batch_size,
            privacy_mode=config.trace_privacy_mode,
        )

    pii = PIIDetector() if config.pii_enabled else None

    rate_limiter = RateLimiter.from_yaml_dict(config.rate_limits) if config.rate_limits else None

    return AsyncShieldEngine(
        rules=config.rules_path,
        mode=config.mode,
        pii_detector=pii,
        trace_recorder=tracer,
        fail_open=config.fail_open,
        sanitizer=sanitizer,
        rate_limiter=rate_limiter,
    )


# ────────────────────────────────────────────────────────────────────
# Validation helpers
# ────────────────────────────────────────────────────────────────────


def validate_config_file(path: str | Path) -> list[str]:
    """Validate a config file against the JSON Schema.

    Returns a list of error messages (empty → valid).
    """
    path = Path(path)
    if not path.exists():
        return [f"File not found: {path}"]

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        return [f"Invalid YAML: {e}"]

    if not isinstance(raw, dict):
        return ["Config root must be a mapping"]

    data = raw.get("policyshield", raw)

    errors: list[str] = []
    mode = data.get("mode", "ENFORCE")
    if isinstance(mode, str) and mode.upper() not in ("ENFORCE", "AUDIT", "DISABLED"):
        errors.append(f"Invalid mode: {mode!r}")

    rules = data.get("rules", {})
    if isinstance(rules, dict):
        rp = rules.get("path")
        if rp is not None and not isinstance(rp, str):
            errors.append("rules.path must be a string")
    elif not isinstance(rules, str):
        errors.append("rules must be a string or mapping")

    return errors


def render_config(config: PolicyShieldConfig) -> str:
    """Render resolved config as YAML string."""
    d = {
        "policyshield": {
            "version": 1,
            "mode": config.mode.value,
            "fail_open": config.fail_open,
            "rules": {
                "path": config.rules_path,
                "watch": config.watch,
                "watch_interval": config.watch_interval,
            },
            "pii": {"enabled": config.pii_enabled},
            "sanitizer": {
                "enabled": config.sanitizer_enabled,
                "max_string_length": config.sanitizer_max_string_length,
                "blocked_patterns": config.sanitizer_blocked_patterns,
                "builtin_detectors": config.sanitizer_builtin_detectors,
            },
            "trace": {
                "enabled": config.trace_enabled,
                "output_dir": config.trace_output_dir,
                "batch_size": config.trace_batch_size,
                "privacy_mode": config.trace_privacy_mode,
            },
            "otel": {
                "enabled": config.otel_enabled,
                "service_name": config.otel_service_name,
                "endpoint": config.otel_endpoint,
            },
            "approval": {
                "backend": config.approval_backend,
            },
        }
    }
    return yaml.dump(d, default_flow_style=False, sort_keys=False)


def generate_default_config() -> str:
    """Generate default policyshield.yaml content."""
    return render_config(PolicyShieldConfig())


def load_schema() -> dict:
    """Load the JSON Schema for validation."""
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
