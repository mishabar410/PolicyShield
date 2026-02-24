# 531 — Full ENV Config (12-factor)

## Goal

Complete the `POLICYSHIELD_*` environment variable mapping for all configuration options.

## Context

- Some config options only work via `policyshield.yaml`
- Docker/K8s deployments need full env var support
- 12-factor requires config from environment

## Code

### Modify: `policyshield/config/settings.py`

Ensure ALL settings have `POLICYSHIELD_*` env var fallbacks:

```python
@dataclass
class ShieldConfig:
    rules_path: str = field(default_factory=lambda: os.environ.get("POLICYSHIELD_RULES", "policies/rules.yaml"))
    mode: str = field(default_factory=lambda: os.environ.get("POLICYSHIELD_MODE", "enforce"))
    fail_open: bool = field(default_factory=lambda: os.environ.get("POLICYSHIELD_FAIL_OPEN", "").lower() == "true")
    approval_timeout: float = field(default_factory=lambda: float(os.environ.get("POLICYSHIELD_APPROVAL_TIMEOUT", "60")))
    trace_dir: str = field(default_factory=lambda: os.environ.get("POLICYSHIELD_TRACE_DIR", "./traces"))
    trace_privacy: bool = field(default_factory=lambda: os.environ.get("POLICYSHIELD_TRACE_PRIVACY", "").lower() == "true")
    log_format: str = field(default_factory=lambda: os.environ.get("POLICYSHIELD_LOG_FORMAT", "text"))
    log_level: str = field(default_factory=lambda: os.environ.get("POLICYSHIELD_LOG_LEVEL", "INFO"))
    max_request_size: int = field(default_factory=lambda: int(os.environ.get("POLICYSHIELD_MAX_REQUEST_SIZE", "1048576")))
    request_timeout: float = field(default_factory=lambda: float(os.environ.get("POLICYSHIELD_REQUEST_TIMEOUT", "30")))
    admin_token: str | None = field(default_factory=lambda: os.environ.get("POLICYSHIELD_ADMIN_TOKEN"))
    api_token: str | None = field(default_factory=lambda: os.environ.get("POLICYSHIELD_API_TOKEN"))
```

### Add: `docs/configuration.md`

Document all env vars with descriptions, defaults, and examples.

### Modify: `policyshield doctor`

Show env var status in health check output.

## Tests

- Test each env var is read correctly
- Test env var overrides YAML config
- Test `policyshield config show` displays resolved values

## Self-check

```bash
POLICYSHIELD_MODE=audit POLICYSHIELD_FAIL_OPEN=true policyshield config show
pytest tests/test_config.py -v
```

## Commit

```
feat(config): complete POLICYSHIELD_* env var mapping (12-factor)
```
