# Prompt 333 — Config Validation on Startup

## Цель

Валидировать все env и YAML конфиги при старте: обнаружить невалидные значения **до** первого запроса.

## Контекст

- Невалидный `POLICYSHIELD_MAX_CONCURRENT_CHECKS=abc` → crash при первом запросе, не при старте
- YAML rules с опечаткой в `verdict: BLOK` → принимается, ломается в runtime
- Нужно: startup validation, fail-fast с понятной ошибкой

## Что сделать

### 1. Создать `config/validator.py`

```python
"""Validate all configuration at startup."""
import os
import logging

logger = logging.getLogger(__name__)

class ConfigError(Exception):
    """Raised when configuration is invalid."""
    pass

def validate_env_config() -> dict[str, str]:
    """Validate environment-based configuration. Returns validated config dict."""
    errors = []

    # Numeric env vars
    for var, default in [
        ("POLICYSHIELD_MAX_CONCURRENT_CHECKS", "100"),
        ("POLICYSHIELD_REQUEST_TIMEOUT", "30"),
        ("POLICYSHIELD_MAX_REQUEST_SIZE", "1048576"),
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
```

### 2. Вызвать при старте сервера

```python
# cli.py или app.py lifespan:
from policyshield.config.validator import validate_env_config, ConfigError

try:
    config = validate_env_config()
except ConfigError as e:
    logger.error(str(e))
    sys.exit(1)
```

## Тесты

```python
class TestConfigValidation:
    def test_valid_config_passes(self, monkeypatch):
        from policyshield.config.validator import validate_env_config
        monkeypatch.setenv("POLICYSHIELD_MAX_CONCURRENT_CHECKS", "50")
        validate_env_config()  # Should not raise

    def test_invalid_number_fails(self, monkeypatch):
        from policyshield.config.validator import validate_env_config, ConfigError
        monkeypatch.setenv("POLICYSHIELD_MAX_CONCURRENT_CHECKS", "abc")
        with pytest.raises(ConfigError, match="not a valid number"):
            validate_env_config()

    def test_negative_number_fails(self, monkeypatch):
        from policyshield.config.validator import validate_env_config, ConfigError
        monkeypatch.setenv("POLICYSHIELD_REQUEST_TIMEOUT", "-5")
        with pytest.raises(ConfigError, match="must be positive"):
            validate_env_config()

    def test_invalid_fail_mode(self, monkeypatch):
        from policyshield.config.validator import validate_env_config, ConfigError
        monkeypatch.setenv("POLICYSHIELD_FAIL_MODE", "maybe")
        with pytest.raises(ConfigError, match="must be 'open' or 'closed'"):
            validate_env_config()
```

## Самопроверка

```bash
pytest tests/test_lifecycle.py::TestConfigValidation -v
pytest tests/ -q
```

## Коммит

```
feat(config): add startup configuration validation with fail-fast errors
```
