# Prompt 358 — Environment-based Full Configuration

## Цель

Позволить настроить всё через env vars для 12-factor app / Docker / K8s deployment.

## Контекст

- Ряд env vars уже введены в предыдущих промптах; нужно собрать в одном конфиг dataclass
- Нужна документация всех env vars + defaults + валидация

## Что сделать

### 1. Собрать `config/settings.py`

```python
# config/settings.py
"""Centralized configuration from environment variables."""
import os
from dataclasses import dataclass, field

@dataclass
class PolicyShieldSettings:
    # Server
    host: str = field(default_factory=lambda: os.environ.get("POLICYSHIELD_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.environ.get("POLICYSHIELD_PORT", "8000")))
    # Auth
    api_token: str | None = field(default_factory=lambda: os.environ.get("POLICYSHIELD_API_TOKEN"))
    admin_token: str | None = field(default_factory=lambda: os.environ.get("POLICYSHIELD_ADMIN_TOKEN"))
    # Limits
    max_concurrent: int = field(default_factory=lambda: int(os.environ.get("POLICYSHIELD_MAX_CONCURRENT_CHECKS", "100")))
    max_request_size: int = field(default_factory=lambda: int(os.environ.get("POLICYSHIELD_MAX_REQUEST_SIZE", "1048576")))
    request_timeout: float = field(default_factory=lambda: float(os.environ.get("POLICYSHIELD_REQUEST_TIMEOUT", "30")))
    engine_timeout: float = field(default_factory=lambda: float(os.environ.get("POLICYSHIELD_ENGINE_TIMEOUT", "5")))
    # Behavior
    fail_mode: str = field(default_factory=lambda: os.environ.get("POLICYSHIELD_FAIL_MODE", "closed"))
    debug: bool = field(default_factory=lambda: os.environ.get("POLICYSHIELD_DEBUG", "").lower() in ("1", "true"))
    # Logging
    log_level: str = field(default_factory=lambda: os.environ.get("POLICYSHIELD_LOG_LEVEL", "INFO"))
    log_format: str = field(default_factory=lambda: os.environ.get("POLICYSHIELD_LOG_FORMAT", "text"))
    # CORS
    cors_origins: list[str] = field(default_factory=lambda: [
        o.strip() for o in os.environ.get("POLICYSHIELD_CORS_ORIGINS", "").split(",") if o.strip()
    ])

def get_settings() -> PolicyShieldSettings:
    return PolicyShieldSettings()
```

### 2. Обновить `app.py` для использования centralized settings

## Тесты

```python
class TestSettings:
    def test_defaults(self):
        from policyshield.config.settings import PolicyShieldSettings
        s = PolicyShieldSettings()
        assert s.port == 8000
        assert s.fail_mode == "closed"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_PORT", "9090")
        s = PolicyShieldSettings()
        assert s.port == 9090
```

## Самопроверка

```bash
pytest tests/test_dx.py::TestSettings -v
pytest tests/ -q
```

## Коммит

```
feat(config): centralize env configuration in PolicyShieldSettings dataclass
```
