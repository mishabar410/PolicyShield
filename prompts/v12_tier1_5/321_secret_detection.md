# Prompt 321 — Secret Detection in Args

## Цель

Добавить проверку на секреты/credentials в `args` перед выполнением: если args содержит AWS ключ, API токен и т.д. → BLOCK.

## Контекст

- Существующие детекторы (`policyshield/detectors/builtin_detectors.py`) проверяют пути и SQL, но **не** секреты
- Если агент передаёт `args: {"api_key": "sk-12345..."}` в `send_email` → секрет утекает в email
- Нужно: `SecretDetector` как built-in детектор + интеграция с engine

## Что сделать

### 1. Добавить `SecretDetector` в `builtin_detectors.py`

```python
from policyshield.detectors.base import SecurityDetector, ThreatInfo
import re

class SecretDetector(SecurityDetector):
    name = "secret_detector"
    description = "Detects credentials and secrets in arguments"
    severity = "critical"

    _PATTERNS = [
        (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"), "AWS Access Key"),
        (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI API Key"),
        (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub PAT"),
        (re.compile(r"xox[bpoas]-[A-Za-z0-9\-]+"), "Slack Token"),
        (re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "Private Key"),
        (re.compile(r"(?:eyJ[A-Za-z0-9_-]{10,}\.){2}[A-Za-z0-9_-]+"), "JWT Token"),
    ]

    def scan_value(self, value: str) -> list[ThreatInfo]:
        threats = []
        for pattern, name in self._PATTERNS:
            if pattern.search(value):
                threats.append(ThreatInfo(
                    detector=self.name,
                    threat_type=name,
                    severity=self.severity,
                    detail=f"Detected {name} in argument value",
                ))
        return threats
```

### 2. Зарегистрировать в реестре

```python
# detectors/registry.py
from .builtin_detectors import SecretDetector
BUILTIN_DETECTORS.append(SecretDetector())
```

## Тесты

```python
class TestSecretDetection:
    def test_aws_key_detected(self):
        from policyshield.detectors.builtin_detectors import SecretDetector
        d = SecretDetector()
        threats = d.scan_value("my key is AKIAIOSFODNN7EXAMPLE")
        assert len(threats) > 0
        assert "AWS" in threats[0].threat_type

    def test_openai_key_detected(self):
        d = SecretDetector()
        threats = d.scan_value("token: sk-abcdefghij1234567890abcdefghij1234567890")
        assert len(threats) > 0

    def test_safe_value_no_threats(self):
        d = SecretDetector()
        threats = d.scan_value("Hello, world!")
        assert len(threats) == 0

    def test_jwt_detected(self):
        d = SecretDetector()
        threats = d.scan_value("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        assert len(threats) > 0
```

## Самопроверка

```bash
pytest tests/test_security_data.py::TestSecretDetection -v
pytest tests/ -q
```

## Коммит

```
feat(detectors): add SecretDetector for credentials in args (AWS, OpenAI, GitHub, JWT)
```
