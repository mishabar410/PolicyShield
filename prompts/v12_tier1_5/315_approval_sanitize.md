# Prompt 315 — Args Sanitization in Approval Flow

## Цель

Санитизировать args перед отправкой в Telegram / listing в pending-approvals, чтобы PII/секреты не утекали через канал согласования.

## Контекст

- `approval/telegram.py` — отправляет `args` открытым текстом в Telegram
- `server/app.py` — `/pending-approvals` отдаёт `args` как есть
- Если args содержит пароль/API key → утечка через Telegram и API

## Что сделать

### 1. Утилита санитизации

```python
# approval/sanitizer.py
"""Sanitize args before exposing in approval channels."""

import re

_SECRET_PATTERNS = [
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}", re.I), "[REDACTED_AWS_KEY]"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"(?:password|passwd|pwd|secret|token)\s*[:=]\s*\S+", re.I), "[REDACTED]"),
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
```

### 2. Использовать в Telegram

```python
# approval/telegram.py — перед отправкой:
from policyshield.approval.sanitizer import sanitize_args

safe_args = sanitize_args(request.args)
# Использовать safe_args в форматировании сообщения
```

### 3. Использовать в pending-approvals endpoint

```python
# server/app.py — в pending_approvals():
from policyshield.approval.sanitizer import sanitize_args

items = [
    PendingApprovalItem(
        ...,
        args=sanitize_args(req.args),
    )
    for req in pending
]
```

## Тесты

```python
class TestArgsSanitization:
    def test_aws_key_redacted(self):
        from policyshield.approval.sanitizer import sanitize_args
        result = sanitize_args({"key": "AKIAIOSFODNN7EXAMPLE"})
        assert "AKIA" not in result["key"]
        assert "REDACTED" in result["key"]

    def test_password_redacted(self):
        result = sanitize_args({"config": "password=s3cret123"})
        assert "s3cret" not in result["config"]

    def test_long_value_truncated(self):
        result = sanitize_args({"data": "x" * 500})
        assert len(result["data"]) < 300
        assert "truncated" in result["data"]

    def test_safe_args_unchanged(self):
        result = sanitize_args({"name": "hello", "count": "5"})
        assert result["name"] == "hello"
        assert result["count"] == "5"
```

## Самопроверка

```bash
pytest tests/test_approval_hardening.py::TestArgsSanitization -v
pytest tests/ -q
```

## Коммит

```
feat(approval): sanitize args before exposing in Telegram/API
```
