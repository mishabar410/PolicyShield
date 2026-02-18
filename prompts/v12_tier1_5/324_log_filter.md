# Prompt 324 — Sensitive Data in Logs

## Цель

Не логировать PII, секреты и полные args в INFO-level логах — только в DEBUG.

## Контекст

- Сейчас `logger.info(...)` может содержать полные args с паролями/ключами
- В production логи отправляются в centralized logging (ELK, Datadog) → PII утечка
- Нужно: INFO → summary без args; DEBUG → полные args (только dev)

## Что сделать

### 1. Обёртка для безопасного логирования

```python
# server/log_utils.py
def safe_args_summary(args: dict, max_keys: int = 5) -> str:
    """Return keys-only summary of args for safe logging."""
    keys = list(args.keys())[:max_keys]
    suffix = f" +{len(args) - max_keys} more" if len(args) > max_keys else ""
    return f"keys=[{', '.join(keys)}{suffix}]"
```

### 2. Обновить логи в `app.py` и `base_engine.py`

```python
# В check handler:
logger.info("Check tool=%s %s → %s (%.1fms)",
    req.tool_name, safe_args_summary(req.args), result.verdict.value, latency_ms)
logger.debug("Full args: %s", req.args)  # Only in debug
```

### 3. Обновить trace recorder

```python
# trace/recorder.py — privacy mode:
if self._privacy_mode:
    entry.pop("args", None)  # Don't write args to trace file
```

## Тесты

```python
class TestSensitiveDataInLogs:
    def test_safe_args_summary_hides_values(self):
        from policyshield.server.log_utils import safe_args_summary
        result = safe_args_summary({"password": "secret123", "user": "admin"})
        assert "secret123" not in result
        assert "password" in result  # Key name is OK

    def test_safe_args_summary_truncates(self):
        from policyshield.server.log_utils import safe_args_summary
        args = {f"key{i}": f"val{i}" for i in range(20)}
        result = safe_args_summary(args, max_keys=3)
        assert "+17 more" in result

    def test_info_log_excludes_values(self, caplog):
        # Need integration test: check that INFO logs don't contain arg values
        pass
```

## Самопроверка

```bash
pytest tests/test_security_data.py::TestSensitiveDataInLogs -v
pytest tests/ -q
```

## Коммит

```
feat(server): hide arg values from INFO logs (keys-only summary)
```
