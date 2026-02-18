# Prompt 339 — Structured JSON Logging

## Цель

Добавить JSON-формат логов для production (parseable by ELK/Datadog), toggle через `POLICYSHIELD_LOG_FORMAT=json`.

## Контекст

- Сейчас `logging.basicConfig()` → plain text → непарсируемый в production
- Нужно: `POLICYSHIELD_LOG_FORMAT=json` → каждая строка = JSON с `timestamp`, `level`, `logger`, `message`
- Default: `text` (human-readable для dev)

## Что сделать

### 1. JSON formatter

```python
# logging_config.py
import json
import logging
from datetime import datetime, timezone

class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)
```

### 2. Инициализация

```python
# logging_config.py
import os

def configure_logging():
    log_format = os.environ.get("POLICYSHIELD_LOG_FORMAT", "text").lower()
    log_level = os.environ.get("POLICYSHIELD_LOG_LEVEL", "INFO").upper()

    root = logging.getLogger()
    root.setLevel(log_level)

    handler = logging.StreamHandler()
    if log_format == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
    root.handlers = [handler]
```

### 3. Вызвать при старте

```python
# cli.py / app.py:
from policyshield.logging_config import configure_logging
configure_logging()
```

## Тесты

```python
class TestStructuredLogging:
    def test_json_format(self, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_LOG_FORMAT", "json")
        from policyshield.logging_config import configure_logging, JSONFormatter
        configure_logging()
        import logging
        handler = logging.getLogger().handlers[0]
        assert isinstance(handler.formatter, JSONFormatter)

    def test_json_output_parseable(self):
        from policyshield.logging_config import JSONFormatter
        import logging, json
        formatter = JSONFormatter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "hello", (), None)
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["message"] == "hello"
        assert parsed["level"] == "INFO"

    def test_text_format_default(self, monkeypatch):
        monkeypatch.delenv("POLICYSHIELD_LOG_FORMAT", raising=False)
        from policyshield.logging_config import configure_logging
        configure_logging()
        # Default should be text formatter
```

## Самопроверка

```bash
pytest tests/test_lifecycle.py::TestStructuredLogging -v
pytest tests/ -q
```

## Коммит

```
feat: add structured JSON logging (POLICYSHIELD_LOG_FORMAT=json|text)
```
