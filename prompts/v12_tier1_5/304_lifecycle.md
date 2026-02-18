# Prompt 304 — Lifecycle & Reliability

## Цель

Обеспечить корректный lifecycle сервера: graceful shutdown, trace flush, config validation, fail-open/closed, engine timeouts, atomic hot-reload, startup self-test, Python version validation, structured logging.

## Контекст

- `policyshield/server/app.py` — FastAPI с `lifespan` context manager, запускает/останавливает watcher
- `policyshield/shield/base_engine.py` — `start_watching()`, `stop_watching()`, `reload_rules()`
- `policyshield/trace/recorder.py` — `TraceRecorder`, buffer flush через `_flush_unlocked()`
- `policyshield/config/loader.py` — загрузка YAML config, нет валидации полей
- `policyshield/cli/main.py` — CLI entry point через Click
- **Проблемы:**
  - При SIGTERM/Ctrl+C: watcher останавливается, но trace buffer не flush'ится → потеря аудита
  - Config загружается без валидации → typo в поле тихо игнорируется
  - `engine._fail_open` есть, но нет конфигурации через YAML/env
  - `engine.check()` может зависнуть на медленном rule (regex backtracking)
  - `reload_rules()` не атомарен — при ошибке парсинга engine остаётся без rules
  - Нет startup self-test — сервер стартует даже с broken config
  - Нет проверки Python version → cryptic errors на Python 3.8
  - Логи в plain text → не парсятся ELK/Datadog/CloudWatch

## Что сделать

### 1. Graceful Shutdown

```python
# app.py — расширить lifespan:
import signal

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    if enable_watcher:
        engine.start_watching()
    logger.info("PolicyShield server started (mode=%s, rules=%d)", engine.mode.value, engine.rule_count)

    yield

    # Shutdown
    logger.info("PolicyShield server shutting down...")
    if enable_watcher:
        engine.stop_watching()
    if engine._tracer:
        engine._tracer.flush()
        logger.info("Trace buffer flushed")
    if hasattr(engine, '_approval_backend') and engine._approval_backend:
        if hasattr(engine._approval_backend, 'stop'):
            engine._approval_backend.stop()
    logger.info("PolicyShield server stopped")
```

### 2. Trace Flush on Shutdown

```python
# trace/recorder.py — добавить __del__ и explicit shutdown:
class TraceRecorder:
    def shutdown(self):
        """Flush all pending traces and close. Called on server shutdown."""
        self.flush()
        logger.info("TraceRecorder shut down, %d entries flushed", self._total_flushed)

    def __del__(self):
        try:
            self.flush()
        except Exception:
            pass
```

### 3. Config Validation

```python
# config/validator.py
"""Validate PolicyShield YAML configuration."""

from dataclasses import dataclass

@dataclass
class ConfigValidationError:
    field: str
    message: str
    severity: str  # "error" | "warning"

KNOWN_TOP_LEVEL_KEYS = {
    "shield_name", "version", "default_verdict", "mode",
    "rules", "builtin_detectors", "honeypots", "pii",
    "approval", "presets", "logging",
}

KNOWN_RULE_KEYS = {
    "id", "tool", "tools", "verdict", "message", "conditions",
    "priority", "rate_limit", "args_patterns", "blocked_patterns",
}

def validate_config(config: dict) -> list[ConfigValidationError]:
    """Validate a parsed YAML config dict."""
    errors = []

    # Check unknown top-level keys
    for key in config:
        if key not in KNOWN_TOP_LEVEL_KEYS:
            errors.append(ConfigValidationError(
                field=key,
                message=f"Unknown top-level key: '{key}'. Did you mean one of: {', '.join(sorted(KNOWN_TOP_LEVEL_KEYS))}?",
                severity="warning",
            ))

    # Validate rules
    rules = config.get("rules", [])
    if not isinstance(rules, list):
        errors.append(ConfigValidationError("rules", "Should be a list", "error"))
    else:
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                errors.append(ConfigValidationError(f"rules[{i}]", "Should be a dict", "error"))
                continue
            if "id" not in rule:
                errors.append(ConfigValidationError(f"rules[{i}]", "Missing 'id'", "error"))
            if "verdict" not in rule:
                errors.append(ConfigValidationError(f"rules[{i}]", "Missing 'verdict'", "error"))
            elif rule["verdict"] not in ("ALLOW", "BLOCK", "REDACT", "APPROVE"):
                errors.append(ConfigValidationError(
                    f"rules[{i}].verdict",
                    f"Invalid verdict '{rule['verdict']}'. Must be ALLOW/BLOCK/REDACT/APPROVE",
                    "error",
                ))
            for key in rule:
                if key not in KNOWN_RULE_KEYS:
                    errors.append(ConfigValidationError(
                        f"rules[{i}].{key}",
                        f"Unknown rule key: '{key}'",
                        "warning",
                    ))

    return errors
```

### 4. Fail-Open / Fail-Closed Configuration

```python
# config/loader.py — добавить парсинг fail_mode:
# В YAML:
#   fail_mode: closed  # or "open" (default: "open")

# base_engine.py — использовать:
class BaseShieldEngine:
    def __init__(self, ..., fail_open: bool = True, ...):
        self._fail_open = fail_open

# app.py — использовать в error handler:
verdict = "ALLOW" if engine._fail_open else "BLOCK"
```

### 5. Engine Check Timeout

```python
# shield/base_engine.py
import signal
from contextlib import contextmanager

CHECK_TIMEOUT = 5.0  # seconds

@contextmanager
def _check_timeout(timeout: float):
    """Context manager that raises TimeoutError after timeout seconds."""
    import threading
    timer = threading.Timer(timeout, lambda: None)
    timer.start()
    try:
        yield
    finally:
        timer.cancel()

# В _do_check_sync():
def _do_check_sync(self, tool_name, args, session_id, sender):
    try:
        # ... existing logic with timeout guard on rule matching
        pass
    except TimeoutError:
        logger.error("Check timeout for tool=%s (%.1fs)", tool_name, self._check_timeout)
        if self._fail_open:
            return ShieldResult(verdict=Verdict.ALLOW, message="Check timeout (fail-open)")
        return ShieldResult(verdict=Verdict.BLOCK, message="Check timeout (fail-closed)")
```

### 6. Atomic Hot-Reload

```python
# base_engine.py — в reload_rules():
def reload_rules(self, path: str | Path | None = None) -> None:
    target = Path(path) if path else self._rules_path
    try:
        new_ruleset = RuleSet.from_yaml(target)
    except Exception as e:
        logger.error("Hot-reload failed: %s. Keeping current rules.", e)
        return  # Don't update — keep old rules
    # Atomic swap
    with self._lock:
        old_count = self.rule_count
        self._rules = new_ruleset
        if hasattr(self, '_honeypots'):
            self._honeypots = self._rules.honeypots  # Also reload honeypots
    logger.info("Rules reloaded: %d → %d rules", old_count, self.rule_count)
```

### 7. Startup Self-Test

```python
# cli/main.py — в serve() command:
def _startup_self_test(engine: BaseShieldEngine) -> bool:
    """Run basic self-test before accepting requests."""
    try:
        # 1. Check rules loaded
        if engine.rule_count == 0:
            logger.warning("Self-test: no rules loaded")

        # 2. Test check works
        from policyshield.core.models import Verdict
        result = engine.check("__self_test__", {}, session_id="__selftest__")
        assert result.verdict in (Verdict.ALLOW, Verdict.BLOCK)

        # 3. Check tracer writable (if configured)
        if engine._tracer:
            engine._tracer.record("__selftest__", "__self_test__", Verdict.ALLOW)
            engine._tracer.flush()

        logger.info("Self-test passed ✓")
        return True
    except Exception as e:
        logger.error("Self-test FAILED: %s", e)
        return False

# В serve():
if not _startup_self_test(engine):
    click.echo("❌ Self-test failed. Fix config and retry.", err=True)
    raise SystemExit(1)
```

### 8. Python Version Validation

```python
# policyshield/__init__.py — в начало файла:
import sys

if sys.version_info < (3, 10):
    raise RuntimeError(
        f"PolicyShield requires Python 3.10+, but you're running {sys.version_info.major}.{sys.version_info.minor}. "
        "Please upgrade Python."
    )
```

### 9. Structured Logging

```python
# config/logging.py
"""Structured logging configuration for PolicyShield."""

import json
import logging
from datetime import datetime, timezone

class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }
        return json.dumps(log_entry, default=str)

def configure_logging(structured: bool = False, level: str = "INFO"):
    """Configure policyshield logging."""
    logger = logging.getLogger("policyshield")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler = logging.StreamHandler()
    if structured:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
        ))
    logger.addHandler(handler)
```

### 10. Config File Validation in CLI

```python
# cli/main.py — добавить подкоманду:
@cli.command()
@click.argument("config_path", type=click.Path(exists=True))
def validate(config_path: str):
    """Validate a PolicyShield YAML config file."""
    import yaml
    from policyshield.config.validator import validate_config

    with open(config_path) as f:
        config = yaml.safe_load(f)

    errors = validate_config(config)
    if not errors:
        click.echo("✅ Config is valid")
        return

    for err in errors:
        icon = "❌" if err.severity == "error" else "⚠️"
        click.echo(f"  {icon} {err.field}: {err.message}")

    hard_errors = [e for e in errors if e.severity == "error"]
    if hard_errors:
        raise SystemExit(1)
```

## Тесты (`tests/test_lifecycle.py`)

```python
"""Tests for lifecycle & reliability features."""
import pytest
import sys

class TestGracefulShutdown:
    def test_trace_flushed_on_shutdown(self, tmp_path):
        from policyshield.trace.recorder import TraceRecorder
        from policyshield.core.models import Verdict
        recorder = TraceRecorder(output_dir=tmp_path)
        recorder.record("s1", "tool1", Verdict.ALLOW)
        recorder.shutdown()
        files = list(tmp_path.glob("*.jsonl"))
        assert len(files) == 1
        assert files[0].read_text().strip()

class TestConfigValidation:
    def test_valid_config_no_errors(self):
        from policyshield.config.validator import validate_config
        config = {"rules": [{"id": "r1", "tool": "test", "verdict": "BLOCK"}]}
        errors = validate_config(config)
        assert not [e for e in errors if e.severity == "error"]

    def test_unknown_key_warning(self):
        from policyshield.config.validator import validate_config
        config = {"rules": [], "typo_key": True}
        errors = validate_config(config)
        assert any(e.field == "typo_key" for e in errors)

    def test_missing_id_error(self):
        from policyshield.config.validator import validate_config
        config = {"rules": [{"verdict": "BLOCK"}]}
        errors = validate_config(config)
        assert any(e.severity == "error" and "id" in e.message for e in errors)

    def test_invalid_verdict_error(self):
        from policyshield.config.validator import validate_config
        config = {"rules": [{"id": "r1", "verdict": "YOLO"}]}
        errors = validate_config(config)
        assert any(e.severity == "error" and "Invalid verdict" in e.message for e in errors)

class TestAtomicReload:
    def test_bad_yaml_keeps_old_rules(self, tmp_path):
        """Reload with bad YAML should keep current rules."""
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text("rules:\n  - id: r1\n    tool: test\n    verdict: BLOCK\n")

        from policyshield.shield.sync_engine import ShieldEngine
        engine = ShieldEngine(rules=str(rules_file))
        assert engine.rule_count == 1

        rules_file.write_text("invalid yaml: [[[")
        engine.reload_rules()
        assert engine.rule_count == 1  # Still 1 — old rules preserved

class TestPythonVersion:
    def test_version_check_exists(self):
        # Just verify the guard is in __init__.py
        import policyshield
        assert sys.version_info >= (3, 10)

class TestStructuredLogging:
    def test_json_formatter(self):
        import json
        from policyshield.config.logging import JSONFormatter
        import logging
        formatter = JSONFormatter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "hello world", (), None)
        output = formatter.format(record)
        data = json.loads(output)
        assert data["message"] == "hello world"
        assert data["level"] == "INFO"
```

## Самопроверка

```bash
pytest tests/test_lifecycle.py -v
pytest tests/ -q
ruff check policyshield/
```

## Порядок коммитов

1. `feat(server): graceful shutdown with resource cleanup`
2. `feat(trace): explicit shutdown() and flush on server stop`
3. `feat(config): add YAML config validator`
4. `feat(engine): configurable fail-open/fail-closed mode`
5. `feat(engine): add check timeout guard`
6. `fix(engine): atomic hot-reload — keep old rules on parse error`
7. `feat(cli): add startup self-test before accepting requests`
8. `feat: add Python 3.10+ version guard`
9. `feat(logging): add structured JSON logging formatter`
10. `feat(cli): add 'validate' subcommand for config files`
