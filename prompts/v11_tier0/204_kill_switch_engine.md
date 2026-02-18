# Prompt 204 — Kill Switch Engine

## Цель

Добавить механизм kill switch в `BaseShieldEngine` — возможность мгновенно блокировать **все** tool calls без перезапуска.

## Контекст

- Если пользователь обнаружил active exploit, нужен способ остановить **всё** одним вызовом
- Kill switch — атомарный boolean флаг в engine, проверяемый **первым** в `_do_check_sync`
- `kill()` включает blokировку, `resume()` выключает
- Когда killed: все вызовы возвращают `BLOCK` с `rule_id="__kill_switch__"`
- Thread-safe: используем `threading.Event` (атомарный, без lock)
- Kill switch не зависит от правил, режима (ENFORCE/AUDIT), sanitizer — это самый первый чек
- API: `engine.kill()`, `engine.resume()`, `engine.is_killed` property

## Что сделать

### 1. Обновить `BaseShieldEngine.__init__` в `policyshield/shield/base_engine.py`

Добавить:

```python
import threading

# В __init__:
self._killed = threading.Event()  # Not set = normal operation
```

### 2. Добавить методы `kill()`, `resume()`, `is_killed`

```python
def kill(self, reason: str = "Kill switch activated") -> None:
    """Activate kill switch — block ALL tool calls immediately.

    Args:
        reason: Human-readable reason for the kill switch activation.
    """
    self._kill_reason = reason
    self._killed.set()

def resume(self) -> None:
    """Deactivate kill switch — resume normal operation."""
    self._killed.clear()
    self._kill_reason = ""

@property
def is_killed(self) -> bool:
    """Whether kill switch is active."""
    return self._killed.is_set()
```

### 3. Обновить `_do_check_sync` — первая проверка

```python
def _do_check_sync(self, tool_name, args, session_id, sender):
    """Synchronous check logic: kill_switch → sanitize → rate-limit → taint → match → PII → verdict."""

    # Kill switch — absolute first check
    if self._killed.is_set():
        return ShieldResult(
            verdict=Verdict.BLOCK,
            rule_id="__kill_switch__",
            message=getattr(self, "_kill_reason", "Kill switch activated"),
        )

    # Sanitize args (existing)
    if self._sanitizer is not None:
        ...
```

### 4. Тесты

#### `tests/test_kill_switch.py`

```python
"""Tests for engine kill switch."""

import threading
import time

import pytest

from policyshield.core.parser import RuleSet
from policyshield.shield.engine import ShieldEngine


def _make_engine() -> ShieldEngine:
    """Engine with no rules, default allow."""
    return ShieldEngine(rules=RuleSet(rules=[], default_verdict="allow"))


class TestKillSwitch:
    def test_not_killed_by_default(self):
        engine = _make_engine()
        assert not engine.is_killed

    def test_kill_blocks_all(self):
        engine = _make_engine()
        engine.kill()
        result = engine.check("any_tool", {})
        assert result.verdict.value == "block"
        assert result.rule_id == "__kill_switch__"

    def test_kill_with_reason(self):
        engine = _make_engine()
        engine.kill(reason="Active exploit detected")
        result = engine.check("any_tool", {})
        assert "Active exploit" in result.message

    def test_resume_restores(self):
        engine = _make_engine()
        engine.kill()
        engine.resume()
        assert not engine.is_killed
        result = engine.check("any_tool", {})
        assert result.verdict.value == "allow"

    def test_kill_overrides_rules(self):
        """Kill switch blocks even tools that would be allowed by rules."""
        rules = RuleSet(rules=[{
            "id": "allow-read",
            "when": {"tool": "read_file"},
            "then": "allow",
        }], default_verdict="allow")
        engine = ShieldEngine(rules=rules)
        engine.kill()
        result = engine.check("read_file", {})
        assert result.verdict.value == "block"
        assert result.rule_id == "__kill_switch__"

    def test_kill_in_audit_mode(self):
        """Kill switch blocks even in AUDIT mode."""
        from policyshield.core.models import ShieldMode
        engine = ShieldEngine(
            rules=RuleSet(rules=[], default_verdict="allow"),
            mode=ShieldMode.AUDIT,
        )
        engine.kill()
        result = engine.check("any_tool", {})
        assert result.verdict.value == "block"

    def test_thread_safety(self):
        """Kill switch is safe to use from multiple threads."""
        engine = _make_engine()
        errors = []

        def checker():
            for _ in range(100):
                try:
                    engine.check("tool", {})
                except Exception as e:
                    errors.append(e)

        def toggler():
            for _ in range(50):
                engine.kill()
                time.sleep(0.001)
                engine.resume()

        t1 = threading.Thread(target=checker)
        t2 = threading.Thread(target=toggler)
        t1.start(); t2.start()
        t1.join(); t2.join()
        assert errors == []

    def test_is_killed_property(self):
        engine = _make_engine()
        assert not engine.is_killed
        engine.kill()
        assert engine.is_killed
        engine.resume()
        assert not engine.is_killed
```

## Самопроверка

```bash
pytest tests/test_kill_switch.py -v
pytest tests/ -q
```

## Коммит

```
feat(security): add engine kill switch for emergency shutdown

- kill() / resume() / is_killed on BaseShieldEngine
- Kill switch is the absolute first check in _do_check_sync
- Uses threading.Event for lock-free, atomic thread safety
- Blocks all tool calls with rule_id="__kill_switch__"
- Overrides rules, mode (ENFORCE/AUDIT), and sanitizer
```
