# Prompt 311 — Approval Timeout & Auto-Resolution

## Цель

Добавить таймаут на approval request: если никто не ответил за N сек → auto-resolve (BLOCK или ALLOW по конфигу).

## Контекст

- `policyshield/shield/base_engine.py` — `_handle_approval_sync()` ждёт ответа бесконечно
- `policyshield/approval/memory.py` — `InMemoryBackend.get_status()` не отслеживает время
- Проблема: если Telegram бот / approver недоступен → запрос зависает навсегда
- Нужно: `approval_timeout: 300` (5 мин), `on_timeout: BLOCK` (конфиг в YAML / env)

## Что сделать

### 1. Добавить `ApprovalConfig` dataclass

```python
# approval/config.py
from dataclasses import dataclass

@dataclass
class ApprovalConfig:
    """Configuration for approval flow behavior."""
    timeout_seconds: float = 300.0
    on_timeout: str = "BLOCK"  # "BLOCK" | "ALLOW"
```

### 2. Обновить `InMemoryBackend`

```python
# approval/memory.py — добавить timestamps:
from time import monotonic

class InMemoryBackend:
    def __init__(self, ..., timeout: float = 300.0, on_timeout: str = "BLOCK"):
        self._timeout = timeout
        self._on_timeout = on_timeout
        self._created_at: dict[str, float] = {}  # request_id → monotonic time

    def submit(self, ...):
        # existing logic
        self._created_at[request_id] = monotonic()

    def get_status(self, request_id: str) -> dict:
        # Check if timed out
        if request_id in self._created_at:
            elapsed = monotonic() - self._created_at[request_id]
            if elapsed > self._timeout and request_id not in self._responses:
                return {
                    "status": "timeout",
                    "elapsed": elapsed,
                    "auto_verdict": self._on_timeout,
                }
        # existing logic ...
```

### 3. Обновить `_handle_approval_sync` в engine

```python
# base_engine.py — в _handle_approval_sync():
status = self._approval_backend.get_status(approval_id)
if status.get("status") == "timeout":
    verdict = Verdict.BLOCK if status["auto_verdict"] == "BLOCK" else Verdict.ALLOW
    logger.warning("Approval %s timed out → %s", approval_id, verdict.value)
    return ShieldResult(verdict=verdict, message=f"Approval timed out after {status['elapsed']:.0f}s")
```

## Тесты

```python
class TestApprovalTimeout:
    def test_approval_times_out(self):
        from policyshield.approval.memory import InMemoryBackend
        backend = InMemoryBackend(timeout=0.1, on_timeout="BLOCK")
        backend.submit(request_id="r1", tool_name="test", args={}, rule_id="rule-1", message="Test")
        import time; time.sleep(0.2)
        status = backend.get_status("r1")
        assert status["status"] == "timeout"
        assert status["auto_verdict"] == "BLOCK"

    def test_approval_within_timeout(self):
        backend = InMemoryBackend(timeout=10.0)
        backend.submit(request_id="r1", tool_name="test", args={}, rule_id="rule-1", message="Test")
        status = backend.get_status("r1")
        assert status["status"] == "pending"

    def test_on_timeout_allow(self):
        backend = InMemoryBackend(timeout=0.1, on_timeout="ALLOW")
        backend.submit(request_id="r1", tool_name="test", args={}, rule_id="rule-1", message="Test")
        import time; time.sleep(0.2)
        status = backend.get_status("r1")
        assert status["auto_verdict"] == "ALLOW"
```

## Самопроверка

```bash
pytest tests/test_approval_hardening.py::TestApprovalTimeout -v
pytest tests/ -q
```

## Коммит

```
feat(approval): add approval timeout with auto-resolution (BLOCK/ALLOW)
```
