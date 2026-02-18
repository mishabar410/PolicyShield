# Prompt 302 — Approval Flow

## Цель

Закрыть все v1.0-blockers в human-in-the-loop flow: timeout, audit trail, GC, race condition, args sanitization, polling timeout, meta cleanup.

## Контекст

- `policyshield/shield/base_engine.py` — `_handle_approval_sync()`, `get_approval_status()`, `_approval_meta: dict` (растёт бесконечно)
- `policyshield/approval/memory.py` — `InMemoryBackend`, `_pending`, `_responses` (нет TTL/GC)
- `policyshield/approval/telegram.py` — `TelegramApprovalBackend`, отправляет `args` открытым текстом
- `policyshield/server/app.py` — `check_approval()`, `respond_approval()`, `pending_approvals()`
- **Проблемы:**
  - Approval висит вечно при отсутствии ответа (нет timeout)
  - Трейсы не записывают кто одобрил/отклонил (нет audit trail)
  - `_pending`/`_responses` растут бесконечно (memory leak)
  - Два человека могут ответить на один approval — второй перезаписывает первого (race condition)
  - Args с PII/секретами отправляются в Telegram открытым текстом
  - Нет timeout на polling в HTTP handler
  - `_approval_meta` в engine растёт бесконечно

## Что сделать

### 1. Approval Timeout & Auto-Resolution

```python
# approval/base.py — добавить таймаут
import asyncio
from dataclasses import dataclass, field
from time import monotonic

@dataclass
class ApprovalConfig:
    timeout_seconds: float = 300.0
    on_timeout: str = "BLOCK"  # "BLOCK" | "ALLOW"

# base_engine.py — в _handle_approval_sync():
# После отправки approval request, запустить timer
# Если timeout наступил до respond() → auto-resolve с on_timeout verdict
```

### 2. Approval Audit Trail

```python
# trace/recorder.py — расширить record():
def record(
    self,
    session_id: str,
    tool: str,
    verdict: Verdict,
    rule_id: str | None = None,
    pii_types: list[str] | None = None,
    latency_ms: float = 0.0,
    args: dict | None = None,
    approval_info: dict | None = None,  # NEW
) -> None:
    # approval_info = {
    #     "approval_id": "...",
    #     "status": "approved",
    #     "responder": "@admin",
    #     "responded_at": "2026-02-18T...",
    #     "channel": "telegram",
    #     "response_time_ms": 12400,
    # }
```

### 3. Stale Approval GC

```python
# approval/memory.py
import threading
from time import monotonic

class InMemoryBackend:
    def __init__(self, approval_ttl: float = 3600.0, gc_interval: float = 60.0):
        self._approval_ttl = approval_ttl
        self._timestamps: dict[str, float] = {}  # request_id → created_at
        self._gc_timer: threading.Timer | None = None
        self._start_gc()

    def _start_gc(self):
        self._gc_timer = threading.Timer(self._gc_interval, self._run_gc)
        self._gc_timer.daemon = True
        self._gc_timer.start()

    def _run_gc(self):
        now = monotonic()
        with self._lock:
            expired = [k for k, ts in self._timestamps.items() if now - ts > self._approval_ttl]
            for k in expired:
                self._pending.pop(k, None)
                self._responses.pop(k, None)
                self._timestamps.pop(k, None)
        self._start_gc()  # reschedule

    def stop(self):
        if self._gc_timer:
            self._gc_timer.cancel()
```

### 4. Concurrent Approval Race Condition — First Response Wins

```python
# approval/memory.py — в respond():
def respond(self, request_id: str, approved: bool, responder: str = "", comment: str = ""):
    with self._lock:
        if request_id in self._responses:
            logger.info("Duplicate response for %s ignored (first response wins)", request_id)
            return  # Already responded — ignore
        response = ApprovalResponse(
            request_id=request_id,
            approved=approved,
            responder=responder,
            comment=comment,
        )
        self._responses[request_id] = response
```

Аналогично в `telegram.py`.

### 5. Args Sanitization в Approval Flow

```python
# approval/telegram.py — перед отправкой в Telegram:
def _format_approval_message(self, request: ApprovalRequest) -> str:
    # Sanitize args перед отправкой
    sanitized = self._sanitize_args(request.args)
    return f"**Tool:** `{request.tool_name}`\n**Args:** {sanitized}"

def _sanitize_args(self, args: dict) -> dict:
    """Mask potentially sensitive values in args."""
    # Truncate long values, mask patterns matching secrets/PII
    sanitized = {}
    for k, v in args.items():
        v_str = str(v)
        if len(v_str) > 200:
            v_str = v_str[:200] + "... (truncated)"
        sanitized[k] = v_str
    return sanitized

# server/app.py — endpoint /pending-approvals тоже санитизировать args
```

### 6. Approval Polling Timeout (HTTP Handler)

```python
# server/app.py — в check_approval():
import asyncio

APPROVAL_POLL_TIMEOUT = float(os.environ.get("POLICYSHIELD_APPROVAL_POLL_TIMEOUT", 30))

@app.post("/api/v1/check-approval")
async def check_approval(req: ApprovalStatusRequest):
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(engine.get_approval_status, req.approval_id),
            timeout=APPROVAL_POLL_TIMEOUT,
        )
    except asyncio.TimeoutError:
        return ApprovalStatusResponse(
            approval_id=req.approval_id,
            status="timeout",
        )
    return ApprovalStatusResponse(**result)
```

### 7. `_approval_meta` Cleanup

```python
# base_engine.py
from time import monotonic

class BaseShieldEngine:
    def __init__(self, ...):
        self._approval_meta: dict[str, dict] = {}
        self._approval_meta_ts: dict[str, float] = {}  # timestamps
        self._approval_meta_ttl: float = 3600.0  # 1 hour
        self._max_approval_meta: int = 10000

    def _cleanup_approval_meta(self):
        """Remove stale entries from _approval_meta."""
        now = monotonic()
        expired = [k for k, ts in self._approval_meta_ts.items()
                   if now - ts > self._approval_meta_ttl]
        for k in expired:
            self._approval_meta.pop(k, None)
            self._approval_meta_ts.pop(k, None)

        # Hard limit
        while len(self._approval_meta) > self._max_approval_meta:
            oldest_key = min(self._approval_meta_ts, key=self._approval_meta_ts.get)
            self._approval_meta.pop(oldest_key, None)
            self._approval_meta_ts.pop(oldest_key, None)
```

## Тесты (`tests/test_approval_flow.py`)

```python
"""Tests for approval flow hardening."""
import pytest
from time import sleep
from policyshield.approval.memory import InMemoryBackend

class TestApprovalTimeout:
    def test_approval_times_out(self):
        """Approval should auto-resolve after timeout."""
        backend = InMemoryBackend(approval_ttl=1)
        # Create approval, wait > 1s, check it's resolved

class TestRaceCondition:
    def test_first_response_wins(self):
        backend = InMemoryBackend()
        backend.submit(request_id="r1", tool_name="test", args={}, rule_id="rule-1", message="Test")
        backend.respond("r1", approved=True, responder="alice")
        backend.respond("r1", approved=False, responder="bob")  # должен игнорироваться
        status = backend.get_status("r1")
        assert status["approved"] is True
        assert status["responder"] == "alice"

class TestStaleGC:
    def test_expired_approvals_cleaned(self):
        backend = InMemoryBackend(approval_ttl=0.1, gc_interval=0.1)
        backend.submit(request_id="r1", tool_name="test", args={}, rule_id="rule-1", message="Test")
        sleep(0.3)
        backend._run_gc()
        assert "r1" not in backend._pending

class TestArgsSanitization:
    def test_long_values_truncated(self):
        backend = InMemoryBackend()
        # Verify args are truncated in formatted message

class TestApprovalAuditTrail:
    def test_trace_includes_approval_info(self):
        """Trace record should include who approved and when."""
        pass  # Requires TraceRecorder integration

class TestApprovalMetaCleanup:
    def test_meta_cleaned_after_ttl(self):
        # Create meta entry, wait, verify cleanup
        pass
```

## Самопроверка

```bash
pytest tests/test_approval_flow.py -v
pytest tests/ -q
ruff check policyshield/approval/ policyshield/shield/base_engine.py
```

## Порядок коммитов

1. `feat(approval): add approval timeout with auto-resolution`
2. `feat(trace): add approval audit trail (who/when/channel)`
3. `feat(approval): add stale approval GC with TTL`
4. `fix(approval): first-response-wins race condition guard`
5. `feat(approval): sanitize args before sending to Telegram/API`
6. `feat(server): add approval polling timeout in HTTP handler`
7. `fix(engine): add TTL cleanup for _approval_meta`
