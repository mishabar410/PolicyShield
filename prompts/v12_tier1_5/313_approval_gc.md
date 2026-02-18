# Prompt 313 — Stale Approval GC

## Цель

Добавить периодическую очистку stale approvals из `InMemoryBackend`, чтобы `_pending`/`_responses` не росли бесконечно.

## Контекст

- `approval/memory.py` — `_pending: dict`, `_responses: dict` — никогда не чистятся
- На длинном uptime = memory leak (1000 approvals/день × 30 дней = 30K записей)
- Нужно: TTL (default 1 час), фоновый GC thread, `stop()` для graceful shutdown

## Что сделать

```python
# approval/memory.py
import threading
from time import monotonic

class InMemoryBackend:
    def __init__(self, ..., gc_ttl: float = 3600.0, gc_interval: float = 60.0):
        self._gc_ttl = gc_ttl
        self._gc_interval = gc_interval
        self._gc_timer: threading.Timer | None = None
        self._start_gc()

    def _start_gc(self):
        """Start periodic garbage collection."""
        self._gc_timer = threading.Timer(self._gc_interval, self._run_gc)
        self._gc_timer.daemon = True
        self._gc_timer.start()

    def _run_gc(self):
        """Remove entries older than gc_ttl."""
        now = monotonic()
        with self._lock:
            expired = [k for k, ts in self._created_at.items() if now - ts > self._gc_ttl]
            for k in expired:
                self._pending.pop(k, None)
                self._responses.pop(k, None)
                self._created_at.pop(k, None)
            if expired:
                logger.info("GC: cleaned %d stale approvals", len(expired))
        self._start_gc()  # Reschedule

    def stop(self):
        """Stop GC timer. Call on shutdown."""
        if self._gc_timer:
            self._gc_timer.cancel()
            self._gc_timer = None
```

## Тесты

```python
class TestStaleApprovalGC:
    def test_expired_approvals_cleaned(self):
        from policyshield.approval.memory import InMemoryBackend
        backend = InMemoryBackend(gc_ttl=0.1, gc_interval=0.05)
        backend.submit(request_id="r1", tool_name="test", args={}, rule_id="r", message="t")
        import time; time.sleep(0.2)
        backend._run_gc()
        assert "r1" not in backend._pending
        backend.stop()

    def test_fresh_approvals_not_cleaned(self):
        backend = InMemoryBackend(gc_ttl=60)
        backend.submit(request_id="r1", tool_name="test", args={}, rule_id="r", message="t")
        backend._run_gc()
        assert "r1" in backend._pending
        backend.stop()

    def test_stop_cancels_timer(self):
        backend = InMemoryBackend()
        assert backend._gc_timer is not None
        backend.stop()
        assert backend._gc_timer is None
```

## Самопроверка

```bash
pytest tests/test_approval_hardening.py::TestStaleApprovalGC -v
pytest tests/ -q
```

## Коммит

```
feat(approval): add stale approval GC with TTL and background timer
```
