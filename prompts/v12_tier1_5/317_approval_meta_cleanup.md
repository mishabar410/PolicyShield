# Prompt 317 — `_approval_meta` Cleanup

## Цель

Добавить TTL и size limit на `_approval_meta` в engine, предотвращая unbounded memory growth.

## Контекст

- `base_engine.py` — `_approval_meta: dict` растёт бесконечно
- Каждый APPROVE создаёт запись с args/rule → на длинном uptime = memory leak
- Нужно: TTL (1 час), hard limit (10K записей), периодическая cleanup

## Что сделать

```python
# base_engine.py
from time import monotonic

class BaseShieldEngine:
    def __init__(self, ...):
        self._approval_meta: dict[str, dict] = {}
        self._approval_meta_ts: dict[str, float] = {}
        self._approval_meta_ttl: float = 3600.0  # 1 hour
        self._max_approval_meta: int = 10_000

    def _cleanup_approval_meta(self):
        """Remove stale and excess entries from _approval_meta."""
        now = monotonic()
        # TTL cleanup
        expired = [k for k, ts in self._approval_meta_ts.items()
                   if now - ts > self._approval_meta_ttl]
        for k in expired:
            self._approval_meta.pop(k, None)
            self._approval_meta_ts.pop(k, None)

        # Hard limit (evict oldest)
        while len(self._approval_meta) > self._max_approval_meta:
            oldest = min(self._approval_meta_ts, key=self._approval_meta_ts.get)
            self._approval_meta.pop(oldest, None)
            self._approval_meta_ts.pop(oldest, None)

    # В _handle_approval_sync() — после добавления записи:
    def _handle_approval_sync(self, ...):
        # ... existing logic ...
        self._approval_meta[approval_id] = {...}
        self._approval_meta_ts[approval_id] = monotonic()
        self._cleanup_approval_meta()
```

## Тесты

```python
class TestApprovalMetaCleanup:
    def test_expired_entries_cleaned(self):
        from policyshield.shield.sync_engine import ShieldEngine
        engine = ShieldEngine(rules="tests/fixtures/rules.yaml")
        engine._approval_meta = {"old": {}}
        engine._approval_meta_ts = {"old": 0}  # epoch → very old
        engine._approval_meta_ttl = 1.0
        engine._cleanup_approval_meta()
        assert "old" not in engine._approval_meta

    def test_hard_limit_enforced(self):
        from policyshield.shield.sync_engine import ShieldEngine
        engine = ShieldEngine(rules="tests/fixtures/rules.yaml")
        engine._max_approval_meta = 3
        for i in range(5):
            engine._approval_meta[f"k{i}"] = {}
            engine._approval_meta_ts[f"k{i}"] = float(i)
        engine._cleanup_approval_meta()
        assert len(engine._approval_meta) <= 3
```

## Самопроверка

```bash
pytest tests/test_approval_hardening.py::TestApprovalMetaCleanup -v
pytest tests/ -q
```

## Коммит

```
fix(engine): add TTL and size limit cleanup for _approval_meta
```
