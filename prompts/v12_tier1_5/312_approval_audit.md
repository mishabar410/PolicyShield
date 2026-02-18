# Prompt 312 — Approval Audit Trail

## Цель

Записывать в trace: кто одобрил/отклонил, когда, через какой канал (Telegram/REST), за сколько.

## Контекст

- `policyshield/trace/recorder.py` — `record()` не принимает approval metadata
- Сейчас trace пишет только `verdict`, но не WHO approved
- Для compliance/audit нужно: responder, timestamp, channel, response time

## Что сделать

### 1. Расширить `TraceRecorder.record()`

```python
# trace/recorder.py
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
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "tool": tool,
        "verdict": verdict.value,
        "rule_id": rule_id,
        "latency_ms": round(latency_ms, 2),
    }
    if approval_info:
        entry["approval"] = approval_info
    # ... rest of existing logic
```

### 2. Передать approval info из engine

```python
# base_engine.py — в _handle_approval_sync(), после получения ответа:
approval_info = {
    "approval_id": approval_id,
    "status": "approved" if response.approved else "denied",
    "responder": response.responder,
    "responded_at": datetime.now(timezone.utc).isoformat(),
    "response_time_ms": round((monotonic() - start_time) * 1000, 1),
}
# Передать в _trace():
self._trace(result, session_id, tool_name, latency_ms, args, approval_info=approval_info)
```

## Тесты

```python
class TestApprovalAuditTrail:
    def test_trace_includes_approval_info(self, tmp_path):
        from policyshield.trace.recorder import TraceRecorder
        from policyshield.core.models import Verdict
        import json

        recorder = TraceRecorder(output_dir=tmp_path)
        recorder.record(
            "s1", "test", Verdict.ALLOW,
            approval_info={
                "approval_id": "ap-123",
                "status": "approved",
                "responder": "@admin",
                "response_time_ms": 5000,
            },
        )
        recorder.flush()
        lines = list(tmp_path.glob("*.jsonl"))[0].read_text().strip().split("\n")
        entry = json.loads(lines[0])
        assert entry["approval"]["responder"] == "@admin"
        assert entry["approval"]["status"] == "approved"

    def test_trace_without_approval_info(self, tmp_path):
        from policyshield.trace.recorder import TraceRecorder
        from policyshield.core.models import Verdict
        import json

        recorder = TraceRecorder(output_dir=tmp_path)
        recorder.record("s1", "test", Verdict.BLOCK)
        recorder.flush()
        lines = list(tmp_path.glob("*.jsonl"))[0].read_text().strip().split("\n")
        entry = json.loads(lines[0])
        assert "approval" not in entry
```

## Самопроверка

```bash
pytest tests/test_approval_hardening.py::TestApprovalAuditTrail -v
pytest tests/ -q
```

## Коммит

```
feat(trace): add approval audit trail (who/when/channel/response_time)
```
