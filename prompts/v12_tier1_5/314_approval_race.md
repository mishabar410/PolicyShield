# Prompt 314 — First Response Wins (Race Condition)

## Цель

Предотвратить race condition когда два approver'а отвечают на один approval: первый ответ побеждает, последующие игнорируются.

## Контекст

- `approval/memory.py` — `respond()` перезаписывает `_responses[request_id]` без проверки
- Два человека нажали Approve/Deny одновременно → второй перезаписывает первого
- Нужно: first-response-wins, дублирующие ответы логируются и игнорируются

## Что сделать

```python
# approval/memory.py — обновить respond():
def respond(self, request_id: str, approved: bool, responder: str = "", comment: str = ""):
    with self._lock:
        if request_id not in self._pending:
            logger.warning("Response for unknown approval %s", request_id)
            return
        if request_id in self._responses:
            logger.info(
                "Duplicate response for %s from %s ignored (first response from %s wins)",
                request_id, responder, self._responses[request_id].responder,
            )
            return  # First response wins
        self._responses[request_id] = ApprovalResponse(
            request_id=request_id,
            approved=approved,
            responder=responder,
            comment=comment,
        )
```

Аналогично в `approval/telegram.py` если есть callback handler.

## Тесты

```python
class TestFirstResponseWins:
    def test_first_response_wins(self):
        from policyshield.approval.memory import InMemoryBackend
        backend = InMemoryBackend()
        backend.submit(request_id="r1", tool_name="test", args={}, rule_id="r", message="t")
        backend.respond("r1", approved=True, responder="alice")
        backend.respond("r1", approved=False, responder="bob")  # Should be ignored
        status = backend.get_status("r1")
        assert status["approved"] is True
        assert status["responder"] == "alice"

    def test_unknown_approval_ignored(self):
        backend = InMemoryBackend()
        backend.respond("nonexistent", approved=True)  # Should not crash

    def test_respond_after_timeout_ignored(self):
        backend = InMemoryBackend(timeout=0.1)
        backend.submit(request_id="r1", tool_name="test", args={}, rule_id="r", message="t")
        import time; time.sleep(0.2)
        # After timeout, response might still come in
        backend.respond("r1", approved=True, responder="late-responder")
        # Should handle gracefully
```

## Самопроверка

```bash
pytest tests/test_approval_hardening.py::TestFirstResponseWins -v
pytest tests/ -q
```

## Коммит

```
fix(approval): first-response-wins guard for concurrent approvals
```
