# Prompt 316 — Approval Polling Timeout (HTTP)

## Цель

Добавить таймаут на HTTP polling endpoint `/check-approval`, чтобы клиент не зависал навсегда при опросе статуса.

## Контекст

- `server/app.py` — `check_approval()` вызывает `engine.get_approval_status()` синхронно
- Если backend медленный (e.g., network-based) → HTTP request зависает
- Нужно: `asyncio.wait_for()` с таймаутом, status `"timeout"` при превышении

## Что сделать

```python
# server/app.py
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
        return ApprovalStatusResponse(approval_id=req.approval_id, status="timeout")
    return ApprovalStatusResponse(**result)
```

## Тесты

```python
class TestApprovalPollingTimeout:
    def test_normal_poll_works(self, client):
        resp = client.post("/api/v1/check-approval", json={"approval_id": "nonexistent"})
        assert resp.status_code in (200, 404)

    @pytest.mark.asyncio
    async def test_slow_poll_returns_timeout(self):
        # Mock engine.get_approval_status with sleep > timeout
        pass
```

## Самопроверка

```bash
pytest tests/test_approval_hardening.py::TestApprovalPollingTimeout -v
pytest tests/ -q
```

## Коммит

```
feat(server): add approval polling timeout (default 30s)
```
