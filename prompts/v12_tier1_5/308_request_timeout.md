# Prompt 308 — HTTP Request Lifecycle Timeout

## Цель

Добавить общий таймаут на обработку HTTP-запроса, чтобы медленный rule/regex не блокировал worker навсегда.

## Контекст

- Нет таймаута на `engine.check()` → regex backtracking = worker заблокирован навсегда
- Дефолт: 30 сек (env `POLICYSHIELD_REQUEST_TIMEOUT`)
- При таймауте: `504 Gateway Timeout` с `verdict: BLOCK`

## Что сделать

```python
# app.py
import asyncio

REQUEST_TIMEOUT = float(os.environ.get("POLICYSHIELD_REQUEST_TIMEOUT", 30))

@app.middleware("http")
async def timeout_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        try:
            return await asyncio.wait_for(call_next(request), timeout=REQUEST_TIMEOUT)
        except asyncio.TimeoutError:
            logger.error("Request timeout (%.1fs) for %s", REQUEST_TIMEOUT, request.url.path)
            return JSONResponse(
                status_code=504,
                content={"verdict": "BLOCK", "error": "request_timeout", "message": f"Request exceeded {REQUEST_TIMEOUT}s"},
            )
    return await call_next(request)
```

## Тесты

```python
class TestRequestTimeout:
    def test_fast_request_succeeds(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "test"})
        assert resp.status_code != 504

    @pytest.mark.asyncio
    async def test_slow_request_returns_504(self):
        """Verify timeout fires for slow handler."""
        # Need to mock engine.check with asyncio.sleep
        pass

    def test_health_not_affected(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
```

## Самопроверка

```bash
pytest tests/test_server_hardening.py::TestRequestTimeout -v
pytest tests/ -q
```

## Коммит

```
feat(server): add HTTP request lifecycle timeout (default 30s, 504 on timeout)
```
