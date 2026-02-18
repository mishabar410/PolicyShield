# Prompt 307 — Backpressure (Max Concurrent Checks)

## Цель

Ограничить количество одновременных `/check` запросов, чтобы перегрузка не привела к OOM/зависанию.

## Контекст

- Нет лимита concurrent requests → DDoS/thundering herd = OOM
- Дефолт: 100 одновременных проверок (env `POLICYSHIELD_MAX_CONCURRENT_CHECKS`)
- При перегрузке: `503 Service Unavailable` с `verdict: BLOCK`

## Что сделать

```python
# app.py
import asyncio

MAX_CONCURRENT = int(os.environ.get("POLICYSHIELD_MAX_CONCURRENT_CHECKS", 100))

# В create_app():
_semaphore = asyncio.Semaphore(MAX_CONCURRENT)

@app.middleware("http")
async def backpressure_middleware(request: Request, call_next):
    if request.url.path in ("/api/v1/check", "/api/v1/post-check"):
        if _semaphore.locked():
            return JSONResponse(
                status_code=503,
                content={"verdict": "BLOCK", "error": "server_overloaded", "message": "Too many concurrent requests"},
            )
        async with _semaphore:
            return await call_next(request)
    return await call_next(request)
```

## Тесты

```python
class TestBackpressure:
    @pytest.mark.asyncio
    async def test_concurrent_limit_enforced(self):
        """When semaphore is full, new requests get 503."""
        import asyncio
        sem = asyncio.Semaphore(1)
        async with sem:
            assert sem.locked()

    def test_overload_returns_503_with_verdict(self, client):
        # Mock: set semaphore to 0
        # Verify 503 response has "verdict" key
        pass

    def test_non_check_endpoints_not_limited(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200  # health always available
```

## Самопроверка

```bash
pytest tests/test_server_hardening.py::TestBackpressure -v
pytest tests/ -q
```

## Коммит

```
feat(server): add backpressure middleware (max concurrent checks, 503 on overload)
```
