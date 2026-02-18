# Prompt 305 — Payload Size Limit

## Цель

Ограничить размер HTTP request body, чтобы один огромный запрос не вызвал OOM.

## Контекст

- Нет лимита на размер payload → один 100MB запрос = OOM crash
- Дефолтный лимит: 1MB (конфигурируется через `POLICYSHIELD_MAX_REQUEST_SIZE`)
- Для `/api/v1/check`: типичный payload 1-10KB; 1MB — более чем достаточно

## Что сделать

```python
# app.py — middleware:
MAX_REQUEST_SIZE = int(os.environ.get("POLICYSHIELD_MAX_REQUEST_SIZE", 1_048_576))  # 1MB

@app.middleware("http")
async def payload_size_limit(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_SIZE:
            return JSONResponse(
                status_code=413,
                content={
                    "error": "payload_too_large",
                    "message": f"Request body exceeds {MAX_REQUEST_SIZE} bytes",
                    "max_bytes": MAX_REQUEST_SIZE,
                },
            )
    return await call_next(request)
```

## Тесты

```python
class TestPayloadSize:
    def test_normal_payload_accepted(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "test", "args": {"x": "a" * 100}})
        assert resp.status_code != 413

    def test_oversized_payload_rejected(self, client, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_MAX_REQUEST_SIZE", "100")
        # Recreate app with new limit
        resp = client.post("/api/v1/check", json={"tool_name": "test", "args": {"data": "x" * 200}})
        assert resp.status_code == 413

    def test_custom_limit_from_env(self, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_MAX_REQUEST_SIZE", "5000000")
        # Verify limit is read correctly
```

## Самопроверка

```bash
pytest tests/test_server_hardening.py::TestPayloadSize -v
pytest tests/ -q
```

## Коммит

```
feat(server): add payload size limit middleware (default 1MB)
```
