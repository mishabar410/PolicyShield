# Prompt 302 — Request / Correlation ID

## Цель

Добавить `request_id` в каждый запрос/ответ для корреляции логов, трейсов и дебага в продакшне.

## Контекст

- Нет `request_id` ни в запросе, ни в ответе — невозможна корреляция при debugging
- Клиент (SDK/OpenClaw) не может привязать ответ к конкретному вызову
- Нужно: клиент может передать свой `request_id`, сервер вернёт его же; если не передал — сгенерирует UUID

## Что сделать

### 1. Обновить модели (`models.py`)

```python
import uuid

class CheckRequest(BaseModel):
    tool_name: str
    args: dict = {}
    session_id: str = "default"
    sender: str | None = None
    request_id: str | None = None  # клиент может передать свой

class CheckResponse(BaseModel):
    verdict: str
    message: str = ""
    rule_id: str | None = None
    modified_args: dict | None = None
    pii_types: list[str] = []
    approval_id: str | None = None
    shield_version: str = ""
    request_id: str = ""  # всегда возвращается
```

### 2. Обновить handler (`app.py`)

```python
import uuid

# В check() handler:
@app.post("/api/v1/check")
async def check(req: CheckRequest):
    req_id = req.request_id or str(uuid.uuid4())
    # ... existing logic ...
    return CheckResponse(
        ...,
        request_id=req_id,
    )
```

### 3. Добавить в логи

```python
logger.info("Check request_id=%s tool=%s verdict=%s", req_id, req.tool_name, result.verdict.value)
```

## Тесты

```python
class TestRequestId:
    def test_response_always_has_request_id(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "test"})
        data = resp.json()
        assert "request_id" in data
        assert len(data["request_id"]) > 0

    def test_client_request_id_echoed(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "test", "request_id": "my-id-123"})
        assert resp.json()["request_id"] == "my-id-123"

    def test_generated_id_is_uuid(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "test"})
        rid = resp.json()["request_id"]
        uuid.UUID(rid)  # Raises ValueError if not valid UUID
```

## Самопроверка

```bash
pytest tests/test_server_hardening.py::TestRequestId -v
pytest tests/ -q
```

## Коммит

```
feat(server): add request_id to CheckRequest/CheckResponse

- Client can pass request_id; server generates UUID if not provided
- request_id always echoed in response for log correlation
```
