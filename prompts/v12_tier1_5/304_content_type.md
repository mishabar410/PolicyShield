# Prompt 304 — Content-Type Validation

## Цель

Валидировать `Content-Type: application/json` на POST-эндпоинтах, чтобы non-JSON input не приводил к непредсказуемому поведению.

## Контекст

- FastAPI парсит body через Pydantic, но при `Content-Type: text/plain` может выдать непонятную ошибку
- Нужно: явно отклонять non-JSON запросы с `415 Unsupported Media Type`

## Что сделать

```python
# app.py — middleware:
@app.middleware("http")
async def content_type_check(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        ct = request.headers.get("content-type", "")
        if ct and "application/json" not in ct and request.url.path.startswith("/api/"):
            return JSONResponse(
                status_code=415,
                content={"error": "unsupported_media_type", "expected": "application/json"},
            )
    return await call_next(request)
```

## Тесты

```python
class TestContentType:
    def test_json_accepted(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "test"})
        assert resp.status_code != 415

    def test_plain_text_rejected(self, client):
        resp = client.post("/api/v1/check", content="not json", headers={"content-type": "text/plain"})
        assert resp.status_code == 415

    def test_form_data_rejected(self, client):
        resp = client.post("/api/v1/check", content="data", headers={"content-type": "application/x-www-form-urlencoded"})
        assert resp.status_code == 415

    def test_no_content_type_allowed(self, client):
        """Missing Content-Type should still work (FastAPI handles it)."""
        resp = client.post("/api/v1/check", json={"tool_name": "test"})
        assert resp.status_code != 415
```

## Самопроверка

```bash
pytest tests/test_server_hardening.py::TestContentType -v
pytest tests/ -q
```

## Коммит

```
feat(server): add Content-Type validation middleware (415 on non-JSON)
```
