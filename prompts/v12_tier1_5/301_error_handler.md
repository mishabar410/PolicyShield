# Prompt 301 — Global Exception Handler

## Цель

Добавить глобальный exception handler в FastAPI, чтобы при любом необработанном исключении клиент получал machine-readable JSON с `verdict`, а не HTML stack trace.

## Контекст

- `policyshield/server/app.py` — FastAPI app factory, 18 endpoints, **нет** global exception handler
- При исключении в `engine.check()` клиент получает непарсируемый `500 Internal Server Error`
- OpenClaw/SDK не может обработать HTML — агент зависает
- Нужно: при ошибке → JSON `{"verdict": "BLOCK"/"ALLOW", "error": "internal_error"}`
- `engine._fail_open` уже есть — использовать для выбора verdict

## Что сделать

### 1. Добавить exception handlers в `app.py`

```python
from starlette.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

# В create_app(), после создания app:

@app.exception_handler(Exception)
async def shield_error_handler(request: Request, exc: Exception):
    """Return machine-readable verdict even on internal errors."""
    logger.error("Unhandled exception in %s: %s", request.url.path, exc, exc_info=True)
    verdict = "ALLOW" if getattr(engine, '_fail_open', False) else "BLOCK"
    return JSONResponse(
        status_code=500,
        content={
            "verdict": verdict,
            "error": "internal_error",
            "message": "Internal server error",
        },
    )

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Return clean validation error without leaking internals."""
    return JSONResponse(
        status_code=422,
        content={
            "error": "validation_error",
            "message": "Invalid request format",
        },
    )
```

## Тесты

```python
# tests/test_server_hardening.py

class TestGlobalExceptionHandler:
    def test_internal_error_returns_json_verdict(self, client):
        """Even on 500, response must have 'verdict' key."""
        # Mock engine.check to raise
        resp = client.post("/api/v1/check", json={"tool_name": "__crash__"})
        assert resp.headers["content-type"].startswith("application/json")
        assert "verdict" in resp.json()

    def test_validation_error_hides_internals(self, client):
        resp = client.post("/api/v1/check", content="not json", headers={"content-type": "application/json"})
        body = resp.json()
        assert "error" in body
        assert "pydantic" not in body.get("message", "").lower()
```

## Самопроверка

```bash
pytest tests/test_server_hardening.py::TestGlobalExceptionHandler -v
pytest tests/ -q
```

## Коммит

```
feat(server): add global exception handler with machine-readable verdict

- 500 errors return JSON {"verdict": "BLOCK"/"ALLOW"} based on fail_open
- ValidationError returns clean message without leaking pydantic details
```
