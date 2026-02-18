# Prompt 323 — Sensitive Data in Error Responses

## Цель

Убедиться, что stack traces, internal paths, и rule internals не утекают в HTTP responses.

## Контекст

- Prompt 301 добавил global error handler, но нужно ещё: убрать traces из validation errors, scrub paths
- FastAPI по дефолту возвращает полные pydantic details в 422
- Нужно: generic messages в production, подробности — только при `POLICYSHIELD_DEBUG=true`

## Что сделать

### 1. Обновить exception handlers в `app.py`

```python
DEBUG = os.environ.get("POLICYSHIELD_DEBUG", "").lower() in ("1", "true", "yes")

@app.exception_handler(Exception)
async def shield_error_handler(request: Request, exc: Exception):
    logger.error("Unhandled: %s", exc, exc_info=True)
    verdict = "ALLOW" if getattr(engine, '_fail_open', False) else "BLOCK"
    detail = {"verdict": verdict, "error": "internal_error", "message": "Internal server error"}
    if DEBUG:
        detail["debug"] = {"type": str(type(exc).__name__), "detail": str(exc)}
    return JSONResponse(status_code=500, content=detail)

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    detail = {"error": "validation_error", "message": "Invalid request format"}
    if DEBUG:
        detail["debug"] = {"errors": exc.errors()}
    return JSONResponse(status_code=422, content=detail)
```

### 2. Scrub rule internals из CheckResponse

```python
# В check handler — не возвращать internal paths:
return CheckResponse(
    ...,
    message=result.message if not _contains_path(result.message) else "Rule matched",
)

def _contains_path(s: str) -> bool:
    return "/" in s and (".py" in s or ".yaml" in s or "home" in s.lower())
```

## Тесты

```python
class TestSensitiveDataInErrors:
    def test_500_hides_stack_trace(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "__crash__"})
        body = resp.json()
        assert "Traceback" not in str(body)
        assert ".py" not in str(body)

    def test_422_hides_pydantic_details(self, client):
        resp = client.post("/api/v1/check", content="broken", headers={"content-type": "application/json"})
        body = resp.json()
        assert "pydantic" not in str(body).lower()

    def test_debug_mode_shows_details(self, monkeypatch, engine):
        monkeypatch.setenv("POLICYSHIELD_DEBUG", "true")
        app = create_app(engine)
        c = TestClient(app)
        resp = c.post("/api/v1/check", json={"tool_name": "__crash__"})
        body = resp.json()
        assert "debug" in body
```

## Самопроверка

```bash
pytest tests/test_security_data.py::TestSensitiveDataInErrors -v
pytest tests/ -q
```

## Коммит

```
feat(server): scrub sensitive data from error responses (debug mode toggle)
```
