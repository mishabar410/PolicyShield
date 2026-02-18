# Prompt 301 — Server Hardening (HTTP Layer)

## Цель

Защитить HTTP-сервер PolicyShield от некорректного и вредоносного input: глобальный error handler, request ID, CORS, Content-Type validation, payload size limit, input validation, backpressure, request timeout.

## Контекст

- `policyshield/server/app.py` — FastAPI app factory, 18 endpoints, **нет** global exception handler
- `policyshield/server/models.py` — Pydantic models, `CheckRequest.tool_name: str` без ограничений
- `engine.check()` вызывается без try/except → при исключении клиент получает непарсируемый `500`
- Нет `request_id` ни в запросе, ни в ответе — невозможна корреляция при debugging
- Нет CORS middleware — browser SDK получит `403 CORS error`
- Нет проверки Content-Type → непредсказуемое поведение на non-JSON input
- Нет лимита на размер payload → один 100MB запрос = OOM
- `tool_name` принимает пустую строку, 10MB строку, null-bytes
- Нет лимита concurrent requests → DDoS вектор
- Нет общего HTTP request timeout → медленный запрос блокирует worker навсегда

## Что сделать

### 1. Global Exception Handler (`app.py`)

```python
from starlette.responses import JSONResponse

@app.exception_handler(Exception)
async def shield_error_handler(request: Request, exc: Exception):
    """Return machine-readable verdict even on internal errors."""
    logger.error("Unhandled exception in %s: %s", request.url.path, exc, exc_info=True)
    # По дефолту fail-closed (BLOCK при ошибке)
    verdict = "ALLOW" if getattr(engine, '_fail_open', False) else "BLOCK"
    return JSONResponse(
        status_code=500,
        content={"verdict": verdict, "error": "internal_error", "message": "Check failed"},
    )
```

### 2. Request / Correlation ID (`models.py` + `app.py`)

```python
# models.py
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
    request_id: str = ""  # всегда возвращается
    # ... остальные поля

# app.py — в check() handler:
req_id = req.request_id or str(uuid.uuid4())
# передать в response: CheckResponse(..., request_id=req_id)
```

### 3. CORS Middleware (`app.py`)

```python
from starlette.middleware.cors import CORSMiddleware

# В create_app(), после создания app:
cors_origins = os.environ.get("POLICYSHIELD_CORS_ORIGINS", "").split(",")
if cors_origins and cors_origins != [""]:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )
```

### 4. Content-Type Validation Middleware

```python
@app.middleware("http")
async def content_type_check(request: Request, call_next):
    if request.method in ("POST", "PUT") and request.url.path != "/docs":
        ct = request.headers.get("content-type", "")
        if ct and "application/json" not in ct:
            return JSONResponse(
                status_code=415,
                content={"error": "Unsupported Media Type", "expected": "application/json"},
            )
    return await call_next(request)
```

### 5. Payload Size Limit

```python
# Вариант А: middleware
MAX_REQUEST_SIZE = int(os.environ.get("POLICYSHIELD_MAX_REQUEST_SIZE", 1_048_576))  # 1MB

@app.middleware("http")
async def payload_size_limit(request: Request, call_next):
    if request.method in ("POST", "PUT"):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_SIZE:
            return JSONResponse(
                status_code=413,
                content={"error": "Payload too large", "max_bytes": MAX_REQUEST_SIZE},
            )
    return await call_next(request)
```

### 6. Input Validation (`models.py`)

```python
from pydantic import BaseModel, Field, field_validator

class CheckRequest(BaseModel):
    tool_name: str = Field(..., min_length=1, max_length=256, pattern=r"^[\w.\-:]+$")
    args: dict = {}
    session_id: str = Field(default="default", min_length=1, max_length=256)
    sender: str | None = Field(default=None, max_length=256)
    request_id: str | None = Field(default=None, max_length=128)

    @field_validator("args")
    @classmethod
    def validate_args_depth(cls, v: dict) -> dict:
        """Reject deeply nested dicts (bomb prevention)."""
        _check_depth(v, max_depth=10)
        return v

def _check_depth(obj: object, max_depth: int, current: int = 0) -> None:
    if current > max_depth:
        raise ValueError(f"Args nesting exceeds max depth ({max_depth})")
    if isinstance(obj, dict):
        for val in obj.values():
            _check_depth(val, max_depth, current + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_depth(item, max_depth, current + 1)
```

### 7. Backpressure / Max Concurrent Checks

```python
import asyncio

MAX_CONCURRENT = int(os.environ.get("POLICYSHIELD_MAX_CONCURRENT_CHECKS", 100))
_semaphore = asyncio.Semaphore(MAX_CONCURRENT)

@app.middleware("http")
async def backpressure_middleware(request: Request, call_next):
    if request.url.path == "/api/v1/check":
        if _semaphore.locked():
            return JSONResponse(
                status_code=503,
                content={"error": "Server overloaded", "verdict": "BLOCK"},
            )
        async with _semaphore:
            return await call_next(request)
    return await call_next(request)
```

### 8. HTTP Request Lifecycle Timeout

```python
REQUEST_TIMEOUT = float(os.environ.get("POLICYSHIELD_REQUEST_TIMEOUT", 30))

@app.middleware("http")
async def timeout_middleware(request: Request, call_next):
    try:
        return await asyncio.wait_for(call_next(request), timeout=REQUEST_TIMEOUT)
    except asyncio.TimeoutError:
        return JSONResponse(
            status_code=504,
            content={"error": "Request timeout", "verdict": "BLOCK"},
        )
```

## Тесты (`tests/test_server_hardening.py`)

```python
"""Tests for HTTP server hardening features."""
import pytest
from fastapi.testclient import TestClient
from policyshield.server.app import create_app
# ... setup engine fixture ...

class TestGlobalExceptionHandler:
    def test_internal_error_returns_verdict(self, client):
        """500 should still return machine-readable verdict."""
        # Trigger internal error (e.g., corrupted engine)
        resp = client.post("/api/v1/check", json={"tool_name": "test", "args": {}})
        # Even on error, response should have 'verdict' key
        assert "verdict" in resp.json()

class TestRequestId:
    def test_response_has_request_id(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "test"})
        assert "request_id" in resp.json()
        assert len(resp.json()["request_id"]) > 0

    def test_client_request_id_echoed(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "test", "request_id": "my-id-123"})
        assert resp.json()["request_id"] == "my-id-123"

class TestContentType:
    def test_wrong_content_type_returns_415(self, client):
        resp = client.post("/api/v1/check", content="not json", headers={"content-type": "text/plain"})
        assert resp.status_code == 415

class TestPayloadSize:
    def test_oversized_payload_returns_413(self, client):
        huge = {"tool_name": "x", "args": {"data": "x" * 2_000_000}}
        resp = client.post("/api/v1/check", json=huge)
        assert resp.status_code == 413

class TestInputValidation:
    def test_empty_tool_name_rejected(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": ""})
        assert resp.status_code == 422

    def test_too_long_tool_name_rejected(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "a" * 300})
        assert resp.status_code == 422

    def test_special_chars_in_tool_name_rejected(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "rm -rf /"})
        assert resp.status_code == 422

    def test_deeply_nested_args_rejected(self, client):
        nested = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": {"k": "deep"}}}}}}}}}}}
        resp = client.post("/api/v1/check", json={"tool_name": "test", "args": nested})
        assert resp.status_code == 422

class TestBackpressure:
    def test_overload_returns_503(self, client):
        # Тест через mock semaphore
        pass  # implementation depends on semaphore injection

class TestRequestTimeout:
    def test_slow_request_returns_504(self, client):
        # Тест с mock slow engine
        pass  # implementation depends on timeout injection
```

## Самопроверка

```bash
pytest tests/test_server_hardening.py -v
pytest tests/ -q          # все тесты проходят
ruff check policyshield/server/
ruff format --check policyshield/server/
```

## Порядок коммитов

Каждая фича — отдельный коммит:

1. `feat(server): add global exception handler with fail-open/closed verdict`
2. `feat(server): add request_id to CheckRequest/CheckResponse`
3. `feat(server): add CORS middleware with env-based config`
4. `feat(server): add Content-Type validation middleware`
5. `feat(server): add payload size limit middleware`
6. `feat(server): add input validation (tool_name pattern, args depth limit)`
7. `feat(server): add backpressure middleware (max concurrent checks)`
8. `feat(server): add HTTP request lifecycle timeout middleware`
