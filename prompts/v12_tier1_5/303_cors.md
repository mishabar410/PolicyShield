# Prompt 303 — CORS Middleware

## Цель

Добавить CORS middleware с env-конфигом, чтобы browser-based SDK и Web UI могли работать с PolicyShield API.

## Контекст

- Нет CORS middleware → запросы из браузера получают `403 CORS error`
- Нужен env-based конфиг: `POLICYSHIELD_CORS_ORIGINS=http://localhost:3000,https://app.example.com`
- По дефолту CORS выключен (пустая строка) — для CLI/SDK не нужен

## Что сделать

### 1. Добавить middleware в `app.py`

```python
from starlette.middleware.cors import CORSMiddleware

# В create_app(), после создания app:
cors_origins = os.environ.get("POLICYSHIELD_CORS_ORIGINS", "").split(",")
cors_origins = [o.strip() for o in cors_origins if o.strip()]
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=3600,
    )
```

## Тесты

```python
class TestCORS:
    def test_cors_disabled_by_default(self, client):
        resp = client.options("/api/v1/check", headers={"Origin": "http://evil.com"})
        assert "access-control-allow-origin" not in resp.headers

    def test_cors_enabled_with_env(self, monkeypatch, engine):
        monkeypatch.setenv("POLICYSHIELD_CORS_ORIGINS", "http://localhost:3000")
        from policyshield.server.app import create_app
        app = create_app(engine)
        from fastapi.testclient import TestClient
        c = TestClient(app)
        resp = c.options("/api/v1/check", headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
        })
        assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"
```

## Самопроверка

```bash
pytest tests/test_server_hardening.py::TestCORS -v
pytest tests/ -q
```

## Коммит

```
feat(server): add CORS middleware with POLICYSHIELD_CORS_ORIGINS env config
```
