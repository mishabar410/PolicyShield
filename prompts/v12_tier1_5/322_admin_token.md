# Prompt 322 — Admin Token Separation

## Цель

Выделить отдельный `POLICYSHIELD_ADMIN_TOKEN` для мутирующих эндпоинтов (`/reload`, `/kill-switch/*`), чтобы compromise обычного API-токена не давал контроль над сервером.

## Контекст

- Сейчас один `POLICYSHIELD_API_TOKEN` для всех эндпоинтов
- Если утёк → злоумышленник может включить kill switch, перезагрузить правила
- Нужно: `/check` → `API_TOKEN`, `/reload`, `/kill-switch/*` → `ADMIN_TOKEN`

## Что сделать

### 1. Обновить `verify_token` в `app.py`

```python
def verify_token(request: Request):
    token = os.environ.get("POLICYSHIELD_API_TOKEN")
    admin_token = os.environ.get("POLICYSHIELD_ADMIN_TOKEN")

    # Admin endpoints require ADMIN_TOKEN
    admin_paths = ("/api/v1/reload", "/api/v1/kill-switch")
    is_admin = any(request.url.path.startswith(p) for p in admin_paths)

    if is_admin:
        required_token = admin_token or token  # Fallback to API_TOKEN if no ADMIN_TOKEN
        if not required_token:
            return  # No auth configured
        _verify_bearer(request, required_token)
    else:
        if not token:
            return
        _verify_bearer(request, token)

def _verify_bearer(request: Request, expected: str):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    provided = auth.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(provided.encode(), expected.encode()):
        raise HTTPException(status_code=403, detail="Invalid token")
```

## Тесты

```python
class TestAdminTokenSeparation:
    def test_check_uses_api_token(self, monkeypatch, engine):
        monkeypatch.setenv("POLICYSHIELD_API_TOKEN", "api-secret")
        monkeypatch.setenv("POLICYSHIELD_ADMIN_TOKEN", "admin-secret")
        app = create_app(engine)
        client = TestClient(app)
        resp = client.post("/api/v1/check", json={"tool_name": "test"},
                           headers={"Authorization": "Bearer api-secret"})
        assert resp.status_code != 403

    def test_reload_rejects_api_token(self, monkeypatch, engine):
        monkeypatch.setenv("POLICYSHIELD_API_TOKEN", "api-secret")
        monkeypatch.setenv("POLICYSHIELD_ADMIN_TOKEN", "admin-secret")
        app = create_app(engine)
        client = TestClient(app)
        resp = client.post("/api/v1/reload", headers={"Authorization": "Bearer api-secret"})
        assert resp.status_code == 403

    def test_reload_accepts_admin_token(self, monkeypatch, engine):
        monkeypatch.setenv("POLICYSHIELD_ADMIN_TOKEN", "admin-secret")
        app = create_app(engine)
        client = TestClient(app)
        resp = client.post("/api/v1/reload", headers={"Authorization": "Bearer admin-secret"})
        assert resp.status_code != 403

    def test_fallback_to_api_token_when_no_admin(self, monkeypatch, engine):
        monkeypatch.setenv("POLICYSHIELD_API_TOKEN", "api-secret")
        app = create_app(engine)
        client = TestClient(app)
        resp = client.post("/api/v1/reload", headers={"Authorization": "Bearer api-secret"})
        assert resp.status_code != 403
```

## Самопроверка

```bash
pytest tests/test_security_data.py::TestAdminTokenSeparation -v
pytest tests/ -q
```

## Коммит

```
feat(server): separate ADMIN_TOKEN for /reload and /kill-switch endpoints
```
