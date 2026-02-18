# Prompt 76 — Server Auth

## Цель

Добавить опциональную Bearer token аутентификацию на PolicyShield HTTP сервер. Поддержать token в OpenClaw плагине.

## Контекст

- Сейчас все эндпоинты (`/api/v1/check`, `/api/v1/reload`, `/api/v1/constraints`) открыты без аутентификации
- `/api/v1/reload` особенно опасен — позволяет перезагрузить правила
- Аутентификация должна быть **опциональной** — без env var работает как раньше (для dev)
- `/api/v1/health` обязательно без auth (для healthcheck от Docker/K8s)

## Что сделать

### 1. Добавить middleware в `policyshield/server/app.py`

```python
import os
from fastapi import Request, HTTPException

API_TOKEN = os.environ.get("POLICYSHIELD_API_TOKEN")

async def verify_token(request: Request):
    """Verify Bearer token if POLICYSHIELD_API_TOKEN is set."""
    if API_TOKEN is None:
        return  # No auth configured — allow all
    if request.url.path == "/api/v1/health":
        return  # Health endpoint is always public
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = auth_header[7:]
    if token != API_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")
```

Зарегистрировать как middleware FastAPI:

```python
from fastapi import Depends

# Вариант: использовать dependency на каждый роут, кроме health
# Или: использовать middleware на уровне app
```

### 2. Обновить `plugins/openclaw/src/client.ts`

Добавить поддержку `api_token`:

```typescript
constructor(config: PluginConfig = {}, logger?: PluginLogger) {
    this.url = (config.url ?? "http://localhost:8100").replace(/\/$/, "");
    this.timeout = config.timeout_ms ?? 5000;
    this.enabled = (config.mode ?? "enforce") !== "disabled";
    this.failOpen = config.fail_open ?? true;
    this.apiToken = config.api_token ?? undefined;
    this.logger = logger;
}

private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
        "Content-Type": "application/json",
    };
    if (this.apiToken) {
        headers["Authorization"] = `Bearer ${this.apiToken}`;
    }
    return headers;
}
```

Использовать `this.getHeaders()` во всех fetch-вызовах вместо hardcoded `"Content-Type"`.

### 3. Обновить `plugins/openclaw/openclaw.plugin.json`

Добавить `api_token` в schema:

```json
"api_token": {
    "type": "string",
    "description": "Bearer token for PolicyShield server authentication. If set, all API requests will include this token. Must match POLICYSHIELD_API_TOKEN on the server.",
    "default": ""
}
```

### 4. Обновить `PluginConfig` type

В `plugins/openclaw/src/client.ts` или отдельном `types.ts`:

```typescript
export type PluginConfig = {
    url?: string;
    mode?: "enforce" | "disabled";
    fail_open?: boolean;
    timeout_ms?: number;
    api_token?: string;
    approve_timeout_ms?: number;
    approve_poll_interval_ms?: number;
    max_result_bytes?: number;
};
```

### 5. Добавить тесты

#### Python: `tests/test_server_auth.py`

```python
import pytest
from unittest.mock import patch
from httpx import AsyncClient
from policyshield.server.app import app

@pytest.mark.asyncio
async def test_health_no_auth():
    """Health endpoint should always work without auth."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        with patch.dict("os.environ", {"POLICYSHIELD_API_TOKEN": "secret"}):
            r = await client.get("/api/v1/health")
            assert r.status_code == 200

@pytest.mark.asyncio
async def test_check_requires_auth():
    """Check endpoint should require auth when token is set."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        with patch.dict("os.environ", {"POLICYSHIELD_API_TOKEN": "secret"}):
            r = await client.post("/api/v1/check", json={...})
            assert r.status_code == 401

@pytest.mark.asyncio
async def test_check_with_valid_token():
    """Check endpoint should work with valid token."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        with patch.dict("os.environ", {"POLICYSHIELD_API_TOKEN": "secret"}):
            r = await client.post(
                "/api/v1/check",
                json={...},
                headers={"Authorization": "Bearer secret"},
            )
            assert r.status_code == 200

@pytest.mark.asyncio
async def test_no_auth_when_env_not_set():
    """All endpoints should work without auth when env var is not set."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        with patch.dict("os.environ", {}, clear=True):
            r = await client.post("/api/v1/check", json={...})
            assert r.status_code == 200
```

#### TypeScript: обновить `plugins/openclaw/tests/client.test.ts`

```typescript
it("sends Authorization header when api_token is set", async () => {
    const client = new PolicyShieldClient({ api_token: "mytoken" }, mockLogger);
    // Mock fetch and verify headers include Authorization: Bearer mytoken
});

it("does not send Authorization header when api_token is empty", async () => {
    const client = new PolicyShieldClient({}, mockLogger);
    // Mock fetch and verify no Authorization header
});
```

## Самопроверка

```bash
# Python тесты
pytest tests/test_server_auth.py -v
pytest tests/ -q

# TypeScript
cd plugins/openclaw
npx tsc --noEmit
npm test

# Ручная проверка
POLICYSHIELD_API_TOKEN=test123 policyshield server --rules rules.yaml &
curl -sf http://localhost:8100/api/v1/health  # 200 OK
curl -sf http://localhost:8100/api/v1/check   # 401
curl -sf -H "Authorization: Bearer test123" http://localhost:8100/api/v1/check  # 200
```

## Коммит

```
feat(server): add optional Bearer token authentication

- Add POLICYSHIELD_API_TOKEN env var for server auth
- /api/v1/health always public (for Docker/K8s healthchecks)
- All other endpoints require Bearer token when configured
- No auth required when env var is not set (dev mode)
- Add api_token support in OpenClaw plugin client
- Add api_token to openclaw.plugin.json schema
- Add server auth tests (Python) and client auth tests (TypeScript)
```
