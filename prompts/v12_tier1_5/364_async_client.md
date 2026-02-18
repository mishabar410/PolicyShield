# Prompt 364 — AsyncPolicyShieldClient

## Цель

Добавить async-версию SDK клиента на основе `httpx.AsyncClient`.

## Контекст

- Sync клиент (#351) не подходит для async frameworks (FastAPI, aiohttp)
- Нужно: `AsyncPolicyShieldClient` с тем же API, но `async def check()` и т.д.

## Что сделать

```python
# policyshield/async_client.py
"""Async Python SDK for PolicyShield HTTP API."""
import httpx
from policyshield.client import CheckResult

class AsyncPolicyShieldClient:
    """Async PolicyShield HTTP client."""

    def __init__(self, base_url: str = "http://localhost:8000/api/v1", token: str | None = None, timeout: float = 30.0):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(base_url=base_url, headers=headers, timeout=timeout)

    async def check(self, tool_name: str, args: dict | None = None, **kwargs) -> CheckResult:
        payload = {"tool_name": tool_name, "args": args or {}, **kwargs}
        resp = await self._client.post("/check", json=payload)
        resp.raise_for_status()
        return CheckResult(**resp.json())

    async def health(self) -> dict:
        resp = await self._client.get("/health")
        resp.raise_for_status()
        return resp.json()

    async def close(self):
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
```

## Тесты

```python
class TestAsyncClient:
    @pytest.mark.asyncio
    async def test_async_check(self, running_server):
        from policyshield.async_client import AsyncPolicyShieldClient
        async with AsyncPolicyShieldClient() as client:
            result = await client.check("test_tool")
            assert result.verdict in ("ALLOW", "BLOCK")

    @pytest.mark.asyncio
    async def test_async_health(self, running_server):
        async with AsyncPolicyShieldClient() as client:
            health = await client.health()
            assert health["status"] == "ok"
```

## Коммит

```
feat(sdk): add AsyncPolicyShieldClient for async frameworks
```
