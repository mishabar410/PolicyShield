# Prompt 351 — Python SDK `PolicyShieldClient`

## Цель

Создать Python SDK-обёртку для HTTP API: `PolicyShieldClient` с `check()`, `post_check()`, `health()`.

## Контекст

- Сейчас нет SDK → разработчики вручную собирают HTTP-запросы
- Нужно: `pip install policyshield` → `from policyshield.client import PolicyShieldClient`

## Что сделать

```python
# policyshield/client.py
"""Python SDK for PolicyShield HTTP API."""
import httpx
from dataclasses import dataclass
from typing import Any

@dataclass
class CheckResult:
    verdict: str
    message: str = ""
    rule_id: str | None = None
    modified_args: dict | None = None
    request_id: str = ""

class PolicyShieldClient:
    """Synchronous PolicyShield HTTP client."""

    def __init__(self, base_url: str = "http://localhost:8000/api/v1", token: str | None = None, timeout: float = 30.0):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(base_url=base_url, headers=headers, timeout=timeout)

    def check(self, tool_name: str, args: dict | None = None, **kwargs) -> CheckResult:
        payload = {"tool_name": tool_name, "args": args or {}, **kwargs}
        resp = self._client.post("/check", json=payload)
        resp.raise_for_status()
        return CheckResult(**resp.json())

    def health(self) -> dict:
        resp = self._client.get("/health")
        resp.raise_for_status()
        return resp.json()

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
```

## Тесты

```python
class TestPolicyShieldClient:
    def test_check_returns_result(self, running_server):
        from policyshield.client import PolicyShieldClient
        with PolicyShieldClient() as client:
            result = client.check("test_tool")
            assert result.verdict in ("ALLOW", "BLOCK")

    def test_health_returns_ok(self, running_server):
        with PolicyShieldClient() as client:
            health = client.health()
            assert health["status"] == "ok"

    def test_auth_token_sent(self):
        # Verify Authorization header
        pass
```

## Самопроверка

```bash
pytest tests/test_dx.py::TestPolicyShieldClient -v
pytest tests/ -q
```

## Коммит

```
feat(sdk): add PolicyShieldClient Python SDK with check/health
```
