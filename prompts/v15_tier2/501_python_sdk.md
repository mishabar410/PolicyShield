# 501 — Python SDK Client

## Goal

Create `PolicyShieldClient` — a thin httpx-based SDK for calling PolicyShield server over HTTP.

## Context

- Current usage requires raw HTTP calls or `TestClient`
- Need proper async/sync client with type hints
- Should mirror server API (`check`, `post_check`, `health`, `kill`, `resume`, `reload`)

## Code

### New file: `policyshield/sdk/client.py`

```python
"""PolicyShield Python SDK — httpx-based client."""
import httpx
from dataclasses import dataclass

@dataclass
class CheckResult:
    verdict: str
    message: str
    rule_id: str | None = None
    modified_args: dict | None = None
    pii_types: list[str] | None = None
    approval_id: str | None = None

class PolicyShieldClient:
    def __init__(self, base_url: str = "http://localhost:8100", api_token: str | None = None, timeout: float = 30.0):
        headers = {}
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"
        self._client = httpx.Client(base_url=base_url, headers=headers, timeout=timeout)

    def check(self, tool_name: str, args: dict | None = None, session_id: str = "default") -> CheckResult:
        resp = self._client.post("/api/v1/check", json={"tool_name": tool_name, "args": args or {}, "session_id": session_id})
        resp.raise_for_status()
        return CheckResult(**resp.json())

    def health(self) -> dict:
        return self._client.get("/api/v1/health").json()

    def kill(self, reason: str = "SDK kill") -> dict:
        return self._client.post("/api/v1/kill-switch", json={"reason": reason}).json()

    def resume(self) -> dict:
        return self._client.post("/api/v1/resume").json()

    def reload(self) -> dict:
        return self._client.post("/api/v1/reload").json()

    def wait_for_approval(self, approval_id: str, timeout: float = 60.0, poll_interval: float = 2.0) -> dict:
        """Poll approval status until resolved or timeout."""
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            resp = self._client.get(f"/api/v1/approval/{approval_id}/status")
            data = resp.json()
            if data.get("status") != "pending":
                return data
            time.sleep(poll_interval)
        raise TimeoutError(f"Approval {approval_id} not resolved within {timeout}s")

    def close(self):
        self._client.close()

    def __enter__(self): return self
    def __exit__(self, *a): self.close()
```

### New file: `policyshield/sdk/async_client.py`

Same as above but with `httpx.AsyncClient` and `async def` methods.

### New file: `policyshield/sdk/__init__.py`

```python
from policyshield.sdk.client import PolicyShieldClient, CheckResult
```

## Tests

### `tests/test_sdk_client.py`

- Test `check()` returns `CheckResult` with correct verdict
- Test `health()` returns dict with "status" key
- Test `wait_for_approval()` with mock server
- Test auth header included when `api_token` set
- Test context manager (`with PolicyShieldClient() as c:`)

## Self-check

```bash
ruff check policyshield/sdk/ tests/test_sdk_client.py
pytest tests/test_sdk_client.py -v
```

## Commit

```
feat(sdk): add PolicyShieldClient Python SDK with sync/async support
```
