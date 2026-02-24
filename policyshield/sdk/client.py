"""PolicyShield Python SDK — httpx-based client for PolicyShield server."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

try:
    import httpx

    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


@dataclass
class CheckResult:
    """Result of a PolicyShield check."""

    verdict: str
    message: str
    rule_id: str | None = None
    modified_args: dict | None = None
    pii_types: list[str] = field(default_factory=list)
    approval_id: str | None = None
    shield_version: str | None = None
    request_id: str | None = None


class PolicyShieldClient:
    """Synchronous Python client for PolicyShield HTTP API.

    Usage:
        with PolicyShieldClient("http://localhost:8100") as client:
            result = client.check("exec_command", {"cmd": "ls"})
            if result.verdict == "BLOCK":
                print("Blocked!")
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8100",
        api_token: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not HAS_HTTPX:
            raise ImportError("PolicyShield SDK requires httpx: pip install httpx")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"
        self._client = httpx.Client(base_url=base_url, headers=headers, timeout=timeout)

    def check(
        self,
        tool_name: str,
        args: dict | None = None,
        session_id: str = "default",
        sender: str | None = None,
    ) -> CheckResult:
        """Check a tool call against security rules."""
        payload: dict[str, Any] = {"tool_name": tool_name, "args": args or {}, "session_id": session_id}
        if sender:
            payload["sender"] = sender
        resp = self._client.post("/api/v1/check", json=payload)
        resp.raise_for_status()
        return CheckResult(**{k: v for k, v in resp.json().items() if k in CheckResult.__dataclass_fields__})

    def post_check(self, tool_name: str, result: str, session_id: str = "default") -> dict:
        """Post-call check on tool output for PII."""
        resp = self._client.post(
            "/api/v1/post-check",
            json={"tool_name": tool_name, "result": result, "session_id": session_id},
        )
        resp.raise_for_status()
        return resp.json()

    def health(self) -> dict:
        """Get server health status."""
        return self._client.get("/api/v1/health").json()

    def kill(self, reason: str = "SDK kill switch") -> dict:
        """Activate kill switch."""
        resp = self._client.post("/api/v1/kill-switch", json={"reason": reason})
        resp.raise_for_status()
        return resp.json()

    def resume(self) -> dict:
        """Deactivate kill switch."""
        resp = self._client.post("/api/v1/resume")
        resp.raise_for_status()
        return resp.json()

    def reload(self) -> dict:
        """Reload rules from disk."""
        resp = self._client.post("/api/v1/reload")
        resp.raise_for_status()
        return resp.json()

    def wait_for_approval(
        self,
        approval_id: str,
        timeout: float = 60.0,
        poll_interval: float = 2.0,
    ) -> dict:
        """Poll approval status until resolved or timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            resp = self._client.get(f"/api/v1/approval/{approval_id}/status")
            data = resp.json()
            if data.get("status") != "pending":
                return data
            time.sleep(poll_interval)
        raise TimeoutError(f"Approval {approval_id} not resolved within {timeout}s")

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> PolicyShieldClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class AsyncPolicyShieldClient:
    """Async Python client for PolicyShield HTTP API.

    Usage:
        async with AsyncPolicyShieldClient("http://localhost:8100") as client:
            result = await client.check("exec_command", {"cmd": "ls"})
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8100",
        api_token: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not HAS_HTTPX:
            raise ImportError("PolicyShield SDK requires httpx: pip install httpx")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"
        self._client = httpx.AsyncClient(base_url=base_url, headers=headers, timeout=timeout)

    async def check(
        self,
        tool_name: str,
        args: dict | None = None,
        session_id: str = "default",
        sender: str | None = None,
    ) -> CheckResult:
        """Check a tool call against security rules."""
        payload: dict[str, Any] = {"tool_name": tool_name, "args": args or {}, "session_id": session_id}
        if sender:
            payload["sender"] = sender
        resp = await self._client.post("/api/v1/check", json=payload)
        resp.raise_for_status()
        return CheckResult(**{k: v for k, v in resp.json().items() if k in CheckResult.__dataclass_fields__})

    async def health(self) -> dict:
        """Get server health status."""
        resp = await self._client.get("/api/v1/health")
        return resp.json()

    async def kill(self, reason: str = "SDK kill switch") -> dict:
        """Activate kill switch."""
        resp = await self._client.post("/api/v1/kill-switch", json={"reason": reason})
        resp.raise_for_status()
        return resp.json()

    async def resume(self) -> dict:
        """Deactivate kill switch."""
        resp = await self._client.post("/api/v1/resume")
        resp.raise_for_status()
        return resp.json()

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AsyncPolicyShieldClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
