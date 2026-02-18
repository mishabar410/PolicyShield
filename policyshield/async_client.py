"""Async Python SDK for PolicyShield HTTP API."""

from __future__ import annotations

import httpx

from policyshield.client import CheckResult


class AsyncPolicyShieldClient:
    """Async PolicyShield HTTP client for async frameworks (FastAPI, aiohttp)."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000/api/v1",
        token: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(base_url=base_url, headers=headers, timeout=timeout)

    async def check(self, tool_name: str, args: dict | None = None, **kwargs) -> CheckResult:
        """Async check a tool call against PolicyShield rules."""
        payload = {"tool_name": tool_name, "args": args or {}, **kwargs}
        resp = await self._client.post("/check", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return CheckResult(
            verdict=data.get("verdict", ""),
            message=data.get("message", ""),
            rule_id=data.get("rule_id"),
            modified_args=data.get("modified_args"),
            request_id=data.get("request_id", ""),
        )

    async def health(self) -> dict:
        """Check PolicyShield server health."""
        resp = await self._client.get("/health")
        resp.raise_for_status()
        return resp.json()

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AsyncPolicyShieldClient:
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()
