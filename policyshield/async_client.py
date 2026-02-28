"""Async Python SDK for PolicyShield HTTP API."""

from __future__ import annotations

import asyncio
import logging

import httpx

from policyshield.client import CheckResult

logger = logging.getLogger("policyshield.async_client")


class AsyncPolicyShieldClient:
    """Async PolicyShield HTTP client for async frameworks (FastAPI, aiohttp).

    Features retry with exponential backoff for transient network errors,
    consistent with the synchronous :class:`PolicyShieldClient`.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000/api/v1",
        token: str | None = None,
        timeout: float = 30.0,
        retries: int = 2,
        backoff_factor: float = 0.5,
    ) -> None:
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(base_url=base_url, headers=headers, timeout=timeout)
        self._retries = retries
        self._backoff_factor = backoff_factor

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Send request with retry + exponential backoff for transient errors."""
        last_exc: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                response = await self._client.request(method, path, **kwargs)
                if response.status_code < 500:
                    return response
                # 5xx — treat as transient, retry
                last_exc = httpx.HTTPStatusError(
                    f"{response.status_code}",
                    request=response.request,
                    response=response,
                )
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.PoolTimeout) as e:
                last_exc = e
            if attempt < self._retries:
                delay = self._backoff_factor * (2 ** attempt)
                logger.warning(
                    "Request %s %s failed (attempt %d/%d): %s — retrying in %.1fs",
                    method, path, attempt + 1, self._retries + 1, last_exc, delay,
                )
                await asyncio.sleep(delay)
        raise last_exc  # type: ignore[misc]

    async def check(self, tool_name: str, args: dict | None = None, **kwargs) -> CheckResult:
        """Async check a tool call against PolicyShield rules."""
        payload = {"tool_name": tool_name, "args": args or {}, **kwargs}
        resp = await self._request("POST", "/check", json=payload)
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
        resp = await self._request("GET", "/health")
        return resp.json()

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AsyncPolicyShieldClient:
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()

