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
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        retries: int | None = None,  # Deprecated alias
    ) -> None:
        # Issue #119/#135: Unify retry params with sync client
        if retries is not None:
            import warnings

            warnings.warn(
                "'retries' is deprecated, use 'max_retries'",
                DeprecationWarning,
                stacklevel=2,
            )
            max_retries = retries
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(base_url=base_url, headers=headers, timeout=timeout)
        self._retries = max_retries
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
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                last_exc = e
            if attempt < self._retries:
                delay = self._backoff_factor * (2**attempt)
                logger.warning(
                    "Request %s %s failed (attempt %d/%d): %s — retrying in %.1fs",
                    method,
                    path,
                    attempt + 1,
                    self._retries + 1,
                    last_exc,
                    delay,
                )
                await asyncio.sleep(delay)
        raise last_exc  # type: ignore[misc]

    async def check(self, tool_name: str, args: dict | None = None, **kwargs) -> CheckResult:
        """Async check a tool call against PolicyShield rules."""
        payload = {"tool_name": tool_name, "args": args or {}, **kwargs}
        resp = await self._request("POST", "/check", json=payload)
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
        resp = await self._request("GET", "/health")
        resp.raise_for_status()
        return resp.json()

    async def close(self) -> None:
        await self._client.aclose()

    async def post_check(self, tool_name: str, result: str, session_id: str = "default") -> dict:
        """Post-call check on tool output for PII."""
        resp = await self._request(
            "POST",
            "/post-check",
            json={"tool_name": tool_name, "result": result, "session_id": session_id},
        )
        resp.raise_for_status()
        return resp.json()

    async def kill(self, reason: str = "SDK kill switch") -> dict:
        """Activate kill switch."""
        resp = await self._request("POST", "/kill", json={"reason": reason})
        resp.raise_for_status()
        return resp.json()

    async def resume(self) -> dict:
        """Deactivate kill switch."""
        resp = await self._request("POST", "/resume")
        resp.raise_for_status()
        return resp.json()

    async def reload(self) -> dict:
        """Reload rules from disk."""
        resp = await self._request("POST", "/reload")
        resp.raise_for_status()
        return resp.json()

    async def wait_for_approval(
        self,
        approval_id: str,
        timeout: float = 60.0,
        poll_interval: float = 2.0,
    ) -> dict:
        """Poll approval status until resolved or timeout."""
        import time

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            resp = await self._request(
                "POST",
                "/check-approval",
                json={"approval_id": approval_id},
            )
            data = resp.json()
            if data.get("status") != "pending":
                return data
            await asyncio.sleep(poll_interval)
        raise TimeoutError(f"Approval {approval_id} not resolved within {timeout}s")

    async def __aenter__(self) -> AsyncPolicyShieldClient:
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()
