"""Python SDK for PolicyShield HTTP API."""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx


@dataclass
class CheckResult:
    """Result of a PolicyShield check."""

    verdict: str
    message: str = ""
    rule_id: str | None = None
    modified_args: dict | None = None
    request_id: str = ""


class PolicyShieldClient:
    """Synchronous PolicyShield HTTP client with retry and backoff."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000/api/v1",
        token: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ) -> None:
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(base_url=base_url, headers=headers, timeout=timeout)
        self._max_retries = max_retries
        self._backoff = backoff_factor

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                resp = self._client.request(method, path, **kwargs)
                if resp.status_code < 500:
                    return resp
                last_exc = httpx.HTTPStatusError(
                    f"{resp.status_code}",
                    request=resp.request,
                    response=resp,
                )
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                last_exc = e
            if attempt < self._max_retries:
                delay = self._backoff * (2**attempt)
                time.sleep(delay)
        raise last_exc  # type: ignore[misc]

    def check(self, tool_name: str, args: dict | None = None, **kwargs) -> CheckResult:
        """Check a tool call against PolicyShield rules."""
        payload = {"tool_name": tool_name, "args": args or {}, **kwargs}
        resp = self._request("POST", "/check", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return CheckResult(
            verdict=data.get("verdict", ""),
            message=data.get("message", ""),
            rule_id=data.get("rule_id"),
            modified_args=data.get("modified_args"),
            request_id=data.get("request_id", ""),
        )

    def health(self) -> dict:
        """Check PolicyShield server health."""
        resp = self._request("GET", "/health")
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> PolicyShieldClient:
        return self

    def __exit__(self, *args) -> None:
        self.close()
