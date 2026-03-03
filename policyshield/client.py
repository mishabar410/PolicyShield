"""Python SDK for PolicyShield HTTP API."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx


@dataclass
class CheckResult:
    """Result of a PolicyShield check."""

    verdict: str
    message: str = ""
    rule_id: str | None = None
    modified_args: dict | None = None
    pii_types: list[str] = field(default_factory=list)
    approval_id: str | None = None
    shield_version: str | None = None
    request_id: str = ""


class PolicyShieldClient:
    """Synchronous PolicyShield HTTP client with retry and backoff.

    Recommended usage as context manager to ensure proper cleanup::

        with PolicyShieldClient(token="...") as client:
            result = client.check("tool_name", {"arg": "value"})

    If used without ``with``, call :meth:`close` explicitly when done.
    """

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
        return CheckResult(**{k: v for k, v in resp.json().items() if k in CheckResult.__dataclass_fields__})

    def post_check(self, tool_name: str, result: str, session_id: str = "default") -> dict:
        """Post-call check on tool output for PII."""
        resp = self._request(
            "POST",
            "/post-check",
            json={"tool_name": tool_name, "result": result, "session_id": session_id},
        )
        resp.raise_for_status()
        return resp.json()

    def health(self) -> dict:
        """Check PolicyShield server health."""
        resp = self._request("GET", "/health")
        resp.raise_for_status()
        return resp.json()

    def kill(self, reason: str = "SDK kill switch") -> dict:
        """Activate kill switch."""
        resp = self._request("POST", "/kill", json={"reason": reason})
        resp.raise_for_status()
        return resp.json()

    def resume(self) -> dict:
        """Deactivate kill switch."""
        resp = self._request("POST", "/resume")
        resp.raise_for_status()
        return resp.json()

    def reload(self) -> dict:
        """Reload rules from disk."""
        resp = self._request("POST", "/reload")
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
            resp = self._request(
                "POST",
                "/check-approval",
                json={"approval_id": approval_id},
            )
            data = resp.json()
            if data.get("status") != "pending":
                return data
            time.sleep(poll_interval)
        raise TimeoutError(f"Approval {approval_id} not resolved within {timeout}s")

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> PolicyShieldClient:
        return self

    def __exit__(self, *args) -> None:
        self.close()
