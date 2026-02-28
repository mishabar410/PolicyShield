"""Tests for AsyncPolicyShieldClient."""

from __future__ import annotations

import pytest
import httpx

from policyshield.async_client import AsyncPolicyShieldClient
from policyshield.client import CheckResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(status_code: int = 200, json_data: dict | None = None) -> httpx.Response:
    """Create a mock httpx.Response."""
    return httpx.Response(
        status_code=status_code,
        json=json_data or {},
        request=httpx.Request("POST", "http://test/api/v1/check"),
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_init_defaults():
    async with AsyncPolicyShieldClient() as client:
        assert client._retries == 2
        assert client._backoff_factor == 0.5


@pytest.mark.asyncio
async def test_init_with_token():
    async with AsyncPolicyShieldClient(token="secret") as client:
        assert client._client.headers["authorization"] == "Bearer secret"


@pytest.mark.asyncio
async def test_init_without_token():
    async with AsyncPolicyShieldClient() as client:
        assert "authorization" not in client._client.headers


# ---------------------------------------------------------------------------
# check()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_success(monkeypatch):
    response_data = {
        "verdict": "ALLOW",
        "message": "ok",
        "rule_id": "r1",
        "modified_args": None,
        "request_id": "req-1",
    }

    async def mock_request(self, method, path, **kwargs):
        return _mock_response(200, response_data)

    monkeypatch.setattr(AsyncPolicyShieldClient, "_request", mock_request)

    async with AsyncPolicyShieldClient() as client:
        result = await client.check("read_file", {"path": "/etc/passwd"})
        assert isinstance(result, CheckResult)
        assert result.verdict == "ALLOW"
        assert result.message == "ok"
        assert result.rule_id == "r1"
        assert result.request_id == "req-1"


@pytest.mark.asyncio
async def test_check_block(monkeypatch):
    response_data = {"verdict": "BLOCK", "message": "blocked", "rule_id": "r2"}

    async def mock_request(self, method, path, **kwargs):
        return _mock_response(200, response_data)

    monkeypatch.setattr(AsyncPolicyShieldClient, "_request", mock_request)

    async with AsyncPolicyShieldClient() as client:
        result = await client.check("exec", {"cmd": "rm -rf /"})
        assert result.verdict == "BLOCK"


# ---------------------------------------------------------------------------
# health()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health(monkeypatch):
    async def mock_request(self, method, path, **kwargs):
        return _mock_response(200, {"status": "ok"})

    monkeypatch.setattr(AsyncPolicyShieldClient, "_request", mock_request)

    async with AsyncPolicyShieldClient() as client:
        result = await client.health()
        assert result == {"status": "ok"}


# ---------------------------------------------------------------------------
# _request retry logic
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_retries_on_5xx(monkeypatch):
    call_count = 0

    async def mock_send(self, request, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            return httpx.Response(500, request=request, json={"error": "server"})
        return httpx.Response(200, request=request, json={"ok": True})

    monkeypatch.setattr(httpx.AsyncClient, "send", mock_send)

    async with AsyncPolicyShieldClient(retries=2, backoff_factor=0.01) as client:
        resp = await client._request("GET", "/health")
        assert resp.status_code == 200
        assert call_count == 3


@pytest.mark.asyncio
async def test_request_no_retry_on_4xx(monkeypatch):
    call_count = 0

    async def mock_send(self, request, **kwargs):
        nonlocal call_count
        call_count += 1
        return httpx.Response(403, request=request, json={"error": "forbidden"})

    monkeypatch.setattr(httpx.AsyncClient, "send", mock_send)

    async with AsyncPolicyShieldClient(retries=2, backoff_factor=0.01) as client:
        resp = await client._request("GET", "/health")
        assert resp.status_code == 403
        assert call_count == 1  # No retries for 4xx


@pytest.mark.asyncio
async def test_request_retries_on_connect_error(monkeypatch):
    call_count = 0

    async def mock_send(self, request, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise httpx.ConnectError("connection refused")
        return httpx.Response(200, request=request, json={"ok": True})

    monkeypatch.setattr(httpx.AsyncClient, "send", mock_send)

    async with AsyncPolicyShieldClient(retries=2, backoff_factor=0.01) as client:
        resp = await client._request("GET", "/health")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_request_raises_after_retries_exhausted(monkeypatch):
    async def mock_send(self, request, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx.AsyncClient, "send", mock_send)

    async with AsyncPolicyShieldClient(retries=1, backoff_factor=0.01) as client:
        with pytest.raises(httpx.ConnectError):
            await client._request("GET", "/health")


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_context_manager():
    client = AsyncPolicyShieldClient()
    async with client as c:
        assert c is client
    # Client should be closed after context exit
    assert client._client.is_closed
