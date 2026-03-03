"""Tests for critical issue fixes — covers new methods added in fixes #154-#200."""

from __future__ import annotations

import asyncio
import threading

import httpx
import pytest

from policyshield.async_client import AsyncPolicyShieldClient
from policyshield.client import CheckResult, PolicyShieldClient
from policyshield.core.models import PIIType
from policyshield.shield.session import SessionManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(status_code: int = 200, json_data: dict | None = None) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        json=json_data or {},
        request=httpx.Request("POST", "http://test/api/v1/check"),
    )


# ---------------------------------------------------------------------------
# CheckResult alignment (#155)
# ---------------------------------------------------------------------------


class TestCheckResultAlignment:
    def test_check_result_has_new_fields(self):
        r = CheckResult(verdict="ALLOW")
        assert r.pii_types == []
        assert r.approval_id is None
        assert r.shield_version is None

    def test_check_result_with_all_fields(self):
        r = CheckResult(
            verdict="BLOCK",
            message="blocked",
            rule_id="r1",
            pii_types=["email", "phone"],
            approval_id="ap-123",
            shield_version="1.0.0",
            request_id="req-1",
        )
        assert r.pii_types == ["email", "phone"]
        assert r.approval_id == "ap-123"
        assert r.shield_version == "1.0.0"


# ---------------------------------------------------------------------------
# Sync client new methods (#155)
# ---------------------------------------------------------------------------


class TestSyncClientNewMethods:
    def test_post_check(self, monkeypatch):
        def mock_request(self, method, path, **kwargs):
            assert method == "POST"
            assert path == "/post-check"
            return _mock_response(200, {"pii_detected": False})

        monkeypatch.setattr(PolicyShieldClient, "_request", mock_request)
        client = PolicyShieldClient()
        result = client.post_check("send_data", "some output")
        assert result == {"pii_detected": False}
        client.close()

    def test_kill(self, monkeypatch):
        def mock_request(self, method, path, **kwargs):
            assert method == "POST"
            assert path == "/kill"
            return _mock_response(200, {"status": "killed"})

        monkeypatch.setattr(PolicyShieldClient, "_request", mock_request)
        client = PolicyShieldClient()
        result = client.kill("test reason")
        assert result["status"] == "killed"
        client.close()

    def test_resume(self, monkeypatch):
        def mock_request(self, method, path, **kwargs):
            assert method == "POST"
            assert path == "/resume"
            return _mock_response(200, {"status": "resumed"})

        monkeypatch.setattr(PolicyShieldClient, "_request", mock_request)
        client = PolicyShieldClient()
        result = client.resume()
        assert result["status"] == "resumed"
        client.close()

    def test_reload(self, monkeypatch):
        def mock_request(self, method, path, **kwargs):
            assert method == "POST"
            assert path == "/reload"
            return _mock_response(200, {"status": "reloaded"})

        monkeypatch.setattr(PolicyShieldClient, "_request", mock_request)
        client = PolicyShieldClient()
        result = client.reload()
        assert result["status"] == "reloaded"
        client.close()

    def test_wait_for_approval_resolved(self, monkeypatch):
        call_count = 0

        def mock_request(self, method, path, **kwargs):
            nonlocal call_count
            call_count += 1
            assert method == "POST"
            assert path == "/check-approval"
            if call_count < 2:
                return _mock_response(200, {"status": "pending"})
            return _mock_response(200, {"status": "approved"})

        monkeypatch.setattr(PolicyShieldClient, "_request", mock_request)
        client = PolicyShieldClient()
        result = client.wait_for_approval("ap-1", timeout=5.0, poll_interval=0.01)
        assert result["status"] == "approved"
        assert call_count == 2
        client.close()

    def test_wait_for_approval_timeout(self, monkeypatch):
        def mock_request(self, method, path, **kwargs):
            return _mock_response(200, {"status": "pending"})

        monkeypatch.setattr(PolicyShieldClient, "_request", mock_request)
        client = PolicyShieldClient()
        with pytest.raises(TimeoutError):
            client.wait_for_approval("ap-1", timeout=0.05, poll_interval=0.01)
        client.close()

    def test_check_filters_unknown_fields(self, monkeypatch):
        """check() should not crash on unknown fields from server response."""
        def mock_request(self, method, path, **kwargs):
            return _mock_response(200, {
                "verdict": "ALLOW",
                "message": "ok",
                "unknown_field": "should_be_ignored",
            })

        monkeypatch.setattr(PolicyShieldClient, "_request", mock_request)
        client = PolicyShieldClient()
        result = client.check("read_file")
        assert result.verdict == "ALLOW"
        client.close()


# ---------------------------------------------------------------------------
# Async client new methods (#155)
# ---------------------------------------------------------------------------


class TestAsyncClientNewMethods:
    @pytest.mark.asyncio
    async def test_post_check(self, monkeypatch):
        async def mock_request(self, method, path, **kwargs):
            assert path == "/post-check"
            return _mock_response(200, {"pii_detected": False})

        monkeypatch.setattr(AsyncPolicyShieldClient, "_request", mock_request)
        async with AsyncPolicyShieldClient() as client:
            result = await client.post_check("send_data", "output")
            assert result == {"pii_detected": False}

    @pytest.mark.asyncio
    async def test_kill(self, monkeypatch):
        async def mock_request(self, method, path, **kwargs):
            return _mock_response(200, {"status": "killed"})

        monkeypatch.setattr(AsyncPolicyShieldClient, "_request", mock_request)
        async with AsyncPolicyShieldClient() as client:
            result = await client.kill()
            assert result["status"] == "killed"

    @pytest.mark.asyncio
    async def test_resume(self, monkeypatch):
        async def mock_request(self, method, path, **kwargs):
            return _mock_response(200, {"status": "resumed"})

        monkeypatch.setattr(AsyncPolicyShieldClient, "_request", mock_request)
        async with AsyncPolicyShieldClient() as client:
            result = await client.resume()
            assert result["status"] == "resumed"

    @pytest.mark.asyncio
    async def test_reload(self, monkeypatch):
        async def mock_request(self, method, path, **kwargs):
            return _mock_response(200, {"status": "reloaded"})

        monkeypatch.setattr(AsyncPolicyShieldClient, "_request", mock_request)
        async with AsyncPolicyShieldClient() as client:
            result = await client.reload()
            assert result["status"] == "reloaded"

    @pytest.mark.asyncio
    async def test_wait_for_approval_resolved(self, monkeypatch):
        call_count = 0

        async def mock_request(self, method, path, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                return _mock_response(200, {"status": "pending"})
            return _mock_response(200, {"status": "approved"})

        monkeypatch.setattr(AsyncPolicyShieldClient, "_request", mock_request)
        async with AsyncPolicyShieldClient() as client:
            result = await client.wait_for_approval("ap-1", timeout=5.0, poll_interval=0.01)
            assert result["status"] == "approved"

    @pytest.mark.asyncio
    async def test_wait_for_approval_timeout(self, monkeypatch):
        async def mock_request(self, method, path, **kwargs):
            return _mock_response(200, {"status": "pending"})

        monkeypatch.setattr(AsyncPolicyShieldClient, "_request", mock_request)
        async with AsyncPolicyShieldClient() as client:
            with pytest.raises(TimeoutError):
                await client.wait_for_approval("ap-1", timeout=0.05, poll_interval=0.01)


# ---------------------------------------------------------------------------
# SessionManager.clear_taint (#199)
# ---------------------------------------------------------------------------


class TestSessionManagerClearTaint:
    def test_clear_taint_existing_session(self):
        mgr = SessionManager()
        mgr.add_taint("s1", PIIType.EMAIL)
        session = mgr.get("s1")
        assert session is not None
        assert len(session.taints) > 0

        result = mgr.clear_taint("s1")
        assert result is True

        session = mgr.get("s1")
        assert session is not None
        assert len(session.taints) == 0

    def test_clear_taint_nonexistent_session(self):
        mgr = SessionManager()
        result = mgr.clear_taint("nonexistent")
        assert result is False

    def test_clear_taint_thread_safety(self):
        """Verify clear_taint is thread-safe under concurrent add_taint."""
        mgr = SessionManager()
        mgr.get_or_create("s1")
        errors = []

        def add_taints():
            try:
                for _ in range(100):
                    mgr.add_taint("s1", PIIType.EMAIL)
            except Exception as e:
                errors.append(e)

        def clear_taints():
            try:
                for _ in range(100):
                    mgr.clear_taint("s1")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=add_taints),
            threading.Thread(target=clear_taints),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []


# ---------------------------------------------------------------------------
# SDK client sync (#155, #156)
# ---------------------------------------------------------------------------


class TestSDKClientSync:
    def test_wait_for_approval_resolved(self, monkeypatch):
        from policyshield.sdk.client import PolicyShieldClient as SDKClient

        call_count = 0

        def mock_post(self, url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                return httpx.Response(200, json={"status": "pending"}, request=httpx.Request("POST", url))
            return httpx.Response(200, json={"status": "approved"}, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.Client, "post", mock_post)
        client = SDKClient(base_url="http://localhost:8000")
        result = client.wait_for_approval("ap-1", timeout=5.0, poll_interval=0.01)
        assert result["status"] == "approved"
        client.close()

    def test_wait_for_approval_timeout(self, monkeypatch):
        from policyshield.sdk.client import PolicyShieldClient as SDKClient

        def mock_post(self, url, **kwargs):
            return httpx.Response(200, json={"status": "pending"}, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.Client, "post", mock_post)
        client = SDKClient(base_url="http://localhost:8000")
        with pytest.raises(TimeoutError):
            client.wait_for_approval("ap-1", timeout=0.05, poll_interval=0.01)
        client.close()

    def test_kill(self, monkeypatch):
        from policyshield.sdk.client import PolicyShieldClient as SDKClient

        def mock_post(self, url, **kwargs):
            return httpx.Response(200, json={"status": "killed"}, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.Client, "post", mock_post)
        client = SDKClient(base_url="http://localhost:8000")
        result = client.kill("test")
        assert result["status"] == "killed"
        client.close()

    def test_resume(self, monkeypatch):
        from policyshield.sdk.client import PolicyShieldClient as SDKClient

        def mock_post(self, url, **kwargs):
            return httpx.Response(200, json={"status": "resumed"}, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.Client, "post", mock_post)
        client = SDKClient(base_url="http://localhost:8000")
        result = client.resume()
        assert result["status"] == "resumed"
        client.close()

    def test_post_check(self, monkeypatch):
        from policyshield.sdk.client import PolicyShieldClient as SDKClient

        def mock_post(self, url, **kwargs):
            return httpx.Response(200, json={"pii_detected": False}, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.Client, "post", mock_post)
        client = SDKClient(base_url="http://localhost:8000")
        result = client.post_check("tool", "output")
        assert result["pii_detected"] is False
        client.close()

    def test_reload(self, monkeypatch):
        from policyshield.sdk.client import PolicyShieldClient as SDKClient

        def mock_post(self, url, **kwargs):
            return httpx.Response(200, json={"status": "reloaded"}, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.Client, "post", mock_post)
        client = SDKClient(base_url="http://localhost:8000")
        result = client.reload()
        assert result["status"] == "reloaded"
        client.close()


# ---------------------------------------------------------------------------
# SDK client async (#155, #156)
# ---------------------------------------------------------------------------


class TestSDKClientAsync:
    @pytest.mark.asyncio
    async def test_wait_for_approval_resolved(self, monkeypatch):
        from policyshield.sdk.client import AsyncPolicyShieldClient as SDKAsyncClient

        call_count = 0

        async def mock_post(self, url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                return httpx.Response(200, json={"status": "pending"}, request=httpx.Request("POST", url))
            return httpx.Response(200, json={"status": "approved"}, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        async with SDKAsyncClient(base_url="http://localhost:8000") as client:
            result = await client.wait_for_approval("ap-1", timeout=5.0, poll_interval=0.01)
            assert result["status"] == "approved"

    @pytest.mark.asyncio
    async def test_wait_for_approval_timeout(self, monkeypatch):
        from policyshield.sdk.client import AsyncPolicyShieldClient as SDKAsyncClient

        async def mock_post(self, url, **kwargs):
            return httpx.Response(200, json={"status": "pending"}, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        async with SDKAsyncClient(base_url="http://localhost:8000") as client:
            with pytest.raises(TimeoutError):
                await client.wait_for_approval("ap-1", timeout=0.05, poll_interval=0.01)

    @pytest.mark.asyncio
    async def test_kill(self, monkeypatch):
        from policyshield.sdk.client import AsyncPolicyShieldClient as SDKAsyncClient

        async def mock_post(self, url, **kwargs):
            return httpx.Response(200, json={"status": "killed"}, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        async with SDKAsyncClient(base_url="http://localhost:8000") as client:
            result = await client.kill("test")
            assert result["status"] == "killed"

    @pytest.mark.asyncio
    async def test_resume(self, monkeypatch):
        from policyshield.sdk.client import AsyncPolicyShieldClient as SDKAsyncClient

        async def mock_post(self, url, **kwargs):
            return httpx.Response(200, json={"status": "resumed"}, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        async with SDKAsyncClient(base_url="http://localhost:8000") as client:
            result = await client.resume()
            assert result["status"] == "resumed"

    @pytest.mark.asyncio
    async def test_post_check(self, monkeypatch):
        from policyshield.sdk.client import AsyncPolicyShieldClient as SDKAsyncClient

        async def mock_post(self, url, **kwargs):
            return httpx.Response(200, json={"pii_detected": False}, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        async with SDKAsyncClient(base_url="http://localhost:8000") as client:
            result = await client.post_check("tool", "output")
            assert result["pii_detected"] is False

    @pytest.mark.asyncio
    async def test_reload(self, monkeypatch):
        from policyshield.sdk.client import AsyncPolicyShieldClient as SDKAsyncClient

        async def mock_post(self, url, **kwargs):
            return httpx.Response(200, json={"status": "reloaded"}, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
        async with SDKAsyncClient(base_url="http://localhost:8000") as client:
            result = await client.reload()
            assert result["status"] == "reloaded"

