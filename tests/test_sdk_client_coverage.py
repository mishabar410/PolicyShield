"""SDK client coverage tests — sync and async clients."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestSyncClientInit:
    def test_init_without_httpx_raises(self):
        with patch("policyshield.sdk.client.HAS_HTTPX", False):
            with pytest.raises(ImportError, match="httpx"):
                from policyshield.sdk.client import PolicyShieldClient

                PolicyShieldClient("http://localhost:8000")

    def test_init_with_token(self):
        from policyshield.sdk.client import PolicyShieldClient

        client = PolicyShieldClient("http://localhost:8000", api_token="test-token")
        assert client._client is not None
        client.close()

    def test_context_manager(self):
        from policyshield.sdk.client import PolicyShieldClient

        with PolicyShieldClient("http://localhost:8000") as client:
            assert client._client is not None


class TestAsyncClientInit:
    def test_init_without_httpx_raises(self):
        with patch("policyshield.sdk.client.HAS_HTTPX", False):
            with pytest.raises(ImportError, match="httpx"):
                from policyshield.sdk.client import AsyncPolicyShieldClient

                AsyncPolicyShieldClient("http://localhost:8000")

    def test_init_with_token(self):
        from policyshield.sdk.client import AsyncPolicyShieldClient

        client = AsyncPolicyShieldClient("http://localhost:8000", api_token="secret")
        assert client._client is not None

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        from policyshield.sdk.client import AsyncPolicyShieldClient

        async with AsyncPolicyShieldClient("http://localhost:8000") as client:
            assert client._client is not None


class TestCheckResult:
    def test_fields(self):
        from policyshield.sdk.client import CheckResult

        r = CheckResult(verdict="BLOCK", message="test", rule_id="r1")
        assert r.verdict == "BLOCK"
        assert r.message == "test"
        assert r.rule_id == "r1"
        assert r.modified_args is None
        assert r.pii_types == []
        assert r.approval_id is None


class TestAsyncClient:
    def test_init_defaults(self):
        from policyshield.async_client import AsyncPolicyShieldClient

        client = AsyncPolicyShieldClient("http://localhost:8000")
        assert client._client is not None
