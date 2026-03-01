"""Targeted coverage tests for Phase 10 modules.

Focuses on uncovered lines in compiler, webhook, client, context, and engine.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from policyshield.ai.compiler import PolicyCompiler
from policyshield.shield.context import ContextEvaluator


# ---------------------------------------------------------------------------
# compiler.py — compile(), compile_sync(), _call_llm()
# ---------------------------------------------------------------------------


class TestCompilerCompile:
    def test_compile_success_first_try(self):
        compiler = PolicyCompiler(api_key="test", max_retries=2)

        valid_yaml = "shield_name: test\nversion: 1\nrules:\n  - id: r1\n    when:\n      tool: exec\n    then: BLOCK\n"

        async def fake_call_llm(desc, errors):
            return valid_yaml

        compiler._call_llm = fake_call_llm  # type: ignore
        result = asyncio.run(compiler.compile("Block exec"))
        assert result.is_valid is True
        assert result.attempts == 1
        assert "shield_name" in result.yaml_text

    def test_compile_retries_on_validation_error(self):
        compiler = PolicyCompiler(api_key="test", max_retries=2)
        calls = []

        async def fake_call_llm(desc, errors):
            calls.append(errors)
            if len(calls) == 1:
                return "invalid yaml {"
            return "shield_name: test\nversion: 1\nrules:\n  - id: r1\n    when:\n      tool: exec\n    then: BLOCK\n"

        compiler._call_llm = fake_call_llm  # type: ignore
        result = asyncio.run(compiler.compile("Block exec"))
        assert result.is_valid is True
        assert result.attempts == 2
        assert len(calls) == 2
        assert len(calls[1]) > 0  # Second call got errors from first

    def test_compile_all_retries_fail(self):
        compiler = PolicyCompiler(api_key="test", max_retries=2)

        async def fake_call_llm(desc, errors):
            return "not: valid\nyaml: at all\n"

        compiler._call_llm = fake_call_llm  # type: ignore
        result = asyncio.run(compiler.compile("Don't care"))
        assert result.is_valid is False
        assert result.attempts == 2
        assert len(result.errors) > 0

    def test_compile_llm_error(self):
        compiler = PolicyCompiler(api_key="test", max_retries=2)

        async def fake_call_llm(desc, errors):
            raise ConnectionError("LLM down")

        compiler._call_llm = fake_call_llm  # type: ignore
        result = asyncio.run(compiler.compile("Block exec"))
        assert result.is_valid is False
        assert "LLM call failed" in result.errors[0]

    def test_compile_sync(self):
        compiler = PolicyCompiler(api_key="test", max_retries=1)
        valid_yaml = "shield_name: test\nversion: 1\nrules:\n  - id: r1\n    when:\n      tool: exec\n    then: BLOCK\n"

        async def fake_call_llm(desc, errors):
            return valid_yaml

        compiler._call_llm = fake_call_llm  # type: ignore
        result = compiler.compile_sync("Block exec")
        assert result.is_valid is True


# ---------------------------------------------------------------------------
# webhook.py — WebhookNotifier
# ---------------------------------------------------------------------------


class TestWebhookNotifier:
    def test_notify_matching_event(self):
        from policyshield.server.webhook import WebhookNotifier

        notifier = WebhookNotifier(url="http://example.com/hook")
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))
        notifier._client = mock_client

        asyncio.run(notifier.notify("BLOCK", "exec", {"msg": "blocked"}))
        mock_client.post.assert_called_once()
        payload = mock_client.post.call_args[1]["json"]
        assert payload["verdict"] == "BLOCK"
        assert payload["tool_name"] == "exec"

    def test_notify_non_matching_event_skips(self):
        from policyshield.server.webhook import WebhookNotifier

        notifier = WebhookNotifier(url="http://example.com/hook", events=["BLOCK"])
        mock_client = AsyncMock()
        notifier._client = mock_client

        asyncio.run(notifier.notify("ALLOW", "exec", {}))
        mock_client.post.assert_not_called()

    def test_notify_handles_error(self):
        from policyshield.server.webhook import WebhookNotifier

        notifier = WebhookNotifier(url="http://example.com/hook")
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=ConnectionError("fail"))
        notifier._client = mock_client

        # Should not raise
        asyncio.run(notifier.notify("BLOCK", "exec", {}))

    def test_close(self):
        from policyshield.server.webhook import WebhookNotifier

        notifier = WebhookNotifier(url="http://example.com/hook")
        mock_client = AsyncMock()
        notifier._client = mock_client

        asyncio.run(notifier.close())
        mock_client.aclose.assert_called_once()


# ---------------------------------------------------------------------------
# client.py — PolicyShieldClient
# ---------------------------------------------------------------------------


class TestPolicyShieldClient:
    def test_init_with_token(self):
        from policyshield.client import PolicyShieldClient

        client = PolicyShieldClient(token="test-token")
        assert "Authorization" in client._client.headers
        client.close()

    def test_init_without_token(self):
        from policyshield.client import PolicyShieldClient

        client = PolicyShieldClient()
        assert "Authorization" not in client._client.headers
        client.close()

    def test_context_manager(self):
        from policyshield.client import PolicyShieldClient

        with PolicyShieldClient() as client:
            assert client is not None

    def test_check_result_dataclass(self):
        from policyshield.client import CheckResult

        r = CheckResult(verdict="ALLOW", message="ok", rule_id="r1")
        assert r.verdict == "ALLOW"
        assert r.modified_args is None

    def test_check_calls_api(self):
        from policyshield.client import PolicyShieldClient

        client = PolicyShieldClient()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "verdict": "ALLOW",
            "message": "ok",
            "rule_id": "r1",
            "request_id": "req123",
        }
        mock_response.raise_for_status = MagicMock()
        client._client.request = MagicMock(return_value=mock_response)

        result = client.check("read_file", {"path": "/tmp/test"})
        assert result.verdict == "ALLOW"
        assert result.request_id == "req123"
        client.close()

    def test_health_calls_api(self):
        from policyshield.client import PolicyShieldClient

        client = PolicyShieldClient()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_response.raise_for_status = MagicMock()
        client._client.request = MagicMock(return_value=mock_response)

        result = client.health()
        assert result == {"status": "ok"}
        client.close()

    def test_retry_on_server_error(self):
        from policyshield.client import PolicyShieldClient

        client = PolicyShieldClient(max_retries=1, backoff_factor=0.01)
        error_resp = MagicMock()
        error_resp.status_code = 500
        error_resp.request = MagicMock()
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        client._client.request = MagicMock(side_effect=[error_resp, ok_resp])

        result = client._request("GET", "/health")
        assert result.status_code == 200
        client.close()


# ---------------------------------------------------------------------------
# context.py — uncovered edge cases
# ---------------------------------------------------------------------------


class TestContextEdgeCases:
    def test_invalid_time_spec(self):
        ev = ContextEvaluator()
        # Invalid spec (no dash) → fail-open → True
        assert ev._check_time("1234") is True

    def test_overnight_range(self):
        ev = ContextEvaluator()
        with patch.object(ev, "_now") as mock_now:
            from datetime import datetime
            from zoneinfo import ZoneInfo

            mock_now.return_value = datetime(2024, 1, 1, 23, 0, tzinfo=ZoneInfo("UTC"))
            assert ev._check_time("22:00-06:00") is True
            mock_now.return_value = datetime(2024, 1, 1, 12, 0, tzinfo=ZoneInfo("UTC"))
            assert ev._check_time("22:00-06:00") is False

    def test_day_wrap_range(self):
        ev = ContextEvaluator()
        with patch.object(ev, "_now") as mock_now:
            from datetime import datetime
            from zoneinfo import ZoneInfo

            # "Fri-Mon" should include Sun
            mock_now.return_value = datetime(2024, 1, 7, 12, 0, tzinfo=ZoneInfo("UTC"))  # Sun
            assert ev._check_day("Fri-Mon") is True

    def test_invalid_day_spec(self):
        ev = ContextEvaluator()
        # Invalid day → fail-open → True
        assert ev._check_day("Xyz-Abc") is True

    def test_value_list_match(self):
        ev = ContextEvaluator()
        assert ev._check_value(["admin", "superadmin"], "admin") is True
        assert ev._check_value(["admin", "superadmin"], "user") is False


# ---------------------------------------------------------------------------
# engine.py — uncovered error path
# ---------------------------------------------------------------------------


class TestShieldEngineEdgeCases:
    def test_check_exception_fail_open(self):
        """ShieldEngine.check should handle matcher exceptions gracefully."""
        from policyshield.core.models import RuleSet, ShieldMode
        from policyshield.shield.engine import ShieldEngine

        rs = RuleSet(shield_name="test", version=1, rules=[], default_verdict="ALLOW")
        engine = ShieldEngine(rules=rs, mode=ShieldMode.ENFORCE, fail_open=True)

        # Force matcher to raise
        engine._matcher.find_best_match = MagicMock(side_effect=RuntimeError("boom"))
        result = engine.check("tool", {"a": 1}, session_id="s1")
        assert result.verdict.value == "ALLOW"

    def test_check_exception_fail_closed(self):
        from policyshield.core.models import RuleSet, ShieldMode
        from policyshield.shield.engine import ShieldEngine

        rs = RuleSet(shield_name="test", version=1, rules=[], default_verdict="ALLOW")
        engine = ShieldEngine(rules=rs, mode=ShieldMode.ENFORCE, fail_open=False)
        engine._matcher.find_best_match = MagicMock(side_effect=RuntimeError("boom"))
        result = engine.check("tool", {"a": 1}, session_id="s1")
        assert result.verdict.value == "BLOCK"
