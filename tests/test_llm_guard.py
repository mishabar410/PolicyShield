"""Tests for LLM Guard middleware."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from policyshield.shield.llm_guard import GuardResult, LLMGuard, LLMGuardConfig


# ---------------------------------------------------------------------------
# Test: disabled guard
# ---------------------------------------------------------------------------


class TestDisabledGuard:
    def test_disabled_returns_empty(self):
        guard = LLMGuard(LLMGuardConfig(enabled=False))
        result = asyncio.run(guard.analyze("tool", {"arg": "val"}))
        assert result.is_threat is False
        assert result.risk_score == 0.0

    def test_enabled_property(self):
        assert LLMGuard(LLMGuardConfig(enabled=False)).enabled is False
        assert LLMGuard(LLMGuardConfig(enabled=True)).enabled is True


# ---------------------------------------------------------------------------
# Test: caching
# ---------------------------------------------------------------------------


class TestCaching:
    def test_cache_hit(self):
        guard = LLMGuard(LLMGuardConfig(enabled=True, api_key="test"))

        # Manually seed the cache
        result = GuardResult(is_threat=True, risk_score=0.9, explanation="Injection")
        key = guard._make_cache_key("exec", {"cmd": "rm -rf /"})
        guard._put_cache(key, result)

        # Should get cached result
        cached = asyncio.run(guard.analyze("exec", {"cmd": "rm -rf /"}))
        assert cached.is_threat is True
        assert cached.cached is True
        assert cached.risk_score == 0.9

    def test_cache_clear(self):
        guard = LLMGuard(LLMGuardConfig(enabled=True, api_key="test"))
        key = guard._make_cache_key("tool", {"a": 1})
        guard._put_cache(key, GuardResult())
        guard.clear_cache()
        assert guard._get_cached(key) is None


# ---------------------------------------------------------------------------
# Test: response parsing
# ---------------------------------------------------------------------------


class TestResponseParsing:
    def test_valid_response(self):
        guard = LLMGuard(LLMGuardConfig(enabled=True))
        data = {
            "choices": [
                {
                    "message": {
                        "content": '{"is_threat": true, "threat_type": "prompt_injection", "risk_score": 0.95, "explanation": "Contains injection attempt"}'
                    }
                }
            ]
        }
        result = guard._parse_response(data)
        assert result.is_threat is True
        assert result.threat_type == "prompt_injection"
        assert result.risk_score == 0.95

    def test_markdown_fenced_response(self):
        guard = LLMGuard(LLMGuardConfig(enabled=True))
        data = {
            "choices": [
                {
                    "message": {
                        "content": '```json\n{"is_threat": false, "risk_score": 0.1}\n```'
                    }
                }
            ]
        }
        result = guard._parse_response(data)
        assert result.is_threat is False

    def test_malformed_response(self):
        guard = LLMGuard(LLMGuardConfig(enabled=True))
        data = {"choices": [{"message": {"content": "not json"}}]}
        result = guard._parse_response(data)
        assert result.is_threat is False  # fail-open default


# ---------------------------------------------------------------------------
# Test: fail modes
# ---------------------------------------------------------------------------


class TestFailModes:
    def test_fail_open_on_error(self):
        config = LLMGuardConfig(enabled=True, api_key="test", fail_open=True)
        guard = LLMGuard(config)

        # Mock _call_llm to raise
        async def _raise(*a, **kw):
            raise ConnectionError("LLM unreachable")

        guard._call_llm = _raise  # type: ignore

        result = asyncio.run(guard.analyze("tool", {"a": 1}))
        assert result.is_threat is False

    def test_fail_closed_on_error(self):
        config = LLMGuardConfig(enabled=True, api_key="test", fail_open=False)
        guard = LLMGuard(config)

        async def _raise(*a, **kw):
            raise ConnectionError("LLM unreachable")

        guard._call_llm = _raise  # type: ignore

        result = asyncio.run(guard.analyze("tool", {"a": 1}))
        assert result.is_threat is True
        assert result.risk_score == 1.0


# ---------------------------------------------------------------------------
# Test: prompt building
# ---------------------------------------------------------------------------


class TestPromptBuilding:
    def test_build_prompt(self):
        guard = LLMGuard(LLMGuardConfig(enabled=True))
        prompt = guard._build_prompt("write_file", {"content": "hello"})
        assert "write_file" in prompt
        assert "hello" in prompt
        assert "prompt_injection" in prompt

    def test_truncation(self):
        guard = LLMGuard(LLMGuardConfig(enabled=True, max_arg_length=20))
        prompt = guard._build_prompt("tool", {"long": "x" * 1000})
        # The prompt should truncate the args representation
        assert len(prompt) < 200  # much less than 1000+ chars


# ---------------------------------------------------------------------------
# Test: config defaults
# ---------------------------------------------------------------------------


class TestConfig:
    def test_defaults(self):
        config = LLMGuardConfig()
        assert config.enabled is False
        assert config.model == "gpt-4o-mini"
        assert config.fail_open is True
        assert config.risk_threshold == 0.7
        assert "prompt_injection" in config.checks
        assert "semantic_pii" in config.checks
