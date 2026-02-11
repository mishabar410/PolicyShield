"""Tests for the rate limiter engine."""

from __future__ import annotations

import time

from policyshield.core.models import RuleSet, Verdict
from policyshield.shield.engine import ShieldEngine
from policyshield.shield.rate_limiter import RateLimitConfig, RateLimiter


class TestRateLimiter:
    """Tests for standalone RateLimiter."""

    def test_allows_within_limit(self):
        rl = RateLimiter([RateLimitConfig(tool="exec", max_calls=3, window_seconds=60)])
        rl.record("exec")
        rl.record("exec")
        result = rl.check("exec")
        assert result.allowed is True

    def test_blocks_over_limit(self):
        rl = RateLimiter([RateLimitConfig(tool="exec", max_calls=2, window_seconds=60)])
        rl.record("exec")
        rl.record("exec")
        result = rl.check("exec")
        assert result.allowed is False
        assert result.message == "Rate limit exceeded"

    def test_per_session_isolation(self):
        rl = RateLimiter([RateLimitConfig(tool="exec", max_calls=1, window_seconds=60, per_session=True)])
        rl.record("exec", "session-a")
        # Session B is not affected
        result = rl.check("exec", "session-b")
        assert result.allowed is True

    def test_global_limit(self):
        rl = RateLimiter([RateLimitConfig(tool="exec", max_calls=2, window_seconds=60, per_session=False)])
        rl.record("exec", "session-a")
        rl.record("exec", "session-b")
        # Global limit is 2, both sessions together hit it
        result = rl.check("exec", "session-c")
        assert result.allowed is False

    def test_wildcard_tool(self):
        rl = RateLimiter([RateLimitConfig(tool="*", max_calls=3, window_seconds=60)])
        rl.record("exec")
        rl.record("read_file")
        rl.record("write_file")
        result = rl.check("anything")
        assert result.allowed is False

    def test_sliding_window_expiry(self):
        rl = RateLimiter([RateLimitConfig(tool="exec", max_calls=1, window_seconds=0.1)])
        rl.record("exec")
        result = rl.check("exec")
        assert result.allowed is False
        time.sleep(0.15)
        result = rl.check("exec")
        assert result.allowed is True

    def test_reset_all(self):
        rl = RateLimiter([RateLimitConfig(tool="exec", max_calls=1, window_seconds=60)])
        rl.record("exec")
        result = rl.check("exec")
        assert result.allowed is False
        rl.reset()
        result = rl.check("exec")
        assert result.allowed is True

    def test_reset_session(self):
        rl = RateLimiter([RateLimitConfig(tool="exec", max_calls=1, window_seconds=60, per_session=True)])
        rl.record("exec", "s1")
        rl.record("exec", "s2")
        rl.reset("s1")
        assert rl.check("exec", "s1").allowed is True
        assert rl.check("exec", "s2").allowed is False

    def test_from_yaml_dict(self):
        configs = [
            {"tool": "web_fetch", "max_calls": 10, "window_seconds": 60},
            {"tool": "*", "max_calls": 100, "window_seconds": 300, "per_session": False},
        ]
        rl = RateLimiter.from_yaml_dict(configs)
        assert rl.check("web_fetch").allowed is True

    def test_different_tools_independent(self):
        rl = RateLimiter([RateLimitConfig(tool="exec", max_calls=1, window_seconds=60)])
        rl.record("exec")
        assert rl.check("exec").allowed is False
        assert rl.check("read_file").allowed is True


class TestEngineWithRateLimiter:
    """Tests for ShieldEngine + RateLimiter integration."""

    def test_engine_blocks_on_rate_limit(self):
        rs = RuleSet(shield_name="test", version=1, rules=[])
        rl = RateLimiter([RateLimitConfig(tool="exec", max_calls=1, window_seconds=60)])
        engine = ShieldEngine(rules=rs, rate_limiter=rl)

        r1 = engine.check("exec")
        assert r1.verdict == Verdict.ALLOW
        r2 = engine.check("exec")
        assert r2.verdict == Verdict.BLOCK
        assert r2.rule_id == "__rate_limit__"

    def test_engine_rate_limit_per_session(self):
        rs = RuleSet(shield_name="test", version=1, rules=[])
        rl = RateLimiter([RateLimitConfig(tool="exec", max_calls=1, window_seconds=60, per_session=True)])
        engine = ShieldEngine(rules=rs, rate_limiter=rl)

        engine.check("exec", session_id="s1")
        r = engine.check("exec", session_id="s2")
        assert r.verdict == Verdict.ALLOW
