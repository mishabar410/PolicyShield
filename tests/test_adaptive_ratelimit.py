"""Tests for global and adaptive rate limiting."""

from __future__ import annotations

import time

from policyshield.shield.rate_limiter import AdaptiveRateLimiter, GlobalRateLimiter


class TestGlobalRateLimit:
    def test_global_limit(self):
        limiter = GlobalRateLimiter(max_calls=3, window=60)
        for _ in range(3):
            assert limiter.check("s1")
        assert not limiter.check("s1")
        assert limiter.check("s2")  # Different session OK

    def test_separate_sessions(self):
        limiter = GlobalRateLimiter(max_calls=2, window=60)
        assert limiter.check("s1")
        assert limiter.check("s1")
        assert not limiter.check("s1")
        assert limiter.check("s2")


class TestAdaptiveRateLimit:
    def test_adapts_on_burst(self):
        limiter = AdaptiveRateLimiter(base_limit=10, burst_threshold=2.0, tighten_factor=0.5, cooldown=600.0)
        # Directly inject burst into history
        now = time.monotonic()
        limiter._call_history = [now - i * 0.001 for i in range(21)]
        # Next check should detect burst and tighten
        limiter.check_and_adapt("s1")
        assert limiter._effective_limit < 10

    def test_relaxes_after_cooldown(self):
        limiter = AdaptiveRateLimiter(base_limit=10, cooldown=0.1)
        limiter._effective_limit = 5
        limiter._last_tighten = time.monotonic()
        time.sleep(0.15)
        assert limiter.effective_limit == 10

    def test_normal_traffic_not_tightened(self):
        limiter = AdaptiveRateLimiter(base_limit=100)
        for _ in range(5):
            ok, _ = limiter.check_and_adapt("s1")
            assert ok
        assert limiter.effective_limit == 100
