"""Tests for API rate limiting."""

from __future__ import annotations

from policyshield.server.rate_limiter import APIRateLimiter


class TestAPIRateLimiter:
    def test_allows_within_limit(self):
        limiter = APIRateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            assert limiter.is_allowed("client1")

    def test_blocks_excess(self):
        limiter = APIRateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            assert limiter.is_allowed("client1")
        assert not limiter.is_allowed("client1")

    def test_separate_buckets_by_key(self):
        limiter = APIRateLimiter(max_requests=2, window_seconds=60)
        assert limiter.is_allowed("token:abc")
        assert limiter.is_allowed("token:abc")
        assert not limiter.is_allowed("token:abc")
        assert limiter.is_allowed("token:xyz")  # Different token

    def test_limit_info(self):
        limiter = APIRateLimiter(max_requests=50, window_seconds=30)
        info = limiter.limit_info
        assert info["max_requests"] == 50
        assert info["window_seconds"] == 30

    def test_default_config(self):
        limiter = APIRateLimiter()
        info = limiter.limit_info
        assert info["max_requests"] == 100
        assert info["window_seconds"] == 60.0
