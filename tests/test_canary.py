"""Tests for canary deployment logic."""

from __future__ import annotations

from time import monotonic

from policyshield.shield.canary import CanaryRouter


class TestCanaryDeployment:
    def test_deterministic_bucketing(self):
        router = CanaryRouter()
        results = [router.should_apply_canary("r1", f"session_{i}", 0.5) for i in range(1000)]
        # Roughly 50% should be True (within statistical margin)
        assert 400 < sum(results) < 600

    def test_same_session_same_result(self):
        router = CanaryRouter()
        r1 = router.should_apply_canary("r1", "fixed_session", 0.5)
        r2 = router.should_apply_canary("r1", "fixed_session", 0.5)
        assert r1 == r2

    def test_zero_percent_never_applies(self):
        router = CanaryRouter()
        results = [router.should_apply_canary("r1", f"s{i}", 0.0) for i in range(100)]
        assert sum(results) == 0

    def test_auto_promote(self):
        router = CanaryRouter()
        router._canary_start_times["r1"] = monotonic() - 100
        result = router.should_apply_canary("r1", "any_session", 0.05, promote_after=50)
        assert result  # Auto-promoted to 100%

    def test_reset(self):
        router = CanaryRouter()
        router._canary_start_times["r1"] = monotonic()
        router.reset("r1")
        assert "r1" not in router._canary_start_times
