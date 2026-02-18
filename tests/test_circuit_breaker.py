"""Tests for approval circuit breaker."""

from __future__ import annotations

import time

from policyshield.approval.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
)


class TestCircuitBreaker:
    def test_closed_by_default(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED
        assert cb.is_available()

    def test_opens_after_threshold(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3))
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert not cb.is_available()

    def test_half_open_after_timeout(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=1, reset_timeout=0.1))
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

    def test_closes_on_success(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=1))
        cb.record_failure()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_fallback_verdict(self):
        cb = CircuitBreaker(CircuitBreakerConfig(fallback="ALLOW"))
        assert cb.fallback_verdict == "ALLOW"

    def test_stays_closed_below_threshold(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3))
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        assert cb.is_available()

    def test_success_resets_failure_count(self):
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3))
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED  # reset by success

    def test_default_config(self):
        cb = CircuitBreaker()
        assert cb.fallback_verdict == "BLOCK"
        assert cb._config.failure_threshold == 3
        assert cb._config.reset_timeout == 60.0
