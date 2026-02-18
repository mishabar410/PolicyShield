"""Circuit breaker for approval backends."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from time import monotonic


class CircuitState(Enum):
    CLOSED = "closed"  # Normal — requests pass through
    OPEN = "open"  # Tripped — all requests fail-fast
    HALF_OPEN = "half_open"  # Testing — one request allowed


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 3
    reset_timeout: float = 60.0
    fallback: str = "BLOCK"  # "BLOCK" | "ALLOW"


class CircuitBreaker:
    """Circuit breaker wrapper for approval backends."""

    def __init__(self, config: CircuitBreakerConfig | None = None):
        self._config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                if monotonic() - self._last_failure_time > self._config.reset_timeout:
                    self._state = CircuitState.HALF_OPEN
            return self._state

    def is_available(self) -> bool:
        return self.state != CircuitState.OPEN

    def record_success(self) -> None:
        with self._lock:
            self._failure_count = 0
            self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = monotonic()
            if self._failure_count >= self._config.failure_threshold:
                self._state = CircuitState.OPEN

    @property
    def fallback_verdict(self) -> str:
        return self._config.fallback
