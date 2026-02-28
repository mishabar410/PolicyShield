"""Canary deployment logic for PolicyShield rules."""

from __future__ import annotations

import hashlib
import logging
import threading
from time import monotonic

logger = logging.getLogger(__name__)


class CanaryRouter:
    """Routes sessions to canary or production rules based on hash-based bucketing."""

    def __init__(self) -> None:
        self._canary_start_times: dict[str, float] = {}  # rule_id → start time
        self._lock = threading.Lock()

    def should_apply_canary(
        self,
        rule_id: str,
        session_id: str,
        canary_percent: float,
        promote_after: float | None = None,
    ) -> bool:
        """Determine if a canary rule should apply to this session.

        Uses deterministic hash-based bucketing so the same session
        always gets the same treatment.

        Args:
            rule_id: The canary rule ID.
            session_id: Current session ID.
            canary_percent: Fraction of sessions to target (0.0-1.0).
            promote_after: Auto-promote to 100% after N seconds.

        Returns:
            True if this session should get the canary rule.
        """
        # Auto-promote if enough time has passed
        if promote_after is not None:
            with self._lock:
                start = self._canary_start_times.get(rule_id)
                if start is None:
                    self._canary_start_times[rule_id] = monotonic()
                elif monotonic() - start > promote_after:
                    logger.warning(
                        "Canary rule '%s' auto-promoted to 100%% after %.0fs",
                        rule_id,
                        monotonic() - start,
                    )
                    return True  # Promoted to 100%

        # Deterministic hash bucketing
        bucket_key = f"{rule_id}:{session_id}"
        hash_value = int(hashlib.sha256(bucket_key.encode()).hexdigest()[:8], 16)
        bucket = hash_value / 0xFFFFFFFF  # Normalize to 0.0-1.0
        return bucket < canary_percent

    def reset(self, rule_id: str) -> None:
        """Reset canary timer for a rule."""
        with self._lock:
            self._canary_start_times.pop(rule_id, None)

