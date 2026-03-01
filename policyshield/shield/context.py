"""Context condition evaluator for PolicyShield rules.

Evaluates ``when.context`` blocks in rule definitions, supporting:
- **time_of_day**: ``"HH:MM-HH:MM"`` or ``"!HH:MM-HH:MM"`` (negated)
- **day_of_week**: ``"Mon-Fri"`` or ``"!Sat,Sun"``
- Arbitrary keys: exact match, ``"!value"`` (negated), or list (any-of)
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

logger = logging.getLogger("policyshield")

_DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


class ContextEvaluator:
    """Evaluates context conditions from rule ``when.context`` blocks.

    Args:
        tz: IANA timezone string for time/day conditions (default ``"UTC"``).
    """

    def __init__(self, tz: str = "UTC") -> None:
        self._tz = ZoneInfo(tz)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, conditions: dict[str, Any], context: dict[str, Any]) -> bool:
        """Return ``True`` if **all** conditions match against *context*."""
        for key, expected in conditions.items():
            if key == "time_of_day":
                if not self._check_time(expected):
                    return False
            elif key == "day_of_week":
                if not self._check_day(expected):
                    return False
            else:
                if not self._check_value(expected, context.get(key)):
                    return False
        return True

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _now(self) -> datetime:
        """Current datetime in the configured timezone (test-friendly)."""
        return datetime.now(self._tz)

    def _check_time(self, spec: str) -> bool:
        """Match ``"HH:MM-HH:MM"`` (or ``"!…"`` for negation)."""
        negate = spec.startswith("!")
        if negate:
            spec = spec[1:]

        parts = spec.split("-", 1)
        if len(parts) != 2:
            logger.warning("Invalid time_of_day spec: %s", spec)
            return True  # fail-open

        start_s, end_s = parts
        now_s = self._now().strftime("%H:%M")

        if start_s <= end_s:
            in_range = start_s <= now_s <= end_s
        else:
            # Overnight range e.g. "22:00-06:00"
            in_range = now_s >= start_s or now_s <= end_s

        return not in_range if negate else in_range

    def _check_day(self, spec: str) -> bool:
        """Match ``"Mon-Fri"`` range or ``"Sat,Sun"`` list (or negated)."""
        negate = spec.startswith("!")
        if negate:
            spec = spec[1:]

        today = self._now().strftime("%a")  # Mon, Tue, …

        if "-" in spec:
            parts = spec.split("-", 1)
            try:
                start_i = _DAYS.index(parts[0])
                end_i = _DAYS.index(parts[1])
                today_i = _DAYS.index(today)
                if start_i <= end_i:
                    in_range = start_i <= today_i <= end_i
                else:
                    in_range = today_i >= start_i or today_i <= end_i
            except ValueError:
                logger.warning("Invalid day_of_week spec: %s", spec)
                return True
        else:
            in_range = today in [d.strip() for d in spec.split(",")]

        return not in_range if negate else in_range

    def _check_value(self, expected: Any, actual: Any) -> bool:
        """Match arbitrary key: exact, negation (``"!val"``), or list (any-of)."""
        if actual is None:
            # Missing key in context: negation passes, anything else fails
            if isinstance(expected, str) and expected.startswith("!"):
                return True
            return False

        if isinstance(expected, str) and expected.startswith("!"):
            return str(actual) != expected[1:]
        if isinstance(expected, list):
            return str(actual) in [str(v) for v in expected]
        return str(actual) == str(expected)
