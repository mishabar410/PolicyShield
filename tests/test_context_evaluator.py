"""Tests for ContextEvaluator — context conditions in rules."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest

from policyshield.shield.context import ContextEvaluator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_eval(tz: str = "UTC") -> ContextEvaluator:
    return ContextEvaluator(tz=tz)


def _fixed_now(hh_mm: str, day: str = "Wed", tz: str = "UTC"):
    """Patch ContextEvaluator._now to return a fixed datetime."""
    days = {"Mon": 0, "Tue": 1, "Wed": 2, "Thu": 3, "Fri": 4, "Sat": 5, "Sun": 6}
    dt = datetime(2025, 1, 6 + days[day], *map(int, hh_mm.split(":")), tzinfo=ZoneInfo(tz))
    return patch.object(ContextEvaluator, "_now", return_value=dt)


# ---------------------------------------------------------------------------
# time_of_day
# ---------------------------------------------------------------------------


class TestTimeOfDay:
    def test_in_range(self):
        ev = _make_eval()
        with _fixed_now("10:30"):
            assert ev.evaluate({"time_of_day": "09:00-18:00"}, {}) is True

    def test_out_of_range(self):
        ev = _make_eval()
        with _fixed_now("20:00"):
            assert ev.evaluate({"time_of_day": "09:00-18:00"}, {}) is False

    def test_negated_in_range(self):
        ev = _make_eval()
        with _fixed_now("10:30"):
            assert ev.evaluate({"time_of_day": "!09:00-18:00"}, {}) is False

    def test_negated_out_of_range(self):
        ev = _make_eval()
        with _fixed_now("20:00"):
            assert ev.evaluate({"time_of_day": "!09:00-18:00"}, {}) is True

    def test_overnight_range_in(self):
        ev = _make_eval()
        with _fixed_now("23:00"):
            assert ev.evaluate({"time_of_day": "22:00-06:00"}, {}) is True

    def test_overnight_range_in_morning(self):
        ev = _make_eval()
        with _fixed_now("03:00"):
            assert ev.evaluate({"time_of_day": "22:00-06:00"}, {}) is True

    def test_overnight_range_out(self):
        ev = _make_eval()
        with _fixed_now("12:00"):
            assert ev.evaluate({"time_of_day": "22:00-06:00"}, {}) is False

    def test_boundary_start(self):
        ev = _make_eval()
        with _fixed_now("09:00"):
            assert ev.evaluate({"time_of_day": "09:00-18:00"}, {}) is True

    def test_boundary_end(self):
        ev = _make_eval()
        with _fixed_now("18:00"):
            assert ev.evaluate({"time_of_day": "09:00-18:00"}, {}) is True


# ---------------------------------------------------------------------------
# day_of_week
# ---------------------------------------------------------------------------


class TestDayOfWeek:
    def test_range_weekday(self):
        ev = _make_eval()
        with _fixed_now("12:00", day="Wed"):
            assert ev.evaluate({"day_of_week": "Mon-Fri"}, {}) is True

    def test_range_weekend(self):
        ev = _make_eval()
        with _fixed_now("12:00", day="Sat"):
            assert ev.evaluate({"day_of_week": "Mon-Fri"}, {}) is False

    def test_list_match(self):
        ev = _make_eval()
        with _fixed_now("12:00", day="Sat"):
            assert ev.evaluate({"day_of_week": "Sat,Sun"}, {}) is True

    def test_list_no_match(self):
        ev = _make_eval()
        with _fixed_now("12:00", day="Wed"):
            assert ev.evaluate({"day_of_week": "Sat,Sun"}, {}) is False

    def test_negated_range(self):
        ev = _make_eval()
        with _fixed_now("12:00", day="Sat"):
            assert ev.evaluate({"day_of_week": "!Mon-Fri"}, {}) is True

    def test_negated_range_inside(self):
        ev = _make_eval()
        with _fixed_now("12:00", day="Wed"):
            assert ev.evaluate({"day_of_week": "!Mon-Fri"}, {}) is False


# ---------------------------------------------------------------------------
# Arbitrary key matching
# ---------------------------------------------------------------------------


class TestValueMatch:
    def test_exact_match(self):
        ev = _make_eval()
        assert ev.evaluate({"user_role": "admin"}, {"user_role": "admin"}) is True

    def test_exact_no_match(self):
        ev = _make_eval()
        assert ev.evaluate({"user_role": "admin"}, {"user_role": "viewer"}) is False

    def test_negation_match(self):
        ev = _make_eval()
        assert ev.evaluate({"user_role": "!admin"}, {"user_role": "viewer"}) is True

    def test_negation_no_match(self):
        ev = _make_eval()
        assert ev.evaluate({"user_role": "!admin"}, {"user_role": "admin"}) is False

    def test_list_any_of(self):
        ev = _make_eval()
        assert ev.evaluate({"env": ["staging", "production"]}, {"env": "staging"}) is True

    def test_list_none_of(self):
        ev = _make_eval()
        assert ev.evaluate({"env": ["staging", "production"]}, {"env": "dev"}) is False

    def test_missing_key_fails(self):
        ev = _make_eval()
        assert ev.evaluate({"env": "production"}, {}) is False

    def test_missing_key_negation_passes(self):
        ev = _make_eval()
        assert ev.evaluate({"env": "!production"}, {}) is True

    def test_integer_value(self):
        ev = _make_eval()
        assert ev.evaluate({"level": 5}, {"level": 5}) is True


# ---------------------------------------------------------------------------
# Multiple conditions (AND logic)
# ---------------------------------------------------------------------------


class TestMultipleConditions:
    def test_all_match(self):
        ev = _make_eval()
        with _fixed_now("10:30", day="Wed"):
            ctx = {"user_role": "admin", "env": "production"}
            assert ev.evaluate(
                {"time_of_day": "09:00-18:00", "user_role": "admin", "env": "production"},
                ctx,
            ) is True

    def test_one_fails(self):
        ev = _make_eval()
        with _fixed_now("10:30", day="Wed"):
            ctx = {"user_role": "viewer", "env": "production"}
            assert ev.evaluate(
                {"time_of_day": "09:00-18:00", "user_role": "admin", "env": "production"},
                ctx,
            ) is False


# ---------------------------------------------------------------------------
# Integration with matcher
# ---------------------------------------------------------------------------


class TestMatcherIntegration:
    def test_context_rule_matches(self):
        """Rule with context condition should match when context matches."""
        from policyshield.core.models import RuleConfig, RuleSet, Verdict
        from policyshield.shield.matcher import MatcherEngine

        rule = RuleConfig(
            id="admin-block",
            when={"tool": "deploy", "context": {"user_role": "admin"}},
            then=Verdict.BLOCK,
            message="Admins blocked from deploy",
        )
        rs = RuleSet(shield_name="test", version=1, rules=[rule])
        eng = MatcherEngine(rs)

        # Context matches
        match = eng.find_best_match("deploy", context={"user_role": "admin"})
        assert match is not None
        assert match.rule.id == "admin-block"

        # Context doesn't match
        match = eng.find_best_match("deploy", context={"user_role": "viewer"})
        assert match is None

        # No context provided → rule doesn't match (context key missing)
        match = eng.find_best_match("deploy")
        assert match is None

    def test_context_rule_negation(self):
        """Rule with negated context should match when value is different."""
        from policyshield.core.models import RuleConfig, RuleSet, Verdict
        from policyshield.shield.matcher import MatcherEngine

        rule = RuleConfig(
            id="non-admin-block",
            when={"tool": "deploy", "context": {"user_role": "!admin"}},
            then=Verdict.BLOCK,
            message="Non-admins blocked",
        )
        rs = RuleSet(shield_name="test", version=1, rules=[rule])
        eng = MatcherEngine(rs)

        # viewer → should match (negation passes)
        match = eng.find_best_match("deploy", context={"user_role": "viewer"})
        assert match is not None

        # admin → should NOT match (negation fails)
        match = eng.find_best_match("deploy", context={"user_role": "admin"})
        assert match is None

    def test_engine_check_with_context(self):
        """ShieldEngine.check should pass context through to matcher."""
        from policyshield.core.models import RuleConfig, RuleSet, Verdict
        from policyshield.shield.engine import ShieldEngine

        rule = RuleConfig(
            id="prod-block",
            when={"tool": "write_file", "context": {"environment": "production"}},
            then=Verdict.BLOCK,
            message="No writes in production",
        )
        rs = RuleSet(shield_name="test", version=1, rules=[rule])
        engine = ShieldEngine(rules=rs)

        # In production → BLOCK
        result = engine.check("write_file", context={"environment": "production"})
        assert result.verdict == Verdict.BLOCK

        # In staging → ALLOW (rule doesn't match)
        result = engine.check("write_file", context={"environment": "staging"})
        assert result.verdict == Verdict.ALLOW
