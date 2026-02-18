"""Tests for budget caps."""

from __future__ import annotations

from policyshield.shield.budget import BudgetConfig, BudgetTracker


class TestBudgetCaps:
    def test_session_budget_exceeded(self):
        tracker = BudgetTracker(BudgetConfig(max_per_session=0.02))
        ok, _ = tracker.check_budget("s1", "exec")  # 0.01
        assert ok
        tracker.record_spend("s1", "exec")
        ok, _ = tracker.check_budget("s1", "exec")  # 0.02 total
        assert ok
        tracker.record_spend("s1", "exec")
        ok, reason = tracker.check_budget("s1", "exec")  # 0.03 > 0.02
        assert not ok
        assert "Session budget" in reason

    def test_hourly_budget(self):
        tracker = BudgetTracker(BudgetConfig(max_per_hour=0.02))
        tracker.record_spend("s1", "exec")
        tracker.record_spend("s2", "exec")
        ok, reason = tracker.check_budget("s3", "exec")
        assert not ok
        assert "Hourly budget" in reason

    def test_session_balance(self):
        tracker = BudgetTracker(BudgetConfig(max_per_session=1.0))
        tracker.record_spend("s1", "exec")
        balance = tracker.session_balance("s1")
        assert balance["spent"] == 0.01
        assert balance["remaining"] == 0.99

    def test_no_budget_limits(self):
        tracker = BudgetTracker(BudgetConfig())
        for _ in range(100):
            ok, _ = tracker.check_budget("s1", "exec")
            assert ok
            tracker.record_spend("s1", "exec")

    def test_custom_tool_costs(self):
        tracker = BudgetTracker(
            BudgetConfig(max_per_session=0.50),
            tool_costs={"expensive_tool": 1.00},
        )
        ok, reason = tracker.check_budget("s1", "expensive_tool")
        assert not ok
        assert "Session budget" in reason
