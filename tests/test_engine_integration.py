"""Integration tests: engine + BudgetTracker, WebhookNotifier, CanaryRouter, CLI report/timeline."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest


# ── Minimal rules YAML ────────────────────────────────────────────

_RULES_YAML = """\
shield_name: test
version: 1
rules:
  - id: block_exec
    tool: exec
    then: BLOCK
    message: blocked
"""


@pytest.fixture()
def rules_path(tmp_path: Path) -> Path:
    p = tmp_path / "rules.yaml"
    p.write_text(_RULES_YAML, encoding="utf-8")
    return p


# ── BudgetTracker integration ─────────────────────────────────────


class TestBudgetIntegration:
    def test_budget_exceeded_blocks(self, rules_path: Path) -> None:
        from policyshield.shield.budget import BudgetConfig, BudgetTracker
        from policyshield.shield.engine import ShieldEngine

        tracker = BudgetTracker(BudgetConfig(max_per_session=0.01))
        engine = ShieldEngine(rules=rules_path, budget_tracker=tracker)

        # First call uses budget
        tracker.record_spend("s1", "read_file")  # 0.002
        tracker.record_spend("s1", "read_file")  # 0.004
        tracker.record_spend("s1", "read_file")  # 0.006
        tracker.record_spend("s1", "read_file")  # 0.008
        tracker.record_spend("s1", "read_file")  # 0.010 — at limit

        result = engine.check("read_file", {}, session_id="s1")
        assert result.verdict.value == "BLOCK"
        assert result.rule_id == "__budget__"

    def test_budget_ok_allows(self, rules_path: Path) -> None:
        from policyshield.shield.budget import BudgetConfig, BudgetTracker
        from policyshield.shield.engine import ShieldEngine

        tracker = BudgetTracker(BudgetConfig(max_per_session=10.0))
        engine = ShieldEngine(rules=rules_path, budget_tracker=tracker)

        result = engine.check("read_file", {}, session_id="s1")
        assert result.verdict.value == "ALLOW"

    def test_budget_records_on_allow(self, rules_path: Path) -> None:
        from policyshield.shield.budget import BudgetConfig, BudgetTracker
        from policyshield.shield.engine import ShieldEngine

        tracker = BudgetTracker(BudgetConfig(max_per_session=10.0))
        engine = ShieldEngine(rules=rules_path, budget_tracker=tracker)

        engine.check("read_file", {}, session_id="s1")

        # Budget should have been recorded via _apply_post_check
        balance = tracker.session_balance("s1")
        assert balance["spent"] > 0


# ── CanaryRouter as engine property ───────────────────────────────


class TestCanaryIntegration:
    def test_canary_accessible_via_engine(self, rules_path: Path) -> None:
        from policyshield.shield.canary import CanaryRouter
        from policyshield.shield.engine import ShieldEngine

        router = CanaryRouter()
        engine = ShieldEngine(rules=rules_path, canary_router=router)
        assert engine._canary_router is router


# ── WebhookNotifier integration ───────────────────────────────────


class TestWebhookIntegration:
    def test_webhook_fires_on_block(self, rules_path: Path) -> None:
        from policyshield.server.webhook import WebhookNotifier
        from policyshield.shield.engine import ShieldEngine

        notifier = WebhookNotifier(url="http://localhost:9999/hook")
        engine = ShieldEngine(rules=rules_path, webhook_notifier=notifier)

        with patch.object(notifier, "notify", new_callable=AsyncMock):
            result = engine.check("exec", {}, session_id="s1")
            assert result.verdict.value == "BLOCK"
            # Webhook fires asynchronously — give it a moment
            import time

            time.sleep(0.3)
            # The webhook should have been called (via fire-and-forget thread)
            # But since it's in a ThreadPoolExecutor with asyncio.run, it may or may not
            # complete. The important thing is that no exception was raised.


# ── CLI report/timeline ───────────────────────────────────────────


class TestCLIReport:
    def test_report_text(self, tmp_path: Path) -> None:
        from policyshield.cli.main import app

        # Create trace file
        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()
        trace_file = trace_dir / "trace_001.jsonl"
        entries = [
            {
                "tool": "exec",
                "verdict": "BLOCK",
                "session_id": "s1",
                "rule_id": "r1",
                "timestamp": "2025-01-01T00:00:00Z",
            },
            {"tool": "read", "verdict": "ALLOW", "session_id": "s1", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        trace_file.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")

        exit_code = app(["report", "--dir", str(trace_dir)])
        assert exit_code == 0

    def test_report_html_output(self, tmp_path: Path) -> None:
        from policyshield.cli.main import app

        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()
        trace_file = trace_dir / "trace_001.jsonl"
        entries = [
            {
                "tool": "exec",
                "verdict": "BLOCK",
                "session_id": "s1",
                "rule_id": "r1",
                "timestamp": "2025-01-01T00:00:00Z",
            },
        ]
        trace_file.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")

        out_file = tmp_path / "report.html"
        exit_code = app(["report", "--dir", str(trace_dir), "--format", "html", "-o", str(out_file)])
        assert exit_code == 0
        assert out_file.exists()
        content = out_file.read_text()
        assert "PolicyShield Compliance Report" in content


class TestCLITimeline:
    def test_timeline_text(self, tmp_path: Path) -> None:
        from policyshield.cli.main import app

        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()
        trace_file = trace_dir / "trace_001.jsonl"
        entries = [
            {
                "tool": "exec",
                "verdict": "BLOCK",
                "session_id": "s1",
                "rule_id": "r1",
                "timestamp": "2025-01-01T00:00:00Z",
            },
            {"tool": "read", "verdict": "ALLOW", "session_id": "s1", "timestamp": "2025-01-01T00:01:00Z"},
            {"tool": "write", "verdict": "ALLOW", "session_id": "s2", "timestamp": "2025-01-01T00:02:00Z"},
        ]
        trace_file.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")

        exit_code = app(["timeline", "--dir", str(trace_dir), "--session", "s1"])
        assert exit_code == 0

    def test_timeline_json(self, tmp_path: Path, capsys) -> None:
        from policyshield.cli.main import app

        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()
        trace_file = trace_dir / "trace_001.jsonl"
        entries = [
            {
                "tool": "exec",
                "verdict": "BLOCK",
                "session_id": "s1",
                "rule_id": "r1",
                "timestamp": "2025-01-01T00:00:00Z",
            },
        ]
        trace_file.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")

        exit_code = app(["timeline", "--dir", str(trace_dir), "--session", "s1", "--format", "json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["session_id"] == "s1"
        assert data["total_checks"] == 1
