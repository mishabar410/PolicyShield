"""Tests for the hot-reload watcher."""

from __future__ import annotations

import time

from policyshield.core.models import RuleSet, Verdict
from policyshield.shield.engine import ShieldEngine
from policyshield.shield.watcher import RuleWatcher


def _yaml_content(rule_id: str = "rule-a", tool: str = "exec", then: str = "block") -> str:
    return f"""\
shield_name: test
version: 1
rules:
  - id: {rule_id}
    when:
      tool: {tool}
    then: {then}
    message: "test"
"""


class TestRuleWatcher:
    """Tests for RuleWatcher polling logic."""

    def test_watcher_detects_file_change(self, tmp_path):
        """Watcher calls callback when a file changes."""
        rule_file = tmp_path / "rules.yaml"
        rule_file.write_text(_yaml_content())

        results = []

        def callback(rs: RuleSet) -> None:
            results.append(rs)

        watcher = RuleWatcher(str(rule_file), callback, poll_interval=0.1)
        watcher.start()

        try:
            # Ensure file mtime changes
            time.sleep(0.15)
            rule_file.write_text(_yaml_content(rule_id="rule-b"))
            # Wait for watcher to detect
            time.sleep(0.5)
        finally:
            watcher.stop()

        assert len(results) >= 1
        assert results[-1].rules[0].id == "rule-b"

    def test_watcher_no_change_no_callback(self, tmp_path):
        """Watcher does NOT call callback when no changes happen."""
        rule_file = tmp_path / "rules.yaml"
        rule_file.write_text(_yaml_content())

        results = []

        def callback(rs: RuleSet) -> None:
            results.append(rs)

        watcher = RuleWatcher(str(rule_file), callback, poll_interval=0.1)
        watcher.start()

        try:
            time.sleep(0.4)
        finally:
            watcher.stop()

        assert len(results) == 0

    def test_watcher_survives_invalid_yaml(self, tmp_path):
        """Watcher handles invalid YAML gracefully (old rules remain)."""
        rule_file = tmp_path / "rules.yaml"
        rule_file.write_text(_yaml_content())

        successes = []

        def callback(rs: RuleSet) -> None:
            successes.append(rs)

        watcher = RuleWatcher(str(rule_file), callback, poll_interval=0.1)
        watcher.start()

        try:
            time.sleep(0.15)
            rule_file.write_text("invalid: yaml: {{{{")
            time.sleep(0.5)
        finally:
            watcher.stop()

        # Should NOT have succeeded with invalid YAML
        assert len(successes) == 0
        assert watcher.is_alive is False  # stopped

    def test_watcher_start_stop(self, tmp_path):
        """Watcher can be started and stopped cleanly."""
        rule_file = tmp_path / "rules.yaml"
        rule_file.write_text(_yaml_content())

        watcher = RuleWatcher(str(rule_file), lambda rs: None, poll_interval=0.1)
        assert watcher.is_alive is False

        watcher.start()
        assert watcher.is_alive is True

        watcher.stop()
        time.sleep(0.2)
        assert watcher.is_alive is False

    def test_watcher_watches_directory(self, tmp_path):
        """Watcher can watch a directory for YAML changes."""
        (tmp_path / "rules.yaml").write_text(_yaml_content())
        results = []

        def callback(rs: RuleSet) -> None:
            results.append(rs)

        watcher = RuleWatcher(str(tmp_path), callback, poll_interval=0.1)
        watcher.start()

        try:
            time.sleep(0.15)
            (tmp_path / "rules.yaml").write_text(_yaml_content(rule_id="new-rule"))
            time.sleep(0.5)
        finally:
            watcher.stop()

        assert len(results) >= 1


class TestEngineHotReload:
    """Tests for ShieldEngine hot reload integration."""

    def test_engine_reload_rules(self, tmp_path):
        """ShieldEngine.reload_rules() updates rules thread-safely."""
        rule_file = tmp_path / "rules.yaml"
        rule_file.write_text(_yaml_content(rule_id="old-rule"))

        engine = ShieldEngine(rules=str(rule_file))
        assert engine.rule_count == 1

        rule_file.write_text(_yaml_content(rule_id="new-rule"))
        engine.reload_rules()
        assert engine.rules.rules[0].id == "new-rule"

    def test_engine_start_stop_watching(self, tmp_path):
        """ShieldEngine can start and stop file watching."""
        rule_file = tmp_path / "rules.yaml"
        rule_file.write_text(_yaml_content())

        engine = ShieldEngine(rules=str(rule_file))
        engine.start_watching(poll_interval=0.1)

        assert engine._watcher is not None
        assert engine._watcher.is_alive is True

        engine.stop_watching()
        time.sleep(0.2)
        assert engine._watcher is None

    def test_engine_hot_reload_callback(self, tmp_path):
        """ShieldEngine detects file change and swaps rules."""
        rule_file = tmp_path / "rules.yaml"
        rule_file.write_text(_yaml_content(rule_id="old-rule", tool="exec"))

        engine = ShieldEngine(rules=str(rule_file))
        engine.start_watching(poll_interval=0.1)

        try:
            result = engine.check("exec")
            assert result.verdict == Verdict.BLOCK

            time.sleep(0.15)
            rule_file.write_text(_yaml_content(rule_id="new-rule", tool="read_file"))

            time.sleep(0.5)

            # Old rule should no longer block exec
            result = engine.check("exec")
            assert result.verdict == Verdict.ALLOW
        finally:
            engine.stop_watching()
