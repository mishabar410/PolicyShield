"""Tests for config migration."""

from __future__ import annotations

from policyshield.migration.migrator import Migrator


class TestConfigMigration:
    def test_migrate_011_to_012(self):
        yaml_text = "rules:\n  - id: rule-1\n    tool: exec\n    then: BLOCK\n"
        migrator = Migrator()
        result = migrator.migrate(yaml_text, "0.11", "0.12")
        assert any("then" in c for c in result.changes)

    def test_migrate_full_chain(self):
        yaml_text = "rules:\n  - id: rule-1\n    then: BLOCK\n"
        migrator = Migrator()
        result = migrator.migrate(yaml_text, "0.11", "1.0")
        assert len(result.changes) > 0
        assert "version" in result.yaml_output

    def test_no_changes_needed(self):
        yaml_text = 'version: "1.0"\nrules:\n  - id: rule-1\n    tool: exec\n    then: BLOCK\n    severity: high\n'
        migrator = Migrator()
        result = migrator.migrate(yaml_text, "1.0", "1.0")
        assert len(result.changes) == 0
