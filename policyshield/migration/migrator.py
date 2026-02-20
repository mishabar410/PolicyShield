"""Config migration for PolicyShield — transforms YAML between versions."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

import yaml

logger = logging.getLogger(__name__)


@dataclass
class MigrationResult:
    original_version: str
    target_version: str
    changes: list[str] = field(default_factory=list)
    yaml_output: str = ""


class Migrator:
    """Applies sequential migrations to PolicyShield YAML config."""

    def __init__(self) -> None:
        self._migrations: list[tuple[str, str, Callable[[dict], list[str]]]] = []
        self._register_all()

    def _register_all(self) -> None:
        """Register all known migrations."""
        self._migrations = [
            ("0.11", "0.12", self._migrate_011_012),
            ("0.12", "1.0", self._migrate_012_100),
        ]

    def migrate(self, yaml_text: str, from_version: str, to_version: str) -> MigrationResult:
        """Apply migrations from ``from_version`` to ``to_version``."""
        data = yaml.safe_load(yaml_text)
        result = MigrationResult(original_version=from_version, target_version=to_version)

        current = from_version
        for src, dst, fn in self._migrations:
            if self._version_gte(current, to_version):
                break
            if self._version_gte(src, current) and not self._version_gte(src, to_version):
                changes = fn(data)
                result.changes.extend(changes)
                current = dst

        result.yaml_output = yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)
        return result

    @staticmethod
    def _version_gte(a: str, b: str) -> bool:
        """Compare version strings."""

        def parse(v: str) -> list[int]:
            return [int(x) for x in v.replace("-", ".").split(".")]

        return parse(a) >= parse(b)

    @staticmethod
    def _migrate_011_012(data: dict) -> list[str]:
        """0.11 → 0.12: rename 'then' → 'verdict', add severity."""
        changes = []
        for rule in data.get("rules", []):
            if "then" in rule and "verdict" not in rule:
                rule["verdict"] = rule.pop("then")
                changes.append(f"Rule {rule.get('id', '?')}: renamed 'then' → 'verdict'")
            if "severity" not in rule:
                rule["severity"] = "medium"
                changes.append(f"Rule {rule.get('id', '?')}: added default severity=medium")
        return changes

    @staticmethod
    def _migrate_012_100(data: dict) -> list[str]:
        """0.12 → 1.0: normalize tool patterns, add version field."""
        changes = []
        if "version" not in data:
            data["version"] = "1.0"
            changes.append("Added version: 1.0")

        for rule in data.get("rules", []):
            if "tool" not in rule:
                rule["tool"] = ".*"
                changes.append(f"Rule {rule.get('id', '?')}: added default tool='.*'")
            if "verdict" in rule and "then" not in rule:
                rule["then"] = rule.pop("verdict")
                changes.append(f"Rule {rule.get('id', '?')}: renamed 'verdict' → 'then'")

        return changes
