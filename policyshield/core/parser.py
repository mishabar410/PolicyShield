"""YAML rule parser for PolicyShield."""

from __future__ import annotations

from pathlib import Path

import yaml

from policyshield.core.exceptions import PolicyShieldParseError
from policyshield.core.models import RuleConfig, RuleSet, Verdict


def parse_rule_file(file_path: str | Path) -> dict:
    """Parse a single YAML rule file and return raw dict.

    Args:
        file_path: Path to the YAML file.

    Returns:
        Parsed YAML as dict.

    Raises:
        PolicyShieldParseError: If the file cannot be read or parsed.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise PolicyShieldParseError(f"File not found: {file_path}", str(file_path))
    if file_path.suffix not in (".yaml", ".yml"):
        raise PolicyShieldParseError(f"Not a YAML file: {file_path}", str(file_path))

    try:
        text = file_path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyShieldParseError(f"Invalid YAML: {e}", str(file_path)) from e

    if not isinstance(data, dict):
        raise PolicyShieldParseError("YAML root must be a mapping", str(file_path))

    return data


def _parse_rule(raw: dict, file_path: str | None = None) -> RuleConfig:
    """Parse a single rule dict into a RuleConfig."""
    if "id" not in raw:
        raise PolicyShieldParseError("Rule missing required field 'id'", file_path)

    # Normalize verdict
    then_value = raw.get("then", "ALLOW")
    if isinstance(then_value, str):
        then_value = then_value.upper()
        try:
            then_value = Verdict(then_value)
        except ValueError:
            raise PolicyShieldParseError(
                f"Invalid verdict '{then_value}' in rule '{raw['id']}'",
                file_path,
            )

    # Normalize severity
    severity_value = raw.get("severity", "LOW")
    if isinstance(severity_value, str):
        severity_value = severity_value.upper()

    return RuleConfig(
        id=raw["id"],
        description=raw.get("description", ""),
        when=raw.get("when", {}),
        then=then_value,
        message=raw.get("message"),
        severity=severity_value,
        enabled=raw.get("enabled", True),
    )


def load_rules(path: str | Path) -> RuleSet:
    """Load rules from a YAML file or directory of YAML files.

    Args:
        path: Path to a YAML file or directory containing YAML files.

    Returns:
        A RuleSet containing all parsed rules.

    Raises:
        PolicyShieldParseError: If files cannot be parsed or validated.
    """
    path = Path(path)

    if path.is_file():
        return _load_rules_from_file(path)
    elif path.is_dir():
        return _load_rules_from_dir(path)
    else:
        raise PolicyShieldParseError(f"Path does not exist: {path}")


def _load_rules_from_file(file_path: Path) -> RuleSet:
    """Load a RuleSet from a single YAML file."""
    data = parse_rule_file(file_path)
    return _build_ruleset(data, str(file_path))


def _load_rules_from_dir(dir_path: Path) -> RuleSet:
    """Load and merge rules from all YAML files in a directory."""
    yaml_files = sorted(dir_path.glob("*.yaml")) + sorted(dir_path.glob("*.yml"))
    if not yaml_files:
        raise PolicyShieldParseError(f"No YAML files found in {dir_path}")

    all_rules: list[RuleConfig] = []
    shield_name = ""
    version = 1

    for f in yaml_files:
        data = parse_rule_file(f)
        if not shield_name and "shield_name" in data:
            shield_name = data["shield_name"]
        if "version" in data:
            version = data["version"]
        raw_rules = data.get("rules", [])
        for raw in raw_rules:
            all_rules.append(_parse_rule(raw, str(f)))

    if not shield_name:
        shield_name = dir_path.name

    ruleset = RuleSet(shield_name=shield_name, version=version, rules=all_rules)
    validate_rule_set(ruleset)
    return ruleset


def _build_ruleset(data: dict, file_path: str) -> RuleSet:
    """Build a RuleSet from a parsed YAML dict."""
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyShieldParseError(
            "'rules' must be a list",
            file_path,
        )

    rules = [_parse_rule(r, file_path) for r in raw_rules]
    shield_name = data.get("shield_name", Path(file_path).stem)
    version = data.get("version", 1)

    ruleset = RuleSet(shield_name=shield_name, version=version, rules=rules)
    validate_rule_set(ruleset)
    return ruleset


def validate_rule_set(ruleset: RuleSet) -> None:
    """Validate a RuleSet for consistency.

    Raises:
        PolicyShieldParseError: If validation fails.
    """
    # Check for duplicate rule IDs
    ids = [r.id for r in ruleset.rules]
    seen = set()
    for rule_id in ids:
        if rule_id in seen:
            raise PolicyShieldParseError(f"Duplicate rule ID: '{rule_id}'")
        seen.add(rule_id)
