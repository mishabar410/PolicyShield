"""YAML rule parser for PolicyShield."""

from __future__ import annotations

from pathlib import Path

import yaml

from policyshield.core.exceptions import PolicyShieldParseError
from policyshield.core.models import OutputRule, RuleConfig, RuleSet, TaintChainConfig, Verdict

# Valid keys for the 'when' clause — anything else is likely a typo
_VALID_WHEN_KEYS = {"tool", "args", "args_match", "sender", "session", "chain"}


def parse_sanitizer_config(data: dict) -> dict | None:
    """Extract sanitizer configuration from parsed YAML data.

    Returns a dict suitable for ``SanitizerConfig(**result)`` or *None* if no config present.
    """
    raw = data.get("sanitizer")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise PolicyShieldParseError("'sanitizer' must be a mapping")
    allowed_keys = {
        "max_string_length",
        "max_args_depth",
        "max_total_keys",
        "strip_whitespace",
        "strip_null_bytes",
        "normalize_unicode",
        "strip_control_chars",
        "blocked_patterns",
        "builtin_detectors",
    }
    unknown = set(raw) - allowed_keys
    if unknown:
        raise PolicyShieldParseError(f"Unknown sanitizer keys: {unknown}")
    return dict(raw)


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

    # Normalize verdict — support both 'then' and 'verdict' keys
    then_value = raw.get("then") or raw.get("verdict", "ALLOW")
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

    # Support both 'when' block and top-level 'tool' key
    # Shallow copy to avoid mutating the original YAML dict
    when = dict(raw.get("when", {}))
    if not when and "tool" in raw:
        when = {"tool": raw["tool"]}
    when = _validated_when(when, raw["id"], file_path)

    # Extract chain from 'when' clause (YAML: when.chain) or top-level
    # Use pop on the COPY — original raw dict stays intact
    chain = when.pop("chain", None)
    if chain is None:
        chain = raw.get("chain")

    return RuleConfig(
        id=raw["id"],
        description=raw.get("description", ""),
        when=when,
        then=then_value,
        message=raw.get("message"),
        severity=severity_value,
        enabled=raw.get("enabled", True),
        approval_strategy=raw.get("approval_strategy"),
        chain=chain,
    )


def parse_rules_from_string(yaml_text: str) -> RuleSet:
    """Parse rules from a YAML string (useful for testing)."""
    data = yaml.safe_load(yaml_text)
    if not isinstance(data, dict):
        raise PolicyShieldParseError("YAML root must be a mapping")
    return _build_ruleset(data, "<string>")


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
    # Resolve include: directives
    data = _resolve_includes(data, file_path.parent)
    return _build_ruleset(data, str(file_path))


def _load_rules_from_dir(dir_path: Path) -> RuleSet:
    """Load and merge rules from all YAML files in a directory.

    Each file is parsed exactly once. Rules, taint_chain, honeypots,
    and output_rules are collected from all files in a single pass.
    """
    yaml_files = sorted(
        list(dir_path.glob("*.yaml")) + list(dir_path.glob("*.yml")),
        key=lambda f: f.stem,
    )
    if not yaml_files:
        raise PolicyShieldParseError(f"No YAML files found in {dir_path}")

    all_rules: list[RuleConfig] = []
    all_output_rules: list[OutputRule] = []
    shield_name = ""
    version = 1
    default_verdict = Verdict.ALLOW
    taint_chain = TaintChainConfig()
    honeypots_data = None

    # Single pass: parse each file once
    for f in yaml_files:
        data = parse_rule_file(f)

        # Metadata (first file wins for shield_name)
        if not shield_name and "shield_name" in data:
            shield_name = data["shield_name"]
        if "version" in data:
            version = data["version"]
        if "default_verdict" in data:
            dv = data["default_verdict"].upper()
            try:
                default_verdict = Verdict(dv)
            except ValueError:
                raise PolicyShieldParseError(f"Invalid default_verdict '{dv}'", str(f))

        # Rules
        for raw in data.get("rules", []):
            all_rules.append(_parse_rule(raw, str(f)))

        # Taint chain (last file wins)
        tc_data = data.get("taint_chain")
        if tc_data:
            taint_chain = TaintChainConfig(**tc_data)

        # Honeypots (last file wins)
        hp_data = data.get("honeypots")
        if hp_data:
            honeypots_data = hp_data

        # Output rules
        for raw_or in data.get("output_rules", []):
            all_output_rules.append(_parse_output_rule(raw_or, str(f)))

    if not shield_name:
        shield_name = dir_path.name

    ruleset = RuleSet(
        shield_name=shield_name,
        version=version,
        rules=all_rules,
        default_verdict=default_verdict,
        taint_chain=taint_chain,
        honeypots=honeypots_data,
        output_rules=all_output_rules,
    )
    validate_rule_set(ruleset)
    return ruleset


def _resolve_includes(data: dict, base_dir: Path, _visited: set[Path] | None = None) -> dict:
    """Resolve ``include:`` directives, merging rules from included files."""
    if _visited is None:
        _visited = set()

    includes = data.pop("include", None)
    if not includes:
        return data

    all_rules: list[dict] = []
    for inc_path in includes:
        resolved = (base_dir / inc_path).resolve()
        if not resolved.exists():
            raise PolicyShieldParseError(f"Include not found: {resolved}")
        if resolved in _visited:
            raise PolicyShieldParseError(f"Circular include detected: {resolved}")
        _visited.add(resolved)
        inc_data = parse_rule_file(resolved)
        # Recursive includes
        inc_data = _resolve_includes(inc_data, resolved.parent, _visited)
        inc_rules = inc_data.get("rules", [])
        all_rules.extend(inc_rules)

    # Included rules come first, local rules can override
    local_rules = data.get("rules", [])
    data["rules"] = all_rules + local_rules
    return data


def _resolve_extends(rules: list[dict]) -> list[dict]:
    """Resolve ``extends:`` — child rule inherits parent fields.

    Iterates until stable to support multi-level inheritance (A → B → C)
    regardless of rule ordering in the YAML file.
    """
    rules_by_id = {r["id"]: r for r in rules if "id" in r}
    max_iterations = len(rules) + 1  # Prevent infinite loops

    for _ in range(max_iterations):
        changed = False
        resolved = []
        for rule in rules:
            extends = rule.get("extends")
            if extends:
                parent = rules_by_id.get(extends)
                if parent is None:
                    raise PolicyShieldParseError(f"Rule extends unknown parent: {extends}")
                # If parent itself still has extends, skip this round
                if parent.get("extends"):
                    resolved.append(rule)
                    continue
                # Merge: parent values as defaults, child overrides
                merged = {**parent, **rule}
                merged["id"] = rule["id"]  # Keep child's ID
                merged.pop("extends", None)
                resolved.append(merged)
                rules_by_id[rule["id"]] = merged  # Update for downstream children
                changed = True
            else:
                resolved.append(rule)
        rules = resolved
        if not changed:
            break

    # Final check: any unresolved extends left?
    for rule in rules:
        if rule.get("extends"):
            raise PolicyShieldParseError(
                f"Circular or unresolvable extends in rule '{rule.get('id', '?')}'"
            )

    return rules


def _parse_output_rule(raw: dict, file_path: str | None = None) -> OutputRule:
    """Parse a single output_rule dict into an OutputRule."""
    tool = raw.get("tool", "")
    if not tool:
        raise PolicyShieldParseError("Output rule missing 'tool' field", file_path)

    # Parse verdict (then) if specified
    then = Verdict.REDACT
    if "then" in raw:
        try:
            then = Verdict(raw["then"].upper())
        except (ValueError, AttributeError):
            raise PolicyShieldParseError(
                f"Invalid output_rule verdict '{raw['then']}'", file_path
            )

    return OutputRule(
        id=raw.get("id", f"output_{tool}"),
        tool=tool,
        block_patterns=raw.get("block_patterns", []),
        max_size=raw.get("max_size"),
        then=then,
        message=raw.get("message", ""),
    )


def _build_ruleset(data: dict, file_path: str) -> RuleSet:
    """Build a RuleSet from a parsed YAML dict."""
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyShieldParseError(
            "'rules' must be a list",
            file_path,
        )

    # Resolve extends: directives
    raw_rules = _resolve_extends(raw_rules)

    rules = [_parse_rule(r, file_path) for r in raw_rules]
    shield_name = data.get("shield_name", Path(file_path).stem)
    version = data.get("version", 1)

    default_verdict = Verdict.ALLOW
    if "default_verdict" in data:
        dv = data["default_verdict"].upper()
        try:
            default_verdict = Verdict(dv)
        except ValueError:
            raise PolicyShieldParseError(f"Invalid default_verdict '{dv}'", file_path)

    # Parse taint_chain config (optional)
    from policyshield.core.models import TaintChainConfig

    taint_chain_data = data.get("taint_chain", {})
    taint_chain = TaintChainConfig(**taint_chain_data) if taint_chain_data else TaintChainConfig()

    # Parse honeypots config (optional)
    honeypots_data = data.get("honeypots")

    # Parse output_rules (optional)
    output_rules = [
        _parse_output_rule(r, file_path) for r in data.get("output_rules", [])
    ]

    ruleset = RuleSet(
        shield_name=shield_name,
        version=version,
        rules=rules,
        default_verdict=default_verdict,
        taint_chain=taint_chain,
        honeypots=honeypots_data,
        output_rules=output_rules,
    )
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


def _validated_when(when: dict, rule_id: str, file_path: str | None) -> dict:
    """Validate 'when' keys and return the dict unchanged."""
    if not isinstance(when, dict):
        return when
    unknown = set(when.keys()) - _VALID_WHEN_KEYS
    if unknown:
        import logging

        logging.getLogger("policyshield").warning(
            "Unknown 'when' keys %s in rule '%s'%s — ignored",
            unknown,
            rule_id,
            f" ({file_path})" if file_path else "",
        )
    return when
