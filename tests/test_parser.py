"""Tests for YAML rule parser."""

import os
import tempfile
from pathlib import Path

import pytest

from policyshield.core.exceptions import PolicyShieldParseError
from policyshield.core.models import Verdict
from policyshield.core.parser import load_rules, parse_rule_file, validate_rule_set


VALID_YAML = """\
shield_name: test-shield
version: 1
rules:
  - id: block-exec
    description: Block exec calls
    when:
      tool: exec
    then: BLOCK
    severity: HIGH
    message: "exec is not allowed"
  - id: allow-read
    description: Allow read
    when:
      tool: read_file
    then: ALLOW
"""

INVALID_YAML = """\
shield_name: test
version: 1
rules: "not-a-list"
"""

DUPLICATE_IDS_YAML = """\
shield_name: test
version: 1
rules:
  - id: my-rule
    then: ALLOW
  - id: my-rule
    then: BLOCK
"""

MISSING_ID_YAML = """\
shield_name: test
version: 1
rules:
  - then: BLOCK
"""

BAD_VERDICT_YAML = """\
shield_name: test
version: 1
rules:
  - id: bad-verdict
    then: EXPLODE
"""


@pytest.fixture
def valid_yaml_file(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text(VALID_YAML)
    return f


@pytest.fixture
def valid_yaml_dir(tmp_path):
    d = tmp_path / "policies"
    d.mkdir()
    f1 = d / "security.yaml"
    f1.write_text("""\
shield_name: test-shield
version: 1
rules:
  - id: block-exec
    then: BLOCK
""")
    f2 = d / "access.yaml"
    f2.write_text("""\
rules:
  - id: allow-read
    then: ALLOW
""")
    return d


class TestParseRuleFile:
    def test_valid_file(self, valid_yaml_file):
        data = parse_rule_file(valid_yaml_file)
        assert data["shield_name"] == "test-shield"
        assert len(data["rules"]) == 2

    def test_file_not_found(self, tmp_path):
        with pytest.raises(PolicyShieldParseError, match="File not found"):
            parse_rule_file(tmp_path / "nonexist.yaml")

    def test_not_yaml_extension(self, tmp_path):
        f = tmp_path / "rules.txt"
        f.write_text("hello")
        with pytest.raises(PolicyShieldParseError, match="Not a YAML file"):
            parse_rule_file(f)

    def test_invalid_yaml_syntax(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text(":\n  - :\n    bad: [")
        with pytest.raises(PolicyShieldParseError, match="Invalid YAML"):
            parse_rule_file(f)

    def test_non_dict_root(self, tmp_path):
        f = tmp_path / "list.yaml"
        f.write_text("- item1\n- item2\n")
        with pytest.raises(PolicyShieldParseError, match="root must be a mapping"):
            parse_rule_file(f)


class TestLoadRules:
    def test_load_from_file(self, valid_yaml_file):
        ruleset = load_rules(valid_yaml_file)
        assert ruleset.shield_name == "test-shield"
        assert len(ruleset.rules) == 2
        assert ruleset.rules[0].id == "block-exec"
        assert ruleset.rules[0].then == Verdict.BLOCK
        assert ruleset.rules[1].id == "allow-read"
        assert ruleset.rules[1].then == Verdict.ALLOW

    def test_load_from_dir(self, valid_yaml_dir):
        ruleset = load_rules(valid_yaml_dir)
        assert ruleset.shield_name == "test-shield"
        assert len(ruleset.rules) == 2
        rule_ids = {r.id for r in ruleset.rules}
        assert "block-exec" in rule_ids
        assert "allow-read" in rule_ids

    def test_load_nonexistent_path(self, tmp_path):
        with pytest.raises(PolicyShieldParseError, match="does not exist"):
            load_rules(tmp_path / "nope")

    def test_load_empty_dir(self, tmp_path):
        d = tmp_path / "empty"
        d.mkdir()
        with pytest.raises(PolicyShieldParseError, match="No YAML files found"):
            load_rules(d)

    def test_rules_not_a_list(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text(INVALID_YAML)
        with pytest.raises(PolicyShieldParseError, match="must be a list"):
            load_rules(f)

    def test_duplicate_ids(self, tmp_path):
        f = tmp_path / "dup.yaml"
        f.write_text(DUPLICATE_IDS_YAML)
        with pytest.raises(PolicyShieldParseError, match="Duplicate rule ID"):
            load_rules(f)

    def test_missing_id(self, tmp_path):
        f = tmp_path / "noid.yaml"
        f.write_text(MISSING_ID_YAML)
        with pytest.raises(PolicyShieldParseError, match="missing required field"):
            load_rules(f)

    def test_bad_verdict(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text(BAD_VERDICT_YAML)
        with pytest.raises(PolicyShieldParseError, match="Invalid verdict"):
            load_rules(f)

    def test_case_insensitive_verdict(self, tmp_path):
        f = tmp_path / "case.yaml"
        f.write_text("""\
shield_name: test
version: 1
rules:
  - id: lower-case
    then: block
""")
        ruleset = load_rules(f)
        assert ruleset.rules[0].then == Verdict.BLOCK
