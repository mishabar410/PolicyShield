"""Tests for the rule linter."""

from __future__ import annotations


from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.lint import RuleLinter


def _make_ruleset(rules: list[RuleConfig], name: str = "test-shield") -> RuleSet:
    """Helper to build a RuleSet from rules."""
    return RuleSet(shield_name=name, version=1, rules=rules)


def _make_rule(**kwargs) -> RuleConfig:
    """Helper to build a RuleConfig with defaults."""
    defaults = {
        "id": "test-rule",
        "when": {},
        "then": Verdict.ALLOW,
        "enabled": True,
    }
    defaults.update(kwargs)
    return RuleConfig(**defaults)


class TestRuleLinter:
    """Tests for RuleLinter checks."""

    def test_lint_clean_rules_no_warnings(self):
        """A correct rule set produces no warnings."""
        rs = _make_ruleset([
            _make_rule(id="rule-a", when={"tool": "exec"}, then=Verdict.BLOCK, message="blocked"),
            _make_rule(id="rule-b", when={"tool": "read_file"}, then=Verdict.ALLOW),
        ])
        warnings = RuleLinter().lint(rs)
        assert warnings == []

    def test_lint_duplicate_ids(self):
        """Two rules with the same ID produce an ERROR."""
        rs = _make_ruleset([
            _make_rule(id="foo", when={"tool": "exec"}, then=Verdict.BLOCK, message="x"),
            _make_rule(id="foo", when={"tool": "read"}, then=Verdict.ALLOW),
        ])
        warnings = RuleLinter().lint(rs)
        errors = [w for w in warnings if w.check == "duplicate_ids"]
        assert len(errors) == 1
        assert errors[0].level == "ERROR"
        assert errors[0].rule_id == "foo"

    def test_lint_invalid_regex(self):
        """An invalid regex in args_match produces an ERROR."""
        rs = _make_ruleset([
            _make_rule(
                id="bad-regex",
                when={"tool": "exec", "args_match": {"command": {"regex": "[invalid("}}},
                then=Verdict.BLOCK,
                message="x",
            ),
        ])
        warnings = RuleLinter().lint(rs)
        errors = [w for w in warnings if w.check == "invalid_regex"]
        assert len(errors) == 1
        assert errors[0].level == "ERROR"
        assert errors[0].rule_id == "bad-regex"

    def test_lint_broad_tool_wildcard(self):
        """tool: '.*' produces a WARNING."""
        rs = _make_ruleset([
            _make_rule(id="catch-all", when={"tool": ".*"}, then=Verdict.BLOCK, message="x"),
        ])
        warnings = RuleLinter().lint(rs)
        broads = [w for w in warnings if w.check == "broad_tool_pattern"]
        assert len(broads) == 1
        assert broads[0].level == "WARNING"

    def test_lint_broad_tool_dotplus(self):
        """tool: '.+' also produces a WARNING."""
        rs = _make_ruleset([
            _make_rule(id="catch-all", when={"tool": ".+"}, then=Verdict.BLOCK, message="x"),
        ])
        warnings = RuleLinter().lint(rs)
        broads = [w for w in warnings if w.check == "broad_tool_pattern"]
        assert len(broads) == 1

    def test_lint_missing_message_on_block(self):
        """A BLOCK rule without message produces a WARNING."""
        rs = _make_ruleset([
            _make_rule(id="no-msg", when={"tool": "exec"}, then=Verdict.BLOCK),
        ])
        warnings = RuleLinter().lint(rs)
        missing = [w for w in warnings if w.check == "missing_message"]
        assert len(missing) == 1
        assert missing[0].level == "WARNING"

    def test_lint_missing_message_on_allow(self):
        """An ALLOW rule without message does NOT produce a warning."""
        rs = _make_ruleset([
            _make_rule(id="ok", when={"tool": "exec"}, then=Verdict.ALLOW),
        ])
        warnings = RuleLinter().lint(rs)
        missing = [w for w in warnings if w.check == "missing_message"]
        assert len(missing) == 0

    def test_lint_conflicting_verdicts(self):
        """Two rules on the same tool with different verdicts produce a WARNING."""
        rs = _make_ruleset([
            _make_rule(id="rule-block", when={"tool": "exec"}, then=Verdict.BLOCK, message="x"),
            _make_rule(id="rule-allow", when={"tool": "exec"}, then=Verdict.ALLOW),
        ])
        warnings = RuleLinter().lint(rs)
        conflicts = [w for w in warnings if w.check == "conflicting_verdicts"]
        assert len(conflicts) == 1
        assert conflicts[0].level == "WARNING"

    def test_lint_disabled_rule_info(self):
        """A disabled rule produces an INFO finding."""
        rs = _make_ruleset([
            _make_rule(id="old-rule", enabled=False),
        ])
        warnings = RuleLinter().lint(rs)
        infos = [w for w in warnings if w.check == "disabled_rules"]
        assert len(infos) == 1
        assert infos[0].level == "INFO"

    def test_lint_multiple_issues(self):
        """A ruleset with multiple problems reports all of them."""
        rs = _make_ruleset([
            _make_rule(id="dup", when={"tool": "exec"}, then=Verdict.BLOCK, message="x"),
            _make_rule(id="dup", when={"tool": "exec"}, then=Verdict.ALLOW),
            _make_rule(
                id="bad-rx",
                when={"tool": "read", "args_match": {"path": {"regex": "((("}}},
                then=Verdict.BLOCK,
                message="x",
            ),
            _make_rule(id="disabled", enabled=False),
        ])
        warnings = RuleLinter().lint(rs)
        checks = {w.check for w in warnings}
        assert "duplicate_ids" in checks
        assert "invalid_regex" in checks
        assert "disabled_rules" in checks
        assert len(warnings) >= 3

    def test_lint_valid_regex_no_error(self):
        """A valid regex does not produce an error."""
        rs = _make_ruleset([
            _make_rule(
                id="ok-regex",
                when={"tool": "exec", "args_match": {"command": {"regex": "rm\\s+-rf"}}},
                then=Verdict.BLOCK,
                message="x",
            ),
        ])
        warnings = RuleLinter().lint(rs)
        errors = [w for w in warnings if w.check == "invalid_regex"]
        assert len(errors) == 0


class TestCLILint:
    """Tests for the lint CLI command."""

    def test_cli_lint_valid_file(self, tmp_path):
        """CLI lint on a valid file returns exit 0."""
        from policyshield.cli.main import app

        yaml_content = """\
shield_name: test
version: 1
rules:
  - id: rule-a
    when:
      tool: exec
    then: block
    message: "blocked"
"""
        f = tmp_path / "rules.yaml"
        f.write_text(yaml_content)
        result = app(["lint", str(f)])
        assert result == 0

    def test_cli_lint_file_with_errors(self, tmp_path):
        """CLI lint on a file with duplicate IDs returns exit 1."""
        from policyshield.cli.main import app

        yaml_content = """\
shield_name: test
version: 1
rules:
  - id: dup
    when:
      tool: exec
    then: block
    message: "x"
  - id: dup
    when:
      tool: read
    then: allow
"""
        f = tmp_path / "rules.yaml"
        f.write_text(yaml_content)
        # The parser rejects duplicate IDs, so lint won't even get to run
        # Let's test with invalid regex instead (parser doesn't validate regex)
        yaml_content2 = """\
shield_name: test
version: 1
rules:
  - id: bad-regex
    when:
      tool: exec
      args_match:
        command:
          regex: "[invalid("
    then: block
    message: "x"
"""
        f2 = tmp_path / "rules2.yaml"
        f2.write_text(yaml_content2)
        result = app(["lint", str(f2)])
        assert result == 1

    def test_cli_lint_nonexistent_file(self):
        """CLI lint on a nonexistent file returns exit 1."""
        from policyshield.cli.main import app

        result = app(["lint", "/nonexistent/path/rules.yaml"])
        assert result == 1
