"""Tests for NL Policy Compiler."""

from __future__ import annotations

from policyshield.ai.compiler import CompileResult, PolicyCompiler


# ---------------------------------------------------------------------------
# Validation tests (no LLM needed)
# ---------------------------------------------------------------------------


class TestValidation:
    def test_valid_yaml(self):
        compiler = PolicyCompiler()
        errors = compiler._validate(
            "shield_name: test\nversion: 1\nrules:\n"
            "  - id: r1\n    when:\n      tool: exec\n    then: BLOCK\n"
            "    message: blocked\n"
        )
        assert errors == []

    def test_missing_rules(self):
        compiler = PolicyCompiler()
        errors = compiler._validate("shield_name: test\nversion: 1\n")
        assert any("Missing 'rules'" in e for e in errors)

    def test_invalid_then(self):
        compiler = PolicyCompiler()
        errors = compiler._validate(
            "shield_name: test\nversion: 1\nrules:\n"
            "  - id: r1\n    when:\n      tool: exec\n    then: DELETE\n"
        )
        assert any("invalid 'then'" in e for e in errors)

    def test_invalid_yaml_syntax(self):
        compiler = PolicyCompiler()
        errors = compiler._validate("{{{{invalid yaml")
        assert any("YAML parse error" in e for e in errors)

    def test_missing_id(self):
        compiler = PolicyCompiler()
        errors = compiler._validate(
            "shield_name: test\nversion: 1\nrules:\n"
            "  - when:\n      tool: exec\n    then: BLOCK\n"
        )
        assert any("missing 'id'" in e for e in errors)

    def test_missing_when(self):
        compiler = PolicyCompiler()
        errors = compiler._validate(
            "shield_name: test\nversion: 1\nrules:\n"
            "  - id: r1\n    then: BLOCK\n"
        )
        assert any("missing 'when'" in e for e in errors)

    def test_rules_not_list(self):
        compiler = PolicyCompiler()
        errors = compiler._validate("rules: not_a_list\n")
        assert any("must be a list" in e for e in errors)

    def test_root_not_mapping(self):
        compiler = PolicyCompiler()
        errors = compiler._validate("- item1\n- item2\n")
        assert any("mapping" in e for e in errors)


# ---------------------------------------------------------------------------
# CompileResult
# ---------------------------------------------------------------------------


class TestCompileResult:
    def test_successful_result(self):
        r = CompileResult(yaml_text="test", is_valid=True, attempts=1)
        assert r.is_valid is True
        assert r.attempts == 1
        assert r.errors == []

    def test_failed_result(self):
        r = CompileResult(is_valid=False, errors=["Missing rules"], attempts=2)
        assert r.is_valid is False
        assert len(r.errors) == 1


# ---------------------------------------------------------------------------
# Compiler config
# ---------------------------------------------------------------------------


class TestCompilerConfig:
    def test_defaults(self):
        compiler = PolicyCompiler()
        assert compiler._model == "gpt-4o-mini"
        assert compiler._max_retries == 2

    def test_custom_config(self):
        compiler = PolicyCompiler(model="gpt-4", max_retries=5)
        assert compiler._model == "gpt-4"
        assert compiler._max_retries == 5
