"""Tests for example chain rules & CLI lint — prompts 108-109."""

import subprocess
import sys
from pathlib import Path

from policyshield.core.parser import load_rules
from policyshield.lint.linter import RuleLinter


EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
CHAIN_RULES = EXAMPLES_DIR / "chain_rules.yaml"


def test_example_chain_rules_parse():
    """Example chain rules YAML should parse without errors."""
    rs = load_rules(CHAIN_RULES)
    assert len(rs.rules) >= 3
    assert rs.rules[0].chain is not None


def test_example_chain_rules_lint_clean():
    """Example chain rules should pass linter with no errors."""
    rs = load_rules(CHAIN_RULES)
    linter = RuleLinter()
    warnings = linter.lint(rs)
    errors = [w for w in warnings if w.level == "ERROR"]
    assert len(errors) == 0, f"Lint errors: {errors}"


def test_cli_lint_chain_rules():
    """'policyshield lint' on example chain rules should exit 0."""
    script = Path(sys.executable).parent / "policyshield"
    result = subprocess.run(
        [str(script), "lint", str(CHAIN_RULES)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}\nstdout: {result.stdout}"
