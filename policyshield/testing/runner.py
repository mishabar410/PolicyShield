"""YAML-based test runner for PolicyShield rules.

Allows writing test cases for rules as data (YAML) rather than Python code.
Analogous to ``opa test`` for Open Policy Agent.

Test files must match ``*_test.yaml`` or ``*.test.yaml`` naming pattern.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from policyshield.core.models import Verdict
from policyshield.core.parser import load_rules
from policyshield.shield.pii import PIIDetector
from policyshield.shield.engine import ShieldEngine, ShieldMode

logger = logging.getLogger("policyshield")


# ── Data classes ─────────────────────────────────────────────────────


@dataclass
class TestCase:
    """A single rule test case parsed from YAML."""

    name: str
    tool: str
    args: dict[str, Any]
    expect_verdict: Verdict
    expect_rule_id: str | None = None
    expect_message_contains: str | None = None
    expect_pii_detected: list[str] | None = None


@dataclass
class TestResult:
    """Result of running a single test case."""

    test_case: TestCase
    passed: bool
    actual_verdict: Verdict
    actual_rule_id: str | None
    actual_message: str
    actual_pii: list[str]
    failure_reason: str | None = None


@dataclass
class TestSuite:
    """Aggregated results for a test file."""

    name: str
    results: list[TestResult] = field(default_factory=list)
    total: int = 0
    passed: int = 0
    failed: int = 0


# ── Runner ───────────────────────────────────────────────────────────


class TestRunner:
    """Run YAML-defined test cases against a rule set.

    Usage::

        runner = TestRunner()
        suite = runner.run_file("policies/rules_test.yaml")
        print(f"{suite.passed}/{suite.total} passed")
    """

    def run_file(self, test_file: str | Path) -> TestSuite:
        """Parse a YAML test file and run all contained test cases.

        Args:
            test_file: Path to a ``*_test.yaml`` or ``*.test.yaml`` file.

        Returns:
            A :class:`TestSuite` with detailed results.

        Raises:
            FileNotFoundError: If the test file or referenced rules file
                does not exist.
            ValueError: If the YAML is not a valid test file.
        """
        test_path = Path(test_file).resolve()
        if not test_path.exists():
            raise FileNotFoundError(f"Test file not found: {test_path}")

        with open(test_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        if not isinstance(data, dict) or "tests" not in data:
            raise ValueError(f"Invalid test file (missing 'tests' key): {test_path}")

        # Resolve rules_path relative to test file
        rules_rel = data.get("rules_path", "rules.yaml")
        rules_path = (test_path.parent / rules_rel).resolve()
        if not rules_path.exists():
            raise FileNotFoundError(f"Rules file not found: {rules_path}")

        suite_name = data.get("test_suite", test_path.stem)

        # Build engine with PII detector
        ruleset = load_rules(str(rules_path))
        engine = ShieldEngine(
            rules=ruleset,
            mode=ShieldMode.ENFORCE,
            pii_detector=PIIDetector(),
        )

        # Parse test cases
        cases: list[TestCase] = []
        for raw in data["tests"]:
            expect = raw.get("expect", {})
            verdict_str = expect.get("verdict", "ALLOW").upper()
            cases.append(
                TestCase(
                    name=raw["name"],
                    tool=raw["tool"],
                    args=raw.get("args", {}),
                    expect_verdict=Verdict(verdict_str),
                    expect_rule_id=expect.get("rule_id"),
                    expect_message_contains=expect.get("message_contains"),
                    expect_pii_detected=expect.get("pii_detected"),
                )
            )

        suite = TestSuite(name=suite_name, total=len(cases))

        for case in cases:
            result = self._run_case(engine, case)
            suite.results.append(result)
            if result.passed:
                suite.passed += 1
            else:
                suite.failed += 1

        return suite

    def run_directory(self, directory: str | Path) -> list[TestSuite]:
        """Discover and run all test files in a directory.

        Args:
            directory: Path to scan for test files.

        Returns:
            List of :class:`TestSuite` results (one per file).
        """
        files = self.discover_test_files(directory)
        return [self.run_file(f) for f in files]

    @staticmethod
    def discover_test_files(directory: str | Path) -> list[Path]:
        """Find all ``*_test.yaml`` and ``*.test.yaml`` files.

        Args:
            directory: Root directory to search.

        Returns:
            Sorted list of discovered test file paths.
        """
        root = Path(directory).resolve()
        results: list[Path] = []
        for pattern in ("*_test.yaml", "*.test.yaml", "*_test.yml", "*.test.yml"):
            results.extend(root.rglob(pattern))
        return sorted(set(results))

    # ── Internal ─────────────────────────────────────────────────────

    @staticmethod
    def _run_case(engine: ShieldEngine, case: TestCase) -> TestResult:
        """Execute a single test case and compare against expectations."""
        shield_result = engine.check(tool_name=case.tool, args=case.args)

        actual_pii = [m.pii_type.value for m in shield_result.pii_matches]

        reasons: list[str] = []

        # Check verdict
        if shield_result.verdict != case.expect_verdict:
            reasons.append(
                f"Expected verdict={case.expect_verdict.value}, "
                f"got {shield_result.verdict.value}"
            )

        # Check rule_id
        if case.expect_rule_id is not None:
            if shield_result.rule_id != case.expect_rule_id:
                reasons.append(
                    f"Expected rule_id={case.expect_rule_id!r}, "
                    f"got {shield_result.rule_id!r}"
                )

        # Check message_contains
        if case.expect_message_contains is not None:
            msg = shield_result.message or ""
            if case.expect_message_contains.lower() not in msg.lower():
                reasons.append(
                    f"Expected message containing {case.expect_message_contains!r}, "
                    f"got {msg!r}"
                )

        # Check PII
        if case.expect_pii_detected is not None:
            expected_set = {p.upper() for p in case.expect_pii_detected}
            actual_set = {p.upper() for p in actual_pii}
            if not expected_set.issubset(actual_set):
                missing = expected_set - actual_set
                reasons.append(
                    f"Expected PII types {expected_set}, "
                    f"got {actual_set} (missing {missing})"
                )

        passed = len(reasons) == 0
        return TestResult(
            test_case=case,
            passed=passed,
            actual_verdict=shield_result.verdict,
            actual_rule_id=shield_result.rule_id,
            actual_message=shield_result.message or "",
            actual_pii=actual_pii,
            failure_reason="; ".join(reasons) if reasons else None,
        )
