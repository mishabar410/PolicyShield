"""PolicyShield CLI — command-line interface for rule validation and trace inspection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from policyshield import __version__
from policyshield.core.exceptions import PolicyShieldParseError
from policyshield.core.parser import load_rules


def app(args: list[str] | None = None) -> int:
    """Main CLI entry point.

    Args:
        args: Command-line arguments (defaults to sys.argv).

    Returns:
        Exit code (0 = success, 1 = error).
    """
    parser = argparse.ArgumentParser(
        prog="policyshield",
        description="PolicyShield — Declarative firewall for AI agent tool calls",
    )
    parser.add_argument("--version", action="version", version=f"policyshield {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    # validate command
    validate_parser = subparsers.add_parser("validate", help="Validate rule files")
    validate_parser.add_argument("path", help="Path to YAML rule file or directory")

    # lint command
    lint_parser = subparsers.add_parser("lint", help="Lint rule files for potential issues")
    lint_parser.add_argument("path", help="Path to YAML rule file or directory")

    # test command
    test_parser = subparsers.add_parser("test", help="Run YAML-based rule tests")
    test_parser.add_argument("path", help="Path to test file or directory")
    test_parser.add_argument("-v", "--verbose", action="store_true", help="Show details for each test")
    test_parser.add_argument("--json", dest="json_output", action="store_true", help="JSON output")

    # diff command
    diff_parser = subparsers.add_parser("diff", help="Compare two rule sets")
    diff_parser.add_argument("old_path", help="Path to old rule file")
    diff_parser.add_argument("new_path", help="Path to new rule file")
    diff_parser.add_argument("--json", dest="json_output", action="store_true", help="JSON output")
    diff_parser.add_argument("--exit-code", action="store_true", help="Exit 1 if differences found")

    # trace command
    trace_parser = subparsers.add_parser("trace", help="Inspect trace logs")
    trace_subparsers = trace_parser.add_subparsers(dest="trace_command")

    # trace show
    show_parser = trace_subparsers.add_parser("show", help="Show trace entries")
    show_parser.add_argument("file", help="Path to JSONL trace file")
    show_parser.add_argument("-n", "--limit", type=int, default=50, help="Max entries to show")
    show_parser.add_argument("--verdict", help="Filter by verdict")
    show_parser.add_argument("--tool", help="Filter by tool name")
    show_parser.add_argument("--session", help="Filter by session ID")

    violations_parser = trace_subparsers.add_parser("violations", help="Show only violations (non-ALLOW)")
    violations_parser.add_argument("file", help="Path to JSONL trace file")
    violations_parser.add_argument("-n", "--limit", type=int, default=50, help="Max entries to show")

    # trace stats
    stats_parser = trace_subparsers.add_parser("stats", help="Show aggregated trace statistics")
    stats_parser.add_argument("file", help="Path to JSONL trace file")
    stats_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    parsed = parser.parse_args(args)

    if parsed.command == "validate":
        return _cmd_validate(parsed.path)
    elif parsed.command == "lint":
        return _cmd_lint(parsed.path)
    elif parsed.command == "test":
        return _cmd_test(parsed)
    elif parsed.command == "diff":
        return _cmd_diff(parsed)
    elif parsed.command == "trace":
        if parsed.trace_command == "show":
            return _cmd_trace_show(parsed)
        elif parsed.trace_command == "violations":
            return _cmd_trace_violations(parsed)
        elif parsed.trace_command == "stats":
            return _cmd_trace_stats(parsed)
        else:
            trace_parser.print_help()
            return 1
    else:
        parser.print_help()
        return 1


def _cmd_validate(path: str) -> int:
    """Validate YAML rule files."""
    try:
        ruleset = load_rules(path)
        enabled = ruleset.enabled_rules()
        print(f"✓ Valid: {ruleset.shield_name} v{ruleset.version}")
        print(f"  Rules: {len(ruleset.rules)} total, {len(enabled)} enabled")

        for rule in ruleset.rules:
            status = "✓" if rule.enabled else "○"
            print(f"  {status} {rule.id} → {rule.then.value} [{rule.severity.value}]")

        return 0
    except PolicyShieldParseError as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        return 1


def _cmd_lint(path: str) -> int:
    """Lint YAML rule files for potential issues."""
    from policyshield.lint import RuleLinter

    try:
        ruleset = load_rules(path)
    except PolicyShieldParseError as e:
        print(f"✗ Error loading rules: {e}", file=sys.stderr)
        return 1

    linter = RuleLinter()
    warnings = linter.lint(ruleset)

    if not warnings:
        print("✓ No issues found")
        return 0

    errors = 0
    warning_count = 0
    info_count = 0

    for w in warnings:
        if w.level == "ERROR":
            icon = "✗"
            errors += 1
        elif w.level == "WARNING":
            icon = "⚠"
            warning_count += 1
        else:
            icon = "ℹ"
            info_count += 1
        print(f"{icon} {w.level} [{w.rule_id}] {w.check}: {w.message}")

    parts = []
    if errors:
        parts.append(f"{errors} error{'s' if errors != 1 else ''}")
    if warning_count:
        parts.append(f"{warning_count} warning{'s' if warning_count != 1 else ''}")
    if info_count:
        parts.append(f"{info_count} info")
    print(f"\n{', '.join(parts)}")

    return 1 if errors > 0 else 0


def _cmd_test(parsed: argparse.Namespace) -> int:
    """Run YAML-based rule tests."""
    from policyshield.testing.runner import TestRunner

    runner = TestRunner()
    target = Path(parsed.path)
    verbose = parsed.verbose
    json_output = getattr(parsed, "json_output", False)

    try:
        if target.is_dir():
            suites = runner.run_directory(target)
        else:
            suites = [runner.run_file(target)]
    except (FileNotFoundError, ValueError) as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1

    if json_output:
        out = []
        for s in suites:
            suite_data = {
                "suite": s.name,
                "total": s.total,
                "passed": s.passed,
                "failed": s.failed,
                "results": [
                    {
                        "name": r.test_case.name,
                        "passed": r.passed,
                        "actual_verdict": r.actual_verdict.value,
                        "failure_reason": r.failure_reason,
                    }
                    for r in s.results
                ],
            }
            out.append(suite_data)
        print(json.dumps(out, indent=2))
        has_failures = any(s.failed > 0 for s in suites)
        return 1 if has_failures else 0

    # Text output
    has_failures = False
    for suite in suites:
        print(f"\n🧪 Test Suite: {suite.name}")
        for r in suite.results:
            if r.passed:
                print(f"  ✓ {r.test_case.name}")
            else:
                has_failures = True
                print(f"  ✗ {r.test_case.name}")
                if verbose and r.failure_reason:
                    print(f"    {r.failure_reason}")
        print(f"\n{suite.passed}/{suite.total} passed, {suite.failed} failed")

    return 1 if has_failures else 0


def _cmd_diff(parsed: argparse.Namespace) -> int:
    """Compare two rule sets and show differences."""
    import json as _json

    from policyshield.core.parser import load_rules
    from policyshield.lint.differ import PolicyDiffer

    try:
        old_rules = load_rules(parsed.old_path)
        new_rules = load_rules(parsed.new_path)
    except Exception as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1

    d = PolicyDiffer.diff(old_rules, new_rules)
    json_output = getattr(parsed, "json_output", False)
    exit_code_flag = getattr(parsed, "exit_code", False)

    if json_output:
        print(_json.dumps(PolicyDiffer.diff_to_dict(d), indent=2, default=str))
    else:
        print(f"📋 Policy Diff: {parsed.old_path} → {parsed.new_path}\n")
        print(PolicyDiffer.format_diff(d))

    if exit_code_flag and d.has_changes:
        return 1
    return 0


def _cmd_trace_show(parsed: argparse.Namespace) -> int:
    """Show trace entries with optional filtering."""
    return _display_trace(
        file_path=parsed.file,
        limit=parsed.limit,
        verdict_filter=parsed.verdict,
        tool_filter=parsed.tool,
        session_filter=parsed.session,
    )


def _cmd_trace_violations(parsed: argparse.Namespace) -> int:
    """Show only violations (non-ALLOW verdicts)."""
    return _display_trace(
        file_path=parsed.file,
        limit=parsed.limit,
        exclude_allow=True,
    )


def _cmd_trace_stats(parsed: argparse.Namespace) -> int:
    """Show aggregated trace statistics."""
    from policyshield.trace.analyzer import TraceAnalyzer, format_stats

    trace_path = Path(parsed.file)
    if not trace_path.exists():
        print(f"✗ Trace file not found: {parsed.file}", file=sys.stderr)
        return 1

    stats = TraceAnalyzer.from_file(trace_path)

    if parsed.format == "json":
        print(json.dumps(stats.to_dict(), indent=2))
    else:
        print(format_stats(stats))

    return 0


def _display_trace(
    file_path: str,
    limit: int = 50,
    verdict_filter: str | None = None,
    tool_filter: str | None = None,
    session_filter: str | None = None,
    exclude_allow: bool = False,
) -> int:
    """Display trace entries from a JSONL file."""
    trace_path = Path(file_path)
    if not trace_path.exists():
        print(f"✗ Trace file not found: {file_path}", file=sys.stderr)
        return 1

    try:
        entries = []
        with open(trace_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)

                # Apply filters
                if verdict_filter and entry.get("verdict", "").upper() != verdict_filter.upper():
                    continue
                if tool_filter and entry.get("tool") != tool_filter:
                    continue
                if session_filter and entry.get("session_id") != session_filter:
                    continue
                if exclude_allow and entry.get("verdict", "").upper() == "ALLOW":
                    continue

                entries.append(entry)
                if len(entries) >= limit:
                    break

        if not entries:
            print("No matching trace entries found.")
            return 0

        # Display entries
        for entry in entries:
            verdict = entry.get("verdict", "?")
            tool = entry.get("tool", "?")
            session = entry.get("session_id", "?")
            timestamp = entry.get("timestamp", "?")
            rule_id = entry.get("rule_id", "-")
            latency = entry.get("latency_ms", 0)

            icon = "✓" if verdict == "ALLOW" else "✗"
            print(f"{icon} [{verdict}] {tool} | session={session} | rule={rule_id} | {latency:.1f}ms | {timestamp}")

            if "pii_types" in entry and entry["pii_types"]:
                print(f"  PII: {', '.join(entry['pii_types'])}")

        print(f"\n({len(entries)} entries shown)")
        return 0
    except (json.JSONDecodeError, OSError) as e:
        print(f"✗ Error reading trace file: {e}", file=sys.stderr)
        return 1
