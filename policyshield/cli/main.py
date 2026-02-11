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

    # trace violations
    violations_parser = trace_subparsers.add_parser("violations", help="Show only violations (non-ALLOW)")
    violations_parser.add_argument("file", help="Path to JSONL trace file")
    violations_parser.add_argument("-n", "--limit", type=int, default=50, help="Max entries to show")

    parsed = parser.parse_args(args)

    if parsed.command == "validate":
        return _cmd_validate(parsed.path)
    elif parsed.command == "lint":
        return _cmd_lint(parsed.path)
    elif parsed.command == "trace":
        if parsed.trace_command == "show":
            return _cmd_trace_show(parsed)
        elif parsed.trace_command == "violations":
            return _cmd_trace_violations(parsed)
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
