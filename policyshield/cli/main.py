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
    stats_parser.add_argument("file", nargs="?", default=None, help="Path to JSONL trace file (legacy mode)")
    stats_parser.add_argument("--dir", default=None, help="Trace directory for aggregation")
    stats_parser.add_argument("--from", dest="time_from", help="Start time (ISO datetime)")
    stats_parser.add_argument("--to", dest="time_to", help="End time (ISO datetime)")
    stats_parser.add_argument("--tool", help="Filter by tool name")
    stats_parser.add_argument("--session", help="Filter by session ID")
    stats_parser.add_argument("--top", type=int, default=10, help="Top N tools (default: 10)")
    stats_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    # trace search
    search_parser = trace_subparsers.add_parser("search", help="Search traces with filters")
    search_parser.add_argument("--dir", default="./traces", help="Trace directory (default: ./traces)")
    search_parser.add_argument("--tool", help="Filter by tool name")
    search_parser.add_argument("--verdict", help="Filter by verdict (ALLOW, BLOCK, REDACT, APPROVE)")
    search_parser.add_argument("--session", help="Filter by session ID")
    search_parser.add_argument("--text", help="Full-text search in args, message, tool")
    search_parser.add_argument("--rule", help="Filter by rule ID")
    search_parser.add_argument("--pii", help="Filter by PII type")
    search_parser.add_argument("--from", dest="time_from", help="Start time (ISO datetime)")
    search_parser.add_argument("--to", dest="time_to", help="End time (ISO datetime)")
    search_parser.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")
    search_parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    # trace export
    export_parser = trace_subparsers.add_parser("export", help="Export trace to CSV or HTML")
    export_parser.add_argument("file", help="Path to JSONL trace file")
    export_parser.add_argument("--format", choices=["csv", "html"], default="csv", help="Export format")
    export_parser.add_argument("--output", help="Output file path")
    export_parser.add_argument("--title", default="PolicyShield Trace Report", help="HTML report title")

    # nanobot wrapper command
    nanobot_parser = subparsers.add_parser(
        "nanobot",
        help="Run nanobot with PolicyShield enforcement",
        description="Wraps nanobot's CLI with PolicyShield. All arguments after the flags are passed to nanobot.",
    )
    nanobot_parser.add_argument(
        "--rules",
        "-r",
        required=True,
        help="Path to YAML rules file",
    )
    nanobot_parser.add_argument(
        "--mode",
        default="ENFORCE",
        choices=["ENFORCE", "AUDIT", "DISABLED"],
        help="Shield mode (default: ENFORCE)",
    )
    nanobot_parser.add_argument(
        "--fail-open",
        action="store_true",
        default=True,
        help="Shield errors don't block tools (default: True)",
    )
    nanobot_parser.add_argument(
        "--fail-closed",
        action="store_true",
        help="Shield errors block tool execution",
    )
    nanobot_parser.add_argument(
        "nanobot_args",
        nargs=argparse.REMAINDER,
        help="Arguments to pass to nanobot CLI",
    )

    # init command
    init_parser = subparsers.add_parser("init", help="Scaffold a new PolicyShield project")
    init_parser.add_argument("directory", nargs="?", default=".", help="Target directory (default: current directory)")
    init_parser.add_argument(
        "--preset",
        default="minimal",
        choices=["minimal", "security", "compliance"],
        help="Rule preset (default: minimal)",
    )
    init_parser.add_argument("--nanobot", action="store_true", help="Add nanobot-specific rules")
    init_parser.add_argument("--no-interactive", action="store_true", help="Skip interactive prompts")

    # config command
    config_parser = subparsers.add_parser("config", help="Manage policyshield config")
    config_subparsers = config_parser.add_subparsers(dest="config_command")
    val_parser = config_subparsers.add_parser("validate", help="Validate config file")
    val_parser.add_argument("path", nargs="?", default="policyshield.yaml", help="Config file path")
    show_parser2 = config_subparsers.add_parser("show", help="Show resolved config")
    show_parser2.add_argument("path", nargs="?", default=None, help="Config file path")
    config_subparsers.add_parser("init", help="Create default policyshield.yaml")

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
        elif parsed.trace_command == "search":
            return _cmd_trace_search(parsed)
        elif parsed.trace_command == "export":
            return _cmd_trace_export(parsed)
        else:
            trace_parser.print_help()
            return 1
    elif parsed.command == "init":
        return _cmd_init(parsed)
    elif parsed.command == "nanobot":
        return _cmd_nanobot(parsed, args)
    elif parsed.command == "config":
        if parsed.config_command == "validate":
            return _cmd_config_validate(parsed)
        elif parsed.config_command == "show":
            return _cmd_config_show(parsed)
        elif parsed.config_command == "init":
            return _cmd_config_init()
        else:
            config_parser.print_help()
            return 1
    else:
        parser.print_help()
        return 1


def _cmd_init(parsed: argparse.Namespace) -> int:
    """Scaffold a new PolicyShield project."""
    from policyshield.cli.init_scaffold import scaffold

    directory = parsed.directory
    preset = parsed.preset
    nanobot_flag = parsed.nanobot
    interactive = not parsed.no_interactive

    try:
        scaffold(
            directory=directory,
            preset=preset,
            nanobot=nanobot_flag,
            interactive=interactive,
        )
        return 0
    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        return 1


def _cmd_nanobot(parsed: argparse.Namespace, original_args: list[str] | None) -> int:
    """Run nanobot with PolicyShield enforcement.

    Patches AgentLoop.__init__ at the class level so that any AgentLoop
    created by nanobot's CLI automatically gets PolicyShield wrapping.
    Then delegates to nanobot's CLI entry point.
    """
    import functools

    rules_path = parsed.rules
    mode_str = parsed.mode
    fail_open = not parsed.fail_closed

    # Validate rules path
    rules = Path(rules_path)
    if not rules.exists():
        print(f"✗ Rules file not found: {rules_path}", file=sys.stderr)
        return 1

    # Import nanobot
    try:
        from nanobot.agent.loop import AgentLoop
    except ImportError:
        print("✗ nanobot is not installed. Install it with: pip install nanobot", file=sys.stderr)
        return 1

    # Import our monkey-patch
    from policyshield.integrations.nanobot.monkey_patch import shield_agent_loop

    # Patch AgentLoop.__init__ at the class level
    _original_init = AgentLoop.__init__

    @functools.wraps(_original_init)
    def _patched_init(self, *args, **kwargs):
        _original_init(self, *args, **kwargs)
        # Apply PolicyShield after the original init completes
        try:
            shield_agent_loop(
                self,
                rules_path=rules_path,
                mode=mode_str,
                fail_open=fail_open,
            )
            print(f"🛡️  PolicyShield active (mode={mode_str}, rules={rules_path})")
        except RuntimeError:
            # Already shielded (e.g. subagent inheriting from parent)
            pass

    AgentLoop.__init__ = _patched_init  # type: ignore[method-assign]

    # Collect nanobot args
    nanobot_argv = parsed.nanobot_args or []
    # Strip leading '--' if present (REMAINDER may include it)
    if nanobot_argv and nanobot_argv[0] == "--":
        nanobot_argv = nanobot_argv[1:]

    if not nanobot_argv:
        print("Usage: policyshield nanobot --rules <RULES> [--mode MODE] <nanobot command>")
        print("\nExample:")
        print("  policyshield nanobot --rules rules.yaml agent -m 'Hello!'")
        print("  policyshield nanobot --rules rules.yaml gateway")
        return 1

    # Delegate to nanobot CLI
    try:
        from nanobot.cli.commands import app as nanobot_app

        sys.argv = ["nanobot"] + nanobot_argv
        nanobot_app(standalone_mode=False)
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    except Exception as e:
        print(f"✗ nanobot error: {e}", file=sys.stderr)
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
    from datetime import datetime as _dt

    # New dir-based aggregation mode
    if parsed.dir:
        from policyshield.trace.aggregator import (
            TimeWindow,
            TraceAggregator,
            format_aggregation,
        )

        trace_dir = Path(parsed.dir)
        if not trace_dir.exists():
            print(f"\u2717 Trace directory not found: {parsed.dir}", file=sys.stderr)
            return 1

        tw = None
        if parsed.time_from or parsed.time_to:
            start = _dt.fromisoformat(parsed.time_from) if parsed.time_from else _dt.min
            end = _dt.fromisoformat(parsed.time_to) if parsed.time_to else _dt.max
            tw = TimeWindow(start=start, end=end)

        aggregator = TraceAggregator(trace_dir)
        result = aggregator.aggregate(
            time_window=tw,
            session_id=parsed.session,
            tool=parsed.tool,
        )

        if parsed.format == "json":
            print(json.dumps(result.to_dict(), indent=2, default=str))
        else:
            print(format_aggregation(result, top_n=parsed.top))

        return 0

    # Legacy file-based mode
    if not parsed.file:
        print("\u2717 Provide either --dir or a trace file path.", file=sys.stderr)
        return 1

    from policyshield.trace.analyzer import TraceAnalyzer, format_stats

    trace_path = Path(parsed.file)
    if not trace_path.exists():
        print(f"\u2717 Trace file not found: {parsed.file}", file=sys.stderr)
        return 1

    stats = TraceAnalyzer.from_file(trace_path)

    if parsed.format == "json":
        print(json.dumps(stats.to_dict(), indent=2))
    else:
        print(format_stats(stats))

    return 0


def _cmd_trace_search(parsed: argparse.Namespace) -> int:
    """Search traces with filters."""
    from datetime import datetime as _dt

    from policyshield.trace.search import SearchQuery, TraceSearchEngine

    trace_dir = Path(parsed.dir)
    if not trace_dir.exists():
        print(f"✗ Trace directory not found: {parsed.dir}", file=sys.stderr)
        return 1

    query = SearchQuery(
        tool=parsed.tool,
        verdict=parsed.verdict,
        session_id=parsed.session,
        text=parsed.text,
        rule_id=parsed.rule,
        pii_type=parsed.pii,
        time_from=_dt.fromisoformat(parsed.time_from) if parsed.time_from else None,
        time_to=_dt.fromisoformat(parsed.time_to) if parsed.time_to else None,
        limit=parsed.limit,
    )

    engine = TraceSearchEngine(trace_dir)
    result = engine.search(query)

    if parsed.format == "json":
        output = {
            "total": result.total,
            "records": result.records,
        }
        print(json.dumps(output, indent=2, default=str))
    else:
        if not result.records:
            print(f"No results found (total: {result.total})")
            return 0
        for rec in result.records:
            verdict = rec.get("verdict", "?")
            tool = rec.get("tool", "?")
            ts = rec.get("timestamp", "?")
            session = rec.get("session_id", "?")
            icon = "✓" if verdict == "ALLOW" else "✗"
            print(f"{icon} [{verdict}] {tool} | session={session} | {ts}")
        print(f"\n({len(result.records)} of {result.total} shown)")

    return 0


def _cmd_trace_export(parsed: argparse.Namespace) -> int:
    """Export trace to CSV or HTML."""
    from datetime import datetime as _dt

    from policyshield.trace.exporter import TraceExporter

    trace_path = Path(parsed.file)
    if not trace_path.exists():
        print(f"✗ Trace file not found: {parsed.file}", file=sys.stderr)
        return 1

    fmt = parsed.format
    output = getattr(parsed, "output", None)
    if not output:
        stamp = _dt.now().strftime("%Y%m%d")
        output = f"trace_export_{stamp}.{fmt}"

    if fmt == "csv":
        count = TraceExporter.to_csv(trace_path, output)
    else:
        title = getattr(parsed, "title", "PolicyShield Trace Report")
        count = TraceExporter.to_html(trace_path, output, title=title)

    print(f"✓ Exported {count} records to {output}")
    return 0


def _cmd_config_validate(parsed: argparse.Namespace) -> int:
    """Validate a policyshield config file."""
    from policyshield.config.loader import validate_config_file

    errors = validate_config_file(parsed.path)
    if errors:
        print(f"✗ Config errors in {parsed.path}:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"✓ Config valid: {parsed.path}")
    return 0


def _cmd_config_show(parsed: argparse.Namespace) -> int:
    """Show resolved config."""
    from policyshield.config.loader import load_config, render_config

    try:
        cfg = load_config(path=getattr(parsed, "path", None))
    except (FileNotFoundError, ValueError) as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1
    print(render_config(cfg))
    return 0


def _cmd_config_init() -> int:
    """Create default policyshield.yaml."""
    from policyshield.config.loader import generate_default_config

    target = Path("policyshield.yaml")
    if target.exists():
        print(f"✗ {target} already exists", file=sys.stderr)
        return 1
    target.write_text(generate_default_config(), encoding="utf-8")
    print(f"✓ Created {target}")
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
